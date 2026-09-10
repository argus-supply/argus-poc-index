"""Atomic Git snapshots and compare-and-swap UTC-day reservations.

All authorized remote branch tips are observed as bounded shallow snapshots. New
commits reference the observed parent; ordinary non-force push rejects races.
"""
from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import subprocess
import uuid
import re
import urllib.request

from .core import canonical, utcnow
from .observations import threshold_observation


class ParentMoved(RuntimeError):
    """Remote publication raced; reread and recompute before retrying."""


class GitStore:
    def __init__(self, path, remote, token=None):
        self.path = Path(path)
        self.path.mkdir(parents=True, exist_ok=True)
        self.env = dict(os.environ, GIT_TERMINAL_PROMPT='0', GIT_TRACE='0', GIT_TRACE_CURL='0',
            GIT_AUTHOR_NAME='ARGUS data sync', GIT_AUTHOR_EMAIL='sync@argus.invalid',
            GIT_COMMITTER_NAME='ARGUS data sync', GIT_COMMITTER_EMAIL='sync@argus.invalid')
        self.env.pop('GIT_CURL_VERBOSE', None)
        if token:
            credential = base64.b64encode(('x-access-token:' + token).encode()).decode()
            self.env.update(GIT_CONFIG_COUNT='1', GIT_CONFIG_KEY_0='http.https://github.com/.extraheader',
                            GIT_CONFIG_VALUE_0='AUTHORIZATION: basic ' + credential)
        proxy = urllib.request.getproxies().get('https')
        if proxy:
            count = int(self.env.get('GIT_CONFIG_COUNT', '0'))
            self.env.update(GIT_CONFIG_COUNT=str(count + 1))
            self.env['GIT_CONFIG_KEY_' + str(count)] = 'http.proxy'
            self.env['GIT_CONFIG_VALUE_' + str(count)] = proxy
        for key, value in (('http.version', 'HTTP/1.1'), ('gc.auto', '0'),
                           ('maintenance.auto', 'false')):
            count = int(self.env.get('GIT_CONFIG_COUNT', '0'))
            self.env['GIT_CONFIG_COUNT'] = str(count + 1)
            self.env['GIT_CONFIG_KEY_' + str(count)] = key
            self.env['GIT_CONFIG_VALUE_' + str(count)] = value
        self.remote = remote
        if not (self.path / 'HEAD').exists():
            self.run('init', '--bare')

    def run(self, *args, data=None, check=True, extra_env=None):
        result = subprocess.run(['git', '-C', str(self.path), *args], input=data,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env={**self.env, **(extra_env or {})}, timeout=90)
        if check and result.returncode:
            raise RuntimeError('git operation failed: ' + args[0])
        return result

    def observe_heads(self):
        """Pin every authorized remote branch; unknown branches require review."""
        result = self.run('ls-remote', '--heads', self.remote)
        tips = {}
        for line in result.stdout.decode().splitlines():
            sha, ref = line.split()
            if ref not in ('refs/heads/main', 'refs/heads/data', 'refs/heads/control') or not re.fullmatch(r'[a-f0-9]{40}', sha):
                raise ValueError('unexpected remote branch or object format')
            tips[ref] = sha
            if self.run('cat-file', '-e', sha + '^{commit}', check=False).returncode:
                self.run('fetch', '--depth=1', '--no-tags', self.remote, sha)
        return tips

    def read(self, branch, revision=None):
        if branch not in ('main', 'data', 'control'):
            raise ValueError('unsupported publication branch')
        tips = self.observe_heads()
        sha = revision or tips.get('refs/heads/' + branch)
        if sha is None:
            return None, {}
        if not re.fullmatch(r'[a-f0-9]{40}', sha):
            raise ValueError('invalid snapshot revision')
        if self.run('cat-file', '-e', sha + '^{commit}', check=False).returncode:
            self.run('fetch', '--depth=1', '--no-tags', self.remote, sha)
        entries = self.run('ls-tree', '-rz', sha).stdout
        files, objects = {}, []
        for entry in entries.split(b'\0'):
            if not entry:
                continue
            meta, raw_path = entry.split(b'\t', 1)
            mode, kind, blob = meta.decode().split()
            path = raw_path.decode()
            if mode != '100644' or kind != 'blob' or path.startswith('/') or '..' in path.split('/'):
                raise ValueError('invalid published data path or mode')
            objects.append((path, blob))
        batch = self.run('cat-file', '--batch', data=('\n'.join(blob for _, blob in objects) + '\n').encode()).stdout if objects else b''
        offset = 0
        for path, expected_blob in objects:
            end = batch.index(b'\n', offset)
            blob, kind, raw_size = batch[offset:end].split()
            size = int(raw_size)
            if blob.decode() != expected_blob or kind != b'blob' or size < 0:
                raise ValueError('published snapshot object mismatch')
            offset = end + 1
            if offset + size >= len(batch) or batch[offset + size:offset + size + 1] != b'\n':
                raise ValueError('truncated published snapshot object')
            files[path] = batch[offset:offset + size]
            threshold_observation('published_blob_bytes', size, 2 * 1024 * 1024)
            offset += size + 1
        if offset != len(batch):
            raise ValueError('unexpected published snapshot objects')
        threshold_observation('published_tree_bytes', sum(map(len, files.values())), 32 * 1024 * 1024)
        return sha, files

    def prepare(self, branch, parent, files, message):
        if branch not in ('main', 'data', 'control'):
            raise ValueError('unsupported publication branch')
        staging = 'refs/heads/staging-' + branch + '-' + uuid.uuid4().hex
        commands = [f'commit {staging}\n'.encode(),
            b'committer ARGUS data sync <sync@argus.invalid> now\n',
            f'data {len(message.encode())}\n'.encode(), message.encode(), b'\n']
        if parent:
            commands.append(f'from {parent}\n'.encode())
        commands.append(b'deleteall\n')
        for path, data in sorted(files.items()):
            if path.startswith('/') or '..' in path.split('/') or '\x00' in path:
                raise ValueError('unsafe publication path')
            commands.extend([f'M 100644 inline {json.dumps(path)}\n'.encode(),
                             f'data {len(data)}\n'.encode(), data, b'\n'])
        commands.append(b'\n')
        self.run('fast-import', '--quiet', '--date-format=now', data=b''.join(commands))
        sha = self.run('rev-parse', staging).stdout.decode().strip()
        tree = self.run('rev-parse', sha + '^{tree}').stdout.decode().strip()
        if parent and tree == self.run('rev-parse', parent + '^{tree}').stdout.decode().strip():
            return parent, False
        return sha, True

    def push_prepared(self, branch, sha):
        if branch not in ('main', 'data', 'control'):
            raise ValueError('unsupported publication branch')
        # No force, force-with-lease, history deletion or application remote here.
        result = self.run('push', self.remote, f'{sha}:refs/heads/{branch}', check=False)
        if result.returncode:
            if b'rejected' in result.stderr or b'failed to update ref' in result.stderr:
                raise ParentMoved('remote parent moved')
            raise RuntimeError('git publication failed')
        return sha, True

    def publish(self, branch, parent, files, message):
        sha, changed = self.prepare(branch, parent, files, message)
        return self.push_prepared(branch, sha) if changed else (sha, False)


from .ledger import Ledger  # Re-export the persistent accounting API.
