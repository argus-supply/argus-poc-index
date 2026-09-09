"""Atomic Git snapshots and compare-and-swap UTC-day reservations.

Only the named branch is fetched at depth one. New commits reference its observed
parent; ordinary non-force push rejects concurrent parent movement.
"""
from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import subprocess
import uuid
import math

from .core import canonical, utcnow
from .http import BudgetExceeded


class ParentMoved(RuntimeError):
    """Remote publication raced; reread and recompute before retrying."""


class GitStore:
    def __init__(self, path, remote, token=None):
        self.path = Path(path)
        self.path.mkdir(parents=True, exist_ok=True)
        self.env = dict(os.environ, GIT_TERMINAL_PROMPT='0',
            GIT_AUTHOR_NAME='ARGUS data sync', GIT_AUTHOR_EMAIL='sync@argus.invalid',
            GIT_COMMITTER_NAME='ARGUS data sync', GIT_COMMITTER_EMAIL='sync@argus.invalid')
        if token:
            credential = base64.b64encode(('x-access-token:' + token).encode()).decode()
            self.env.update(GIT_CONFIG_COUNT='1', GIT_CONFIG_KEY_0='http.https://github.com/.extraheader',
                            GIT_CONFIG_VALUE_0='AUTHORIZATION: basic ' + credential)
        self.remote = remote
        if not (self.path / 'HEAD').exists():
            self.run('init', '--bare')

    def run(self, *args, data=None, check=True, extra_env=None):
        result = subprocess.run(['git', '-C', str(self.path), *args], input=data,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env={**self.env, **(extra_env or {})}, timeout=90)
        if check and result.returncode:
            raise RuntimeError('git operation failed: ' + args[0])
        return result

    def read(self, branch, revision=None):
        if branch not in ('data', 'control'):
            raise ValueError('unsupported publication branch')
        result = self.run('ls-remote', '--heads', self.remote, f'refs/heads/{branch}')
        if not result.stdout.strip():
            return None, {}
        # Fetch resolves one immutable snapshot even if ls-remote raced.
        self.run('fetch', '--depth=1', '--no-tags', self.remote, revision or f'refs/heads/{branch}')
        sha = self.run('rev-parse', 'FETCH_HEAD').stdout.decode().strip()
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
        for path, _ in objects:
            end = batch.index(b'\n', offset)
            _, kind, raw_size = batch[offset:end].split()
            size = int(raw_size)
            if kind != b'blob' or size > 2 * 1024 * 1024 or sum(map(len, files.values())) + size > 32 * 1024 * 1024:
                raise ValueError('published snapshot exceeds bounds')
            offset = end + 1
            files[path] = batch[offset:offset + size]
            offset += size + 1
        return sha, files

    def publish(self, branch, parent, files, message):
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
        # No force, force-with-lease, history deletion or application remote here.
        result = self.run('push', self.remote, f'{sha}:refs/heads/{branch}', check=False)
        if result.returncode:
            if b'rejected' in result.stderr or b'failed to update ref' in result.stderr:
                raise ParentMoved('remote parent moved')
            raise RuntimeError('git publication failed')
        return sha, True


class Ledger:
    """Control-branch reservations survive killed jobs and fresh runners."""
    def __init__(self, store, policy, day=None):
        self.store, self.policy = store, policy
        self.day = day or utcnow()[:10]

    def read(self):
        parent, files = self.store.read('control')
        self.health = files.get('health.json')
        ledger = json.loads(files.get('ledger.json', b'{}'))
        if ledger.get('day') != self.day:
            ledger = {'schema_version': '1.0', 'day': self.day, 'reservations': {},
                'history_upper_bound_bytes': ledger.get('history_upper_bound_bytes', 0),
                'runner_month': self.day[:7],
                'runner_minutes_used': ledger.get('runner_minutes_used', 0) if ledger.get('runner_month') == self.day[:7] else 0,
                'daily_history': {day: value for day, value in ledger.get('daily_history', {}).items()
                                  if day >= self.day[:8] + '01'}}
        return parent, ledger

    def files(self, ledger, health=None):
        files = {'ledger.json': canonical(ledger)}
        current = canonical(health) if health is not None else self.health
        if current:
            if len(current) > 65536:
                raise ValueError('health summary exceeds 64 KiB')
            files['health.json'] = current
        return files

    def reserve(self, job_id, requested, *, bootstrap=False):
        for _ in range(3):
            parent, ledger = self.read()
            if job_id in ledger['reservations']:
                # A rerun of an interrupted job receives no second allowance.
                raise BudgetExceeded('job already reserved; use a new run attempt')
            limit = self.policy['job_bytes'] if bootstrap else self.policy['daily_bytes']
            used = sum(x['charged_bytes'] for x in ledger['reservations'].values())
            allocation = min(requested, max(0, limit - used))
            if allocation <= 0:
                raise BudgetExceeded('persistent daily byte budget exhausted')
            runner_limit = self.policy.get('repository_runner_minutes', self.policy['monthly_runner_minutes'])
            if ledger.get('runner_minutes_used', 0) + 12 > runner_limit:
                raise BudgetExceeded('persistent monthly runner budget exhausted')
            ledger['runner_minutes_used'] = ledger.get('runner_minutes_used', 0) + 12
            ledger['reservations'][job_id] = {'charged_bytes': allocation, 'reserved_bytes': allocation,
                'status': 'reserved', 'started_at': utcnow(), 'requests': 0, 'reserved_minutes': 12}
            ledger['history_upper_bound_bytes'] += len(canonical(ledger)) + len(self.health or b'') + 4096
            try:
                self.store.publish('control', parent, self.files(ledger), 'chore(data): reserve upstream budget')
                return allocation
            except ParentMoved:
                continue
        raise ParentMoved('budget reservation contention')

    def settle(self, job_id, actual_bytes, requests, changed_bytes=0, *, bootstrap=False, health=None, runner_seconds=720):
        for _ in range(3):
            parent, ledger = self.read()
            item = ledger['reservations'].get(job_id)
            if not item:
                raise ValueError('missing daily reservation')
            if item['status'] == 'settled':
                return
            if actual_bytes > item['reserved_bytes']:
                raise ValueError('actual transfer exceeds reservation')
            item.update(charged_bytes=actual_bytes, requests=requests, status='settled', completed_at=utcnow())
            actual_minutes = min(12, max(1, math.ceil(runner_seconds / 60)))
            ledger['runner_minutes_used'] -= item.get('reserved_minutes', 12) - actual_minutes
            item['runner_minutes'] = actual_minutes
            ledger['history_upper_bound_bytes'] += changed_bytes
            if not bootstrap:
                ledger['daily_history'][self.day] = ledger['daily_history'].get(self.day, 0) + changed_bytes
            # Small control commits also consume all-branch history.
            ledger['history_upper_bound_bytes'] += len(canonical(ledger)) + len(canonical(health)) + 4096
            try:
                self.store.publish('control', parent, self.files(ledger, health), 'chore(data): settle upstream budget')
                return
            except ParentMoved:
                continue
        raise ParentMoved('budget settlement contention')

    def publication_allowed(self, proposed_bytes, *, bootstrap=False):
        _, ledger = self.read()
        history = ledger['history_upper_bound_bytes'] + proposed_bytes
        daily = list(ledger.get('daily_history', {}).values())
        estimated_month = (sum(daily) + (0 if bootstrap else proposed_bytes)) / max(1, len(daily)) * 30
        daily_average = (sum(daily) + (0 if bootstrap else proposed_bytes)) / max(1, len(daily))
        return (history < self.policy['history_bytes'] and estimated_month < self.policy['monthly_history_growth_bytes']
                and daily_average <= self.policy['daily_git_change_bytes'])
