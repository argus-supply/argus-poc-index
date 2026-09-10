"""Opt-in local GitHub REST recovery transport; collector defaults stay native Git.

Ledger still prepares, measures and reserves exact local commits before publication.
REST object creation must preserve every SHA; only then may a non-force ref move.
Unsigned commits whose API dates lose their original offset need a local snapshot
import. Signed or extended candidate headers are rejected instead of rewritten.
"""
from concurrent.futures import ThreadPoolExecutor
import base64
import datetime as dt
import hashlib
import json
from pathlib import Path
import re
import threading
import time
import urllib.error
import urllib.request

from sync.gitstore import GitStore, ParentMoved
from sync.gitcost import GitCostUnavailable, _Git
from sync.observations import threshold_observation


REPOSITORIES = ('argus-intel-data', 'argus-poc-index', 'argus-detection-resources')
BRANCHES = ('main', 'data', 'control')
SHA = re.compile(r'[a-f0-9]{40}')
MAX_TREE_BYTES = 32 * 1024 * 1024
MAX_BLOB_BYTES = 2 * 1024 * 1024
MAX_METADATA_BYTES = 16 * 1024 * 1024
MAX_ENTRIES = 100000
GITHUB_MAX_BLOB_BYTES = 100 * 1024 * 1024
MAX_BLOB_JSON_BYTES = ((GITHUB_MAX_BLOB_BYTES + 2) // 3 * 4) + 65536


class GitHubApiError(RuntimeError):
    """Bounded API error containing no upstream body, credential or request headers."""
    def __init__(self, message, status=None):
        super().__init__(message)
        self.status = status


class NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if fp is not None:
            fp.close()
        raise GitHubApiError('GitHub REST redirect refused', code)


class GitHubRest:
    """Non-retrying REST with advisory totals and hard per-response safety bounds."""
    def __init__(self, repository, token, *, opener=None, max_requests=5000,
                 max_wire_bytes=128 * 1024 * 1024, max_seconds=1800):
        if repository not in REPOSITORIES or not isinstance(token, str) or not token or '\n' in token or '\r' in token:
            raise ValueError('expected one authorized repository and an in-memory token')
        for value in (max_requests, max_wire_bytes, max_seconds):
            if type(value) is not int or value <= 0:
                raise ValueError('invalid recovery transport target')
        self.repository, self.token = repository, token
        self.opener = opener or urllib.request.build_opener(NoRedirects())
        self.max_requests, self.max_wire_bytes, self.max_seconds = max_requests, max_wire_bytes, max_seconds
        self.requests = self.uploaded_bytes = self.downloaded_bytes = 0
        self.started, self.lock = time.monotonic(), threading.Lock()

    def report(self):
        return {'transport': 'github-rest-git', 'requests': self.requests,
            'request_json_bytes_attempted': self.uploaded_bytes, 'response_json_bytes_read': self.downloaded_bytes,
            'elapsed_seconds': round(time.monotonic() - self.started, 3),
            'limits': {'requests': self.max_requests, 'wire_bytes': self.max_wire_bytes, 'seconds': self.max_seconds},
            'enforcement': 'advisory', 'capacity_observations': self.observations(),
            'scope': 'Request payload bytes reserved before send and response bytes actually read; separate from compressed Git object costs'}

    def observations(self):
        """Report cumulative usage without preventing a subsequent request."""
        return [threshold_observation(name, value, target) for name, value, target in (
            ('rest_requests', self.requests, self.max_requests),
            ('rest_wire_bytes', self.uploaded_bytes + self.downloaded_bytes, self.max_wire_bytes),
            ('rest_seconds', round(time.monotonic() - self.started, 3), self.max_seconds))]

    def request(self, method, route, payload=None):
        allowed = {
            'GET': r'(?:matching-refs/heads/|(?:commits|blobs)/[a-f0-9]{40}|trees/[a-f0-9]{40}\?recursive=1)',
            'POST': r'(?:blobs|trees|commits|refs)',
            'PATCH': r'refs/heads/(?:main|data|control)',
        }
        if method not in allowed or not re.fullmatch(allowed[method], route):
            raise ValueError('GitHub REST route is outside recovery scope')
        if route == 'refs' and (payload or {}).get('ref') not in ('refs/heads/' + name for name in BRANCHES):
            raise ValueError('GitHub REST branch is outside recovery scope')
        if method == 'PATCH' and (payload or {}).get('force') is not False:
            raise ValueError('recovery ref updates must be non-force')
        body = None if payload is None else json.dumps(payload, ensure_ascii=False, separators=(',', ':')).encode()
        request_limit = MAX_BLOB_JSON_BYTES if method == 'POST' and route == 'blobs' else MAX_METADATA_BYTES
        response_limit = MAX_BLOB_JSON_BYTES if method == 'GET' and route.startswith('blobs/') else MAX_METADATA_BYTES
        if body is not None:
            if method == 'POST' and route == 'blobs' and len(body) > request_limit:
                raise GitHubApiError('GitHub REST blob request exceeds GitHub file limit envelope')
            threshold_observation('rest_request_json_bytes', len(body), MAX_METADATA_BYTES)
        with self.lock:
            size = len(body or b'')
            self.requests += 1
            self.uploaded_bytes += size
            self.observations()
        url = 'https://api.github.com/repos/argus-supply/' + self.repository + '/git/' + route
        request = urllib.request.Request(url, data=body, method=method, headers={
            'Authorization': 'Bearer ' + self.token, 'Accept': 'application/vnd.github+json',
            'Accept-Encoding': 'identity', 'Content-Type': 'application/json',
            'X-GitHub-Api-Version': '2022-11-28', 'User-Agent': 'ARGUS-local-git-recovery/1.0'})
        try:
            with self.opener.open(request, timeout=30) as response:
                if not 200 <= response.status < 300:
                    raise GitHubApiError('GitHub REST HTTP ' + str(response.status), response.status)
                if 'rel="next"' in response.headers.get('Link', ''):
                    raise GitHubApiError('GitHub REST branch inventory is paginated')
                if response.headers.get('Content-Encoding', 'identity') != 'identity':
                    raise GitHubApiError('GitHub REST compressed response refused')
                chunks, received = [], 0
                while True:
                    # Count every received byte across concurrent requests. The
                    # per-response cap protects against untrusted oversized JSON.
                    with self.lock:
                        chunk = response.read(min(65536, response_limit - received + 1))
                        self.downloaded_bytes += len(chunk)
                    received += len(chunk)
                    if received > response_limit:
                        raise GitHubApiError('GitHub REST response exceeds per-response safety bound')
                    if not chunk:
                        break
                    chunks.append(chunk)
                self.observations()
                return json.loads(b''.join(chunks))
        except urllib.error.HTTPError as error:
            status = error.code
            error.close()
            raise GitHubApiError('GitHub REST HTTP ' + str(status), status) from None
        except (urllib.error.URLError, OSError, TimeoutError):
            raise GitHubApiError('GitHub REST transport failed; publication state remains unconfirmed') from None
        except (ValueError, UnicodeError):
            raise GitHubApiError('GitHub REST returned invalid JSON') from None


def checked_sha(value):
    if not isinstance(value, str) or not SHA.fullmatch(value):
        raise GitHubApiError('invalid immutable Git SHA')
    return value


def identity_from_api(value):
    try:
        name, email, date = value['name'], value['email'], dt.datetime.fromisoformat(value['date'].replace('Z', '+00:00'))
        if date.tzinfo is None or date.microsecond or any(c in name + email for c in '\n\r\x00<>'):
            raise ValueError()
        return f'{name} <{email}> {int(date.timestamp())} {date.strftime("%z")}'
    except (KeyError, TypeError, ValueError, AttributeError):
        raise GitHubApiError('GitHub REST commit identity cannot be reconstructed') from None


def commit_from_api(value, expected):
    """Reconstruct exact unsigned commit bytes; API-normalized dates never change SHA."""
    if (value.get('verification') or {}).get('signature'):
        raise GitHubApiError('signed remote commit requires local snapshot import')
    try:
        lines = ['tree ' + checked_sha(value['tree']['sha'])]
        lines.extend('parent ' + checked_sha(parent['sha']) for parent in value['parents'])
        lines.extend([key + ' ' + identity_from_api(value[key]) for key in ('author', 'committer')])
        body = ('\n'.join(lines) + '\n\n' + value['message']).encode('utf-8')
    except (KeyError, TypeError, UnicodeError):
        raise GitHubApiError('GitHub REST commit metadata is incomplete') from None
    if hashlib.sha1(b'commit ' + str(len(body)).encode() + b'\0' + body).hexdigest() != expected:
        raise GitHubApiError('remote commit SHA mismatch; import its exact local snapshot to retain original metadata')
    return body


def commit_payload(body):
    """Project only headers the REST commit endpoint can reproduce without loss."""
    try:
        head, message = body.decode('utf-8').split('\n\n', 1)
        fields, parents = {}, []
        for line in head.splitlines():
            key, value = line.split(' ', 1)
            if key == 'parent':
                parents.append(checked_sha(value))
            elif key in ('tree', 'author', 'committer') and key not in fields:
                fields[key] = value
            else:
                raise ValueError()
        result = {'tree': checked_sha(fields['tree']), 'parents': parents, 'message': message}
        for key in ('author', 'committer'):
            match = re.fullmatch(r'([^\n<>]+) <([^\n<>]+)> (-?\d+) ([+-]\d{4})', fields[key])
            if not match:
                raise ValueError()
            name, email, epoch, offset = match.groups()
            date = dt.datetime.fromtimestamp(int(epoch), dt.timezone.utc)
            zone = dt.datetime.strptime(offset, '%z').tzinfo
            result[key] = {'name': name, 'email': email, 'date': date.astimezone(zone).isoformat(timespec='seconds')}
        return result
    except (KeyError, ValueError, OverflowError, UnicodeError):
        raise GitHubApiError('candidate commit has unsupported headers or identity; exact SHA publication refused') from None


class GitHubApiStore(GitStore):
    """GitStore replacement for explicit local recovery, with snapshot-only API reads."""
    def __init__(self, path, repository, token=None, *, api=None):
        if repository not in REPOSITORIES:
            raise ValueError('repository is outside the three authorized targets')
        self.repository = repository
        self.api = api or GitHubRest(repository, token)
        if self.api.repository != repository:
            raise ValueError('REST client repository does not match the store')
        self.snapshots = {}
        super().__init__(path, 'https://github.com/argus-supply/' + repository + '.git')
        for key in list(self.env):
            if key in ('GH_TOKEN', 'GITHUB_TOKEN', 'GIT_AUTHOR_DATE', 'GIT_COMMITTER_DATE') or key.startswith('GIT_CONFIG_'):
                self.env.pop(key)
        self.env.update(TZ='UTC', GIT_NO_LAZY_FETCH='1', GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL='/dev/null',
            GIT_CONFIG_COUNT='2', GIT_CONFIG_KEY_0='gc.auto', GIT_CONFIG_VALUE_0='0',
            GIT_CONFIG_KEY_1='maintenance.auto', GIT_CONFIG_VALUE_1='false')

    def _has(self, sha, kind):
        return self.run('cat-file', '-t', checked_sha(sha), check=False).stdout.strip() == kind.encode()

    def _write_object(self, kind, body, expected):
        actual = self.run('hash-object', '-t', kind, '-w', '--stdin', data=body).stdout.decode().strip()
        if actual != expected:
            raise GitHubApiError('GitHub REST ' + kind + ' SHA mismatch')

    def import_local_snapshot(self, source, sha):
        """Batch-copy one bounded snapshot, including raw metadata, never ancestry.

        Explicit object IDs feed a non-delta pack without revision traversal. The
        shallow marker lets strict indexing validate this snapshot without fetching
        missing parents. Existing objects are reused and every imported ID checked.
        """
        source = Path(source).resolve()
        if not source.is_dir():
            raise ValueError('local snapshot source must be an existing directory')
        checked_sha(sha)

        source_git, destination_git = _Git(source, 90), _Git(self.path, 90)

        def bounded(git, *args, data=None, limit=None):
            try:
                return git.run(*args, data=data, limit=limit)
            except GitCostUnavailable:
                raise GitHubApiError('local snapshot operation failed or exceeded its bound') from None

        commit = bounded(source_git, 'cat-file', 'commit', sha)
        entries = bounded(source_git, 'ls-tree', '-rzt', '--full-tree', sha)
        root = checked_sha(commit.split(b'\n', 1)[0].removeprefix(b'tree ').decode())
        objects = {root: 'tree', sha: 'commit'}
        blob_paths, entry_count = [], 0
        for entry in entries.split(b'\0'):
            if not entry:
                continue
            meta, _ = entry.split(b'\t', 1)
            mode, kind, oid = meta.decode().split()
            if (mode, kind) not in (('040000', 'tree'), ('100644', 'blob'), ('100755', 'blob')):
                raise GitHubApiError('unsupported local snapshot tree mode')
            objects[checked_sha(oid)] = kind
            entry_count += 1
            if kind == 'blob':
                blob_paths.append(oid)
        ordered = sorted(objects)
        threshold_observation('local_snapshot_entries', entry_count, MAX_ENTRIES)
        threshold_observation('local_snapshot_objects', len(objects), MAX_ENTRIES)
        request = ('\n'.join(ordered) + '\n').encode()
        batch_format = '--batch-check=%(objectname) %(objecttype) %(objectsize)'
        checks = bounded(source_git, 'cat-file', batch_format, data=request).splitlines()
        if len(checks) != len(ordered):
            raise GitHubApiError('local snapshot object inventory is incomplete')
        sizes = {}
        for expected, line in zip(ordered, checks):
            fields = line.decode('ascii').split()
            if len(fields) != 3 or fields[:2] != [expected, objects[expected]] or not fields[2].isdigit():
                raise GitHubApiError('local snapshot object identity or type mismatch')
            oid, kind, size = fields[0], fields[1], int(fields[2])
            if kind == 'blob' and size > GITHUB_MAX_BLOB_BYTES:
                raise GitHubApiError('local snapshot exceeds GitHub 100 MiB file limit')
            threshold_observation('local_snapshot_object_bytes', size,
                                  MAX_BLOB_BYTES if kind == 'blob' else MAX_METADATA_BYTES)
            sizes[oid] = size
        total = sum(sizes[oid] for oid in blob_paths)
        threshold_observation('local_snapshot_tree_bytes', total, MAX_TREE_BYTES)
        threshold_observation('local_snapshot_raw_object_bytes', sum(sizes.values()),
                              MAX_TREE_BYTES + MAX_METADATA_BYTES)
        present = bounded(destination_git, 'cat-file', batch_format, data=request).splitlines()
        if len(present) != len(ordered):
            raise GitHubApiError('destination object inventory is incomplete')
        missing = []
        for oid, line in zip(ordered, present):
            if line == (oid + ' missing').encode():
                missing.append(oid)
            elif line != f'{oid} {objects[oid]} {sizes[oid]}'.encode():
                raise GitHubApiError('destination snapshot object metadata mismatch')
        pack_bytes = 0
        if missing:
            pack = bounded(source_git, 'pack-objects', '--stdout', '--compression=6',
                '--window=0', '--depth=0', '--threads=1', '--no-reuse-object', '--no-reuse-delta',
                data=('\n'.join(missing) + '\n').encode(), limit=None)
            pack_bytes = len(pack)
            if len(pack) < 32 or pack[:4] != b'PACK' or int.from_bytes(pack[8:12], 'big') != len(missing):
                raise GitHubApiError('snapshot pack contains an unexpected object inventory')
            self._mark_shallow(sha)
            bounded(destination_git, 'index-pack', '--stdin', '--strict', data=pack, limit=65536)
            verified = bounded(destination_git, 'cat-file', batch_format, data=request).splitlines()
            if verified != checks:
                raise GitHubApiError('imported snapshot does not preserve every original object SHA')
        self._mark_shallow(sha)
        return {'candidate': sha, 'snapshot_object_count': len(objects), 'imported_object_count': len(missing),
                'pack_bytes': pack_bytes, 'logical_tree_bytes': total, 'ancestry_imported': False}

    def _mark_shallow(self, sha):
        path = self.path / 'shallow'
        entries = set(path.read_text().splitlines()) if path.exists() else set()
        entries.add(sha)
        path.write_text('\n'.join(sorted(entries)) + '\n')

    def _inventory(self, sha):
        if sha in self.snapshots:
            return self.snapshots[sha]
        if self._has(sha, 'commit'):
            raw = self.run('cat-file', 'commit', sha).stdout
        else:
            value = self.api.request('GET', 'commits/' + checked_sha(sha))
            if value.get('sha') != sha:
                raise GitHubApiError('GitHub REST commit identity mismatch')
            raw = commit_from_api(value, sha)
            self._write_object('commit', raw, sha)
            self._mark_shallow(sha)
        root = checked_sha(raw.split(b'\n', 1)[0].removeprefix(b'tree ').decode())
        response = self.api.request('GET', 'trees/' + root + '?recursive=1')
        if response.get('truncated') is not False or response.get('sha') != root:
            raise GitHubApiError('GitHub REST tree is truncated or has the wrong SHA')
        entries = response.get('tree')
        if not isinstance(entries, list):
            raise GitHubApiError('invalid GitHub REST tree inventory')
        threshold_observation('rest_snapshot_entries', len(entries), MAX_ENTRIES)
        trees, blobs, children, total, paths = {'': root}, {}, {}, 0, set()
        for item in entries:
            path, kind, mode, oid = item.get('path'), item.get('type'), item.get('mode'), checked_sha(item.get('sha'))
            if not isinstance(path, str) or '\0' in path or any(part in ('', '.', '..') for part in path.split('/')) or path in paths or path.count('/') > 64:
                raise GitHubApiError('unsafe or duplicate GitHub REST tree path')
            paths.add(path)
            parent, _, name = path.rpartition('/')
            children.setdefault(parent, []).append((mode, kind, oid, name))
            if kind == 'tree' and mode == '040000':
                trees[path] = oid
            elif kind == 'blob' and mode in ('100644', '100755'):
                size = item.get('size')
                if type(size) is not int or not 0 <= size <= GITHUB_MAX_BLOB_BYTES:
                    raise GitHubApiError('GitHub REST blob exceeds GitHub 100 MiB file limit')
                threshold_observation('rest_blob_bytes', size, MAX_BLOB_BYTES)
                total += size
                if oid in blobs and blobs[oid] != size:
                    raise GitHubApiError('GitHub REST blob size disagrees across paths')
                blobs[oid] = size
            else:
                raise GitHubApiError('GitHub REST tree mode is unsupported')
        if any(parent not in trees for parent in children):
            raise GitHubApiError('GitHub REST tree omits a parent tree')
        threshold_observation('rest_snapshot_tree_bytes', total, MAX_TREE_BYTES)

        def download(oid):
            if self._has(oid, 'blob'):
                return
            value = self.api.request('GET', 'blobs/' + oid)
            try:
                body = base64.b64decode(''.join(value['content'].split()), validate=True)
            except (ValueError, KeyError, TypeError):
                raise GitHubApiError('GitHub REST blob encoding is invalid') from None
            if value.get('encoding') != 'base64' or value.get('sha') != oid or value.get('size') != len(body) or len(body) != blobs[oid]:
                raise GitHubApiError('GitHub REST blob size or SHA declaration mismatch')
            self._write_object('blob', body, oid)

        with ThreadPoolExecutor(max_workers=4) as executor:
            list(executor.map(download, blobs))
        for path, oid in sorted(trees.items(), key=lambda item: item[0].count('/') + bool(item[0]), reverse=True):
            rows = children.get(path, [])
            body = b''.join(f'{mode} {kind} {child}\t{name}'.encode() + b'\0' for mode, kind, child, name in rows)
            actual = self.run('mktree', '-z', data=body).stdout.decode().strip()
            if actual != oid:
                raise GitHubApiError('GitHub REST reconstructed tree SHA mismatch')
        result = {'root': root, 'entries': entries, 'objects': {sha, *trees.values(), *blobs}, 'bytes': total}
        self.snapshots[sha] = result
        return result

    def observe_heads(self):
        values = self.api.request('GET', 'matching-refs/heads/')
        if not isinstance(values, list) or len(values) > len(BRANCHES):
            raise GitHubApiError('GitHub REST branch inventory is incomplete or outside scope')
        tips = {}
        for item in values:
            ref = item.get('ref')
            obj = item.get('object', {})
            if ref not in ('refs/heads/' + name for name in BRANCHES) or ref in tips or obj.get('type') != 'commit':
                raise GitHubApiError('unexpected GitHub REST branch or object type')
            tips[ref] = checked_sha(obj.get('sha'))
        for sha in tips.values():
            self._inventory(sha)
        return tips

    def read(self, branch, revision=None):
        if branch not in BRANCHES:
            raise ValueError('unsupported publication branch')
        if revision:
            self._inventory(checked_sha(revision))
        return super().read(branch, revision)

    def push_prepared(self, branch, sha):
        """Create only missing snapshot objects and update one non-force branch ref."""
        if branch not in BRANCHES:
            raise ValueError('unsupported publication branch')
        checked_sha(sha)
        payload = commit_payload(self.run('cat-file', 'commit', sha).stdout)
        tips = self.observe_heads()
        ref, parent = 'refs/heads/' + branch, tips.get('refs/heads/' + branch)
        if parent == sha:
            return sha, False
        if payload['parents'] != ([parent] if parent else []):
            raise ParentMoved('GitHub REST branch moved before publication')
        known = set().union(*(self.snapshots[value]['objects'] for value in tips.values())) if tips else set()
        raw_entries = self.run('ls-tree', '-rzt', '--full-tree', sha).stdout
        threshold_observation('candidate_tree_metadata_bytes', len(raw_entries), MAX_METADATA_BYTES)
        trees, blobs, children, total = {'': payload['tree']}, {}, {}, 0
        for raw in raw_entries.split(b'\0'):
            if not raw:
                continue
            meta, path = raw.split(b'\t', 1)
            mode, kind, oid = meta.decode().split()
            path = path.decode('utf-8')
            parent_path, _, name = path.rpartition('/')
            children.setdefault(parent_path, []).append({'path': name, 'mode': mode, 'type': kind, 'sha': oid})
            if mode == '040000' and kind == 'tree':
                trees[path] = oid
            elif mode in ('100644', '100755') and kind == 'blob':
                size = int(self.run('cat-file', '-s', oid).stdout)
                if size > GITHUB_MAX_BLOB_BYTES:
                    raise GitHubApiError('candidate exceeds GitHub 100 MiB file limit')
                threshold_observation('candidate_blob_bytes', size, MAX_BLOB_BYTES)
                blobs[oid] = size
                total += size
            else:
                raise GitHubApiError('candidate tree mode is unsupported')
        threshold_observation('candidate_tree_bytes', total, MAX_TREE_BYTES)
        threshold_observation('candidate_snapshot_entries', len(trees) + len(blobs), MAX_ENTRIES)

        def upload(oid):
            body = self.run('cat-file', 'blob', oid).stdout
            result = self.api.request('POST', 'blobs', {'encoding': 'base64', 'content': base64.b64encode(body).decode()})
            if result.get('sha') != oid:
                raise GitHubApiError('uploaded blob SHA differs from reserved candidate')

        with ThreadPoolExecutor(max_workers=4) as executor:
            list(executor.map(upload, sorted(set(blobs) - known)))
        for path, oid in sorted(trees.items(), key=lambda item: item[0].count('/') + bool(item[0]), reverse=True):
            if oid not in known:
                value = self.api.request('POST', 'trees', {'tree': children.get(path, [])})
                if value.get('sha') != oid:
                    raise GitHubApiError('uploaded tree SHA differs from reserved candidate')
                known.add(oid)
        value = self.api.request('POST', 'commits', payload)
        if value.get('sha') != sha:
            raise GitHubApiError('created commit SHA differs from precharged candidate; ref update refused')
        try:
            value = self.api.request('PATCH', 'refs/heads/' + branch, {'sha': sha, 'force': False}) if parent else self.api.request(
                'POST', 'refs', {'ref': ref, 'sha': sha})
        except GitHubApiError as error:
            if error.status in (409, 422):
                raise ParentMoved('GitHub REST ref update rejected; publication intent retained') from None
            raise
        if value.get('ref') != ref or value.get('object', {}).get('sha') != sha:
            raise GitHubApiError('GitHub REST ref acknowledgement mismatch; publication intent retained')
        return sha, True
