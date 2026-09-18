"""Offline REST object fixtures backed by real bare Git; no public network access."""
import base64
from concurrent.futures import ThreadPoolExecutor
import copy
import io
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
import urllib.error
from unittest.mock import patch

from sync.core import ROOT, load_policy
from sync.gitstore import GitStore, ParentMoved
from sync.gitcost import _Git
from sync.ledger import Ledger
from tools.github_api_store import (GitHubApiError, GitHubApiStore, GitHubRest,
                                    commit_payload, identity_from_api)


class LocalGitApi:
    """GitHub JSON projection with real object hashing and ref ancestry checks."""
    repository = 'argus-intel-data'

    def __init__(self, path):
        self.git = GitStore(path, str(path))
        self.calls, self.refs = [], {}
        self.mutate = None
        self.fail_ref = None
        self.normalize_dates = False
        self.lock = threading.Lock()
        self.active_uploads = self.peak_uploads = 0

    def object(self, kind, body):
        return self.git.run('hash-object', '-t', kind, '-w', '--stdin', data=body).stdout.decode().strip()

    def seed(self, files, branch='main', parent=None, offset='+00:00'):
        candidate, _ = self.git.prepare(branch, parent, files, 'fixture original message\n')
        if offset != '+00:00':
            payload = commit_payload(self.git.run('cat-file', 'commit', candidate).stdout)
            for key in ('author', 'committer'):
                payload[key]['date'] = '2026-09-09T11:00:00' + offset
            candidate = self.create_commit(payload)
        self.refs['refs/heads/' + branch] = candidate
        return candidate

    def create_commit(self, payload):
        lines = ['tree ' + payload['tree'], *['parent ' + sha for sha in payload['parents']]]
        lines += [key + ' ' + identity_from_api(payload[key]) for key in ('author', 'committer')]
        return self.object('commit', ('\n'.join(lines) + '\n\n' + payload['message']).encode())

    def request(self, method, route, payload=None):
        with self.lock:
            self.calls.append((method, route, copy.deepcopy(payload)))
        if self.mutate:
            replacement = self.mutate(method, route, payload)
            if replacement is not None:
                return replacement
        if method == 'GET' and route == 'matching-refs/heads/':
            return [{'ref': ref, 'object': {'sha': sha, 'type': 'commit'}} for ref, sha in self.refs.items()]
        if method == 'GET' and route.startswith('commits/'):
            sha = route.split('/')[1]
            payload = commit_payload(self.git.run('cat-file', 'commit', sha).stdout)
            if self.normalize_dates:
                for key in ('author', 'committer'):
                    import datetime as dt
                    payload[key]['date'] = dt.datetime.fromisoformat(payload[key]['date']).astimezone(dt.timezone.utc).isoformat()
            return {**payload, 'sha': sha, 'tree': {'sha': payload['tree']},
                    'parents': [{'sha': value} for value in payload['parents']], 'verification': {'signature': None}}
        if method == 'GET' and route.startswith('trees/'):
            sha = route.split('/')[1].split('?')[0]
            entries = []
            for raw in self.git.run('ls-tree', '-rzt', sha).stdout.split(b'\0'):
                if not raw:
                    continue
                metadata, path = raw.split(b'\t', 1)
                mode, kind, oid = metadata.decode().split()
                row = {'mode': mode, 'type': kind, 'sha': oid, 'path': path.decode()}
                if kind == 'blob':
                    row['size'] = int(self.git.run('cat-file', '-s', oid).stdout)
                entries.append(row)
            return {'sha': sha, 'truncated': False, 'tree': entries}
        if method == 'GET' and route.startswith('blobs/'):
            sha = route.split('/')[1]
            body = self.git.run('cat-file', 'blob', sha).stdout
            return {'sha': sha, 'encoding': 'base64', 'content': base64.b64encode(body).decode(), 'size': len(body)}
        if method == 'POST' and route == 'blobs':
            with self.lock:
                self.active_uploads += 1
                self.peak_uploads = max(self.peak_uploads, self.active_uploads)
            try:
                return {'sha': self.object('blob', base64.b64decode(payload['content']))}
            finally:
                with self.lock:
                    self.active_uploads -= 1
        if method == 'POST' and route == 'trees':
            body = b''.join(f'{row["mode"]} {row["type"]} {row["sha"]}\t{row["path"]}'.encode() + b'\0' for row in payload['tree'])
            return {'sha': self.git.run('mktree', '-z', data=body).stdout.decode().strip()}
        if method == 'POST' and route == 'commits':
            return {'sha': self.create_commit(payload)}
        if method == 'PATCH' or method == 'POST' and route == 'refs':
            if self.fail_ref:
                raise self.fail_ref
            ref = 'refs/heads/' + route.rsplit('/', 1)[-1] if method == 'PATCH' else payload['ref']
            if method == 'PATCH':
                if payload.get('force') is not False:
                    raise AssertionError('force update was attempted')
                raw = self.git.run('cat-file', 'commit', payload['sha']).stdout
                parents = commit_payload(raw)['parents']
                if parents != [self.refs[ref]]:
                    raise GitHubApiError('fixture ref conflict', 422)
            elif ref in self.refs:
                raise GitHubApiError('fixture existing ref', 422)
            self.refs[ref] = payload['sha']
            return {'ref': ref, 'object': {'sha': payload['sha'], 'type': 'commit'}}
        raise AssertionError('unexpected offline API route: ' + method + ' ' + route)


class ApiStoreTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='argus-rest-store-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.api = LocalGitApi(self.root / 'api.git')
        self.store = GitHubApiStore(self.root / 'client.git', self.api.repository, api=self.api)

    def test_shallow_snapshot_rebuilds_exact_objects_without_parent_or_duplicate_blob_reads(self):
        parent = self.api.seed({'old': b'old history'})
        sha = self.api.seed({'nested/a': b'shared', 'nested/b': b'shared', 'plain': b'new'}, parent=parent)
        read_sha, files = self.store.read('main')
        self.assertEqual(read_sha, sha)
        self.assertEqual(files, {'nested/a': b'shared', 'nested/b': b'shared', 'plain': b'new'})
        self.assertFalse(self.store._has(parent, 'commit'))
        self.assertEqual((self.store.path / 'shallow').read_text().strip(), sha)
        commits = [route for method, route, _ in self.api.calls if method == 'GET' and route.startswith('commits/')]
        blobs = [route for method, route, _ in self.api.calls if method == 'GET' and route.startswith('blobs/')]
        self.assertEqual(commits, ['commits/' + sha])
        self.assertEqual(len(blobs), 2)
        self.api.calls.clear()
        self.store.read('main')
        self.assertEqual([route for _, route, _ in self.api.calls], ['matching-refs/heads/'])

    def test_local_snapshot_recovers_utc_projected_commit_without_sha_drift(self):
        sha = self.api.seed({'main.py': b'local source'}, offset='+08:00')
        self.api.normalize_dates = True
        with self.assertRaisesRegex(GitHubApiError, 'remote commit SHA mismatch'):
            self.store.observe_heads()
        self.store.import_local_snapshot(self.api.git.path, sha)
        self.api.calls.clear()
        self.assertEqual(self.store.read('main'), (sha, {'main.py': b'local source'}))
        self.assertFalse(any(route.startswith('commits/') or route.startswith('blobs/') for _, route, _ in self.api.calls))

    def test_local_batch_import_copies_only_missing_snapshot_objects_without_parent_history(self):
        parent = self.api.seed({'history-only': b'not part of the current snapshot'})
        files = {'records/' + str(index) + '.json': ('record-' + str(index)).encode() for index in range(120)}
        files['duplicate'] = files['records/0.json']
        candidate = self.api.seed(files, parent=parent)
        original = _Git.run
        commands = []

        def tracked(git, *args, **kwargs):
            commands.append(args)
            return original(git, *args, **kwargs)

        with patch('tools.github_api_store._Git.run', new=tracked):
            imported = self.store.import_local_snapshot(self.api.git.path, candidate)
        self.assertEqual(len(commands), 7)
        self.assertEqual(imported['snapshot_object_count'], 123)
        self.assertEqual(imported['imported_object_count'], 123)
        self.assertGreater(imported['pack_bytes'], 0)
        self.assertEqual(imported['logical_tree_bytes'], sum(map(len, files.values())))
        self.assertFalse(imported['ancestry_imported'])
        self.assertFalse(self.store._has(parent, 'commit'))
        history_blob = self.api.git.run('rev-parse', parent + ':history-only').stdout.decode().strip()
        self.assertFalse(self.store._has(history_blob, 'blob'))
        raw = self.api.git.run('cat-file', 'commit', candidate).stdout
        self.assertEqual(self.store.run('cat-file', 'commit', candidate).stdout, raw)
        self.assertEqual(self.api.calls, [])
        commands.clear()
        with patch('tools.github_api_store._Git.run', new=tracked):
            repeated = self.store.import_local_snapshot(self.api.git.path, candidate)
        self.assertEqual(len(commands), 4)
        self.assertEqual(repeated['imported_object_count'], 0)
        self.assertEqual(repeated['pack_bytes'], 0)

    def test_local_batch_import_warns_on_object_count_but_rejects_corrupt_pack(self):
        candidate = self.api.seed({'file': b'bounded object'})
        with patch('tools.github_api_store.MAX_ENTRIES', 2):
            with self.assertLogs('sync.observations', level='WARNING'):
                self.store.import_local_snapshot(self.api.git.path, candidate)
        self.assertTrue(self.store._has(candidate, 'commit'))
        other = GitHubApiStore(self.root / 'corrupt-import.git', self.api.repository, api=self.api)
        original = _Git.run

        def corrupt(git, *args, **kwargs):
            result = original(git, *args, **kwargs)
            if args[0] == 'pack-objects':
                return result[:-1] + bytes([result[-1] ^ 1])
            return result

        with patch('tools.github_api_store._Git.run', new=corrupt):
            with self.assertRaisesRegex(GitHubApiError, 'failed or exceeded'):
                other.import_local_snapshot(self.api.git.path, candidate)
        self.assertFalse(other._has(candidate, 'commit'))
        self.assertEqual(self.api.calls, [])

    def test_prepared_commits_use_utc_and_ignore_inherited_git_dates(self):
        with patch.dict(os.environ, TZ='Asia/Shanghai', GIT_AUTHOR_DATE='2001-01-01T12:00:00+08:00',
                        GIT_COMMITTER_DATE='2001-01-01T12:00:00+08:00'):
            store = GitHubApiStore(self.root / 'utc-client.git', self.api.repository, api=self.api)
        self.assertEqual(store.env['TZ'], 'UTC')
        self.assertNotIn('GIT_AUTHOR_DATE', store.env)
        self.assertNotIn('GIT_COMMITTER_DATE', store.env)
        candidate, _ = store.prepare('control', None, {'ledger.json': b'{}'}, 'UTC candidate')
        payload = commit_payload(store.run('cat-file', 'commit', candidate).stdout)
        for key in ('author', 'committer'):
            self.assertTrue(payload[key]['date'].endswith('+00:00'))
            self.assertFalse(payload[key]['date'].startswith('2001-'))
        self.assertEqual(store.run('config', '--get', 'gc.auto').stdout.strip(), b'0')
        self.assertEqual(store.run('config', '--get', 'maintenance.auto').stdout.strip(), b'false')

    def test_changed_blobs_upload_once_and_final_ref_matches_precharged_candidate(self):
        parent = self.api.seed({'shared': b'shared', 'old': b'old'})
        self.store.observe_heads()
        files = {'shared': b'shared', 'nested/changed': b'new', 'repeated': b'new',
                 **{'many/' + str(index): str(index).encode() for index in range(6)}}
        candidate, _ = self.store.prepare('main', parent, files, 'exact candidate message\n')
        self.api.calls.clear()
        self.assertEqual(self.store.push_prepared('main', candidate), (candidate, True))
        self.assertEqual(self.api.refs['refs/heads/main'], candidate)
        uploads = [payload for method, route, payload in self.api.calls if method == 'POST' and route == 'blobs']
        self.assertEqual(len(uploads), 7)
        self.assertNotIn(base64.b64encode(b'shared').decode(), [payload['content'] for payload in uploads])
        self.assertLessEqual(self.api.peak_uploads, 4)
        self.assertEqual(self.api.calls[-1], ('PATCH', 'refs/heads/main', {'sha': candidate, 'force': False}))

    def test_ledger_cost_reservation_and_settlement_use_identical_rest_commits(self):
        ledger = Ledger(self.store, load_policy(ROOT / 'policy.json'))
        ledger.reserve('rest-publication', 0, publication_only=True)
        candidate, _ = self.store.prepare('data', None, {'manifest.json': b'{"fixture":true}\n'}, 'data candidate')
        measured = ledger.reserve_publication('rest-publication', 'data', candidate, 17)
        control = self.api.refs['refs/heads/control']
        state = json.loads(self.store.read('control')[1]['ledger.json'])
        self.assertEqual(state['reservations']['rest-publication']['git_publication']['candidate'], candidate)
        self.assertNotIn('refs/heads/data', self.api.refs)
        self.store.push_prepared('data', candidate)
        ledger.settle('rest-publication', 0, 0, published=True, runner_seconds=0)
        final = json.loads(self.store.read('control')[1]['ledger.json'])
        self.assertNotEqual(self.api.refs['refs/heads/control'], control)
        self.assertEqual(final['reservations']['rest-publication']['status'], 'settled')
        self.assertEqual(final['git_cost']['accounted_refs']['refs/heads/data'], candidate)
        self.assertEqual(final['git_cost']['accounted_upper_bound_bytes'], measured['compressed_object_upper_bound_bytes']
                         + sum(item['charged_upper_bound_bytes'] for item in ledger.control_measurements))

    def test_failed_ref_update_preserves_remote_intent_and_precharged_bytes(self):
        ledger = Ledger(self.store, load_policy(ROOT / 'policy.json'))
        ledger.reserve('interrupted', 0, publication_only=True)
        candidate, _ = self.store.prepare('data', None, {'record': b'fixture'}, 'interrupted candidate')
        ledger.reserve_publication('interrupted', 'data', candidate, 7)
        before = json.loads(self.store.read('control')[1]['ledger.json'])
        self.api.fail_ref = GitHubApiError('fixture transport unavailable')
        with self.assertRaises(GitHubApiError):
            self.store.push_prepared('data', candidate)
        self.api.fail_ref = None
        after = json.loads(self.store.read('control')[1]['ledger.json'])
        self.assertEqual(after, before)
        self.assertEqual(after['reservations']['interrupted']['git_publication']['state'], 'reserved')
        self.assertNotIn('refs/heads/data', self.api.refs)

    def test_candidate_sha_drift_or_uploaded_object_mismatch_never_updates_ref(self):
        parent = self.api.seed({'old': b'old'})
        self.store.observe_heads()
        candidate, _ = self.store.prepare('main', parent, {'new': b'new'}, 'must retain original SHA')
        for stage in ('blobs', 'trees', 'commits'):
            with self.subTest(stage=stage):
                self.api.calls.clear()
                self.api.mutate = lambda method, route, payload: {'sha': 'f' * 40} if method == 'POST' and route == stage else None
                with self.assertRaisesRegex(GitHubApiError, 'SHA'):
                    self.store.push_prepared('main', candidate)
                self.assertEqual(self.api.refs['refs/heads/main'], parent)
                self.assertFalse(any(method == 'PATCH' or route == 'refs' for method, route, _ in self.api.calls))
        self.api.mutate = None

    def test_branch_race_is_rejected_without_force_or_ref_retry(self):
        parent = self.api.seed({'old': b'old'})
        self.store.observe_heads()
        candidate, _ = self.store.prepare('main', parent, {'new': b'new'}, 'racing candidate')
        self.api.fail_ref = GitHubApiError('fixture ref conflict', 422)
        with self.assertRaises(ParentMoved):
            self.store.push_prepared('main', candidate)
        self.assertEqual(self.api.refs['refs/heads/main'], parent)
        self.assertEqual(sum(method == 'PATCH' for method, _, _ in self.api.calls), 1)
        self.api.fail_ref = None
        moved = self.api.seed({'concurrent': b'other update'}, parent=parent)
        self.api.calls.clear()
        with self.assertRaises(ParentMoved):
            self.store.push_prepared('main', candidate)
        self.assertEqual(self.api.refs['refs/heads/main'], moved)
        self.assertFalse(any(method != 'GET' for method, _, _ in self.api.calls))

    def test_truncated_tree_wrong_blob_hash_and_outside_branch_are_rejected(self):
        self.api.seed({'record': b'good'})
        original = self.api.request
        cases = ('truncated', 'blob-hash', 'outside-branch', 'tree-hash', 'oversized-tree')
        for index, case in enumerate(cases):
            with self.subTest(case=case):
                store = GitHubApiStore(self.root / ('bad-' + str(index)), self.api.repository, api=self.api)

                def mutate(method, route, payload):
                    self.api.mutate = None
                    try:
                        response = original(method, route, payload)
                    finally:
                        self.api.mutate = mutate
                    if case == 'truncated' and route.startswith('trees/'):
                        response['truncated'] = True
                    if case == 'blob-hash' and route.startswith('blobs/'):
                        response['content'] = base64.b64encode(b'evil').decode()
                    if case == 'outside-branch' and route == 'matching-refs/heads/':
                        response[0]['ref'] = 'refs/heads/unreviewed'
                    if case == 'tree-hash' and route.startswith('trees/'):
                        response['tree'][0]['path'] = 'different-path'
                    if case == 'oversized-tree' and route.startswith('trees/'):
                        response['tree'] = [{**response['tree'][0], 'size': 2 * 1024 * 1024,
                                             'path': 'large-' + str(index)} for index in range(17)]
                    return response

                self.api.mutate = mutate
                with self.assertRaises(GitHubApiError):
                    store.observe_heads()
                self.api.mutate = None

    def test_local_import_and_upload_measure_logical_tree_bytes_without_rejecting(self):
        parent = self.api.seed({'old': b'old'})
        self.store.observe_heads()
        candidate, _ = self.store.prepare('main', parent, {'a': b'repeat', 'b': b'repeat'}, 'bounded logical tree')
        self.api.calls.clear()
        with patch('tools.github_api_store.MAX_TREE_BYTES', 10), self.assertLogs('sync.observations', level='WARNING'):
            self.assertEqual(self.store.push_prepared('main', candidate), (candidate, True))
            other = GitHubApiStore(self.root / 'bounded-import.git', self.api.repository, api=self.api)
            imported = other.import_local_snapshot(self.store.path, candidate)
        self.assertEqual(imported['logical_tree_bytes'], 12)
        self.assertEqual(self.api.refs['refs/heads/main'], candidate)

    def test_rest_roundtrip_above_old_tree_and_blob_targets_preserves_exact_snapshot(self):
        body = b'x' * (2 * 1024 * 1024 + 1)
        files = {f'records/{index}.jsonl': body for index in range(17)}
        candidate, _ = self.store.prepare('data', None, files, 'large REST snapshot')
        with self.assertLogs('sync.observations', level='WARNING'):
            self.store.push_prepared('data', candidate)
            other = GitHubApiStore(self.root / 'large-read.git', self.api.repository, api=self.api)
            read_sha, restored = other.read('data')
        self.assertEqual((read_sha, restored), (candidate, files))

    def test_github_file_limit_rejects_before_any_remote_object_creation(self):
        candidate, _ = self.store.prepare('data', None, {'large': b'123456'}, 'official limit')
        with patch('tools.github_api_store.GITHUB_MAX_BLOB_BYTES', 5):
            with self.assertRaisesRegex(GitHubApiError, 'GitHub 100 MiB'):
                self.store.push_prepared('data', candidate)
            with self.assertRaisesRegex(GitHubApiError, 'GitHub 100 MiB'):
                self.store.import_local_snapshot(self.store.path, candidate)
        self.assertFalse(any(method != 'GET' for method, _, _ in self.api.calls))

    def test_candidate_extra_headers_are_rejected_before_api_write(self):
        parent = self.api.seed({'old': b'old'})
        self.store.observe_heads()
        candidate, _ = self.store.prepare('main', parent, {'new': b'new'}, 'signed candidate')
        raw = self.store.run('cat-file', 'commit', candidate).stdout.replace(b'\n\n', b'\ngpgsig unsupported\n\n', 1)
        signed = self.store.run('hash-object', '-t', 'commit', '-w', '--stdin', data=raw).stdout.decode().strip()
        self.api.calls.clear()
        with self.assertRaisesRegex(GitHubApiError, 'unsupported headers'):
            self.store.push_prepared('main', signed)
        self.assertEqual(self.api.calls, [])


class Response(io.BytesIO):
    def __init__(self, body, headers=None):
        super().__init__(body)
        self.status, self.headers = 200, headers or {}


class RestTransportTests(unittest.TestCase):
    def test_parallel_responses_count_all_bytes_after_advisory_totals_are_exceeded(self):
        opener = type('Opener', (), {'open': lambda self, request, timeout: Response(b'{}')})()
        api = GitHubRest('argus-intel-data', 'token', opener=opener, max_wire_bytes=5)
        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = [executor.submit(api.request, 'GET', 'matching-refs/heads/') for _ in range(4)]
            failures = 0
            for future in futures:
                try:
                    future.result()
                except GitHubApiError:
                    failures += 1
        self.assertEqual(failures, 0)
        self.assertEqual(api.uploaded_bytes + api.downloaded_bytes, 8)
        self.assertTrue(api.report()['capacity_observations'][1]['exceeded'])
        expired = GitHubRest('argus-intel-data', 'token', opener=opener, max_seconds=1)
        expired.started -= 2
        self.assertEqual(expired.request('GET', 'matching-refs/heads/'), {})
        self.assertEqual(expired.requests, 1)
        self.assertTrue(expired.report()['capacity_observations'][2]['exceeded'])

    def test_credentials_remain_only_in_headers_and_errors_are_redacted(self):
        token = 'fixture-secret-token'

        class Opener:
            def open(self, request, timeout):
                self.request = request
                raise urllib.error.URLError(token + ' hidden upstream body')

        opener = Opener()
        api = GitHubRest('argus-intel-data', token, opener=opener)
        with self.assertRaises(GitHubApiError) as error:
            api.request('GET', 'matching-refs/heads/')
        self.assertNotIn(token, str(error.exception))
        self.assertNotIn(token, json.dumps(api.report()))
        self.assertNotIn(token, opener.request.full_url)
        self.assertEqual(opener.request.get_header('Authorization'), 'Bearer ' + token)

    def test_allowlist_nonforce_budgets_pagination_and_response_bounds(self):
        with self.assertRaises(ValueError):
            GitHubRest('unrelated', 'token')
        api = GitHubRest('argus-intel-data', 'token')
        for method, route, payload in [('GET', '../other', None), ('POST', 'refs', {'ref': 'refs/heads/other'}),
                                       ('PATCH', 'refs/heads/main', {'force': True})]:
            with self.subTest(route=route), self.assertRaises(ValueError):
                api.request(method, route, payload)
        for body, headers, limit in [(b'[]', {'Link': '<next>; rel="next"'}, 100),
                                     (b'0123456789', {}, 5), (b'no-json', {}, 100)]:
            with self.subTest(headers=headers, limit=limit):
                opener = type('Opener', (), {'open': lambda self, request, timeout: Response(body, headers)})()
                api = GitHubRest('argus-intel-data', 'token', opener=opener, max_wire_bytes=limit)
                with self.assertRaises(GitHubApiError):
                    api.request('GET', 'matching-refs/heads/')
        opener = type('Opener', (), {'open': lambda self, request, timeout: Response(b'[]')})()
        api = GitHubRest('argus-intel-data', 'token', opener=opener, max_requests=1)
        self.assertEqual(api.request('GET', 'matching-refs/heads/'), [])
        self.assertEqual(api.request('GET', 'matching-refs/heads/'), [])
        self.assertEqual(api.requests, 2)
        self.assertTrue(api.report()['capacity_observations'][0]['exceeded'])

    def test_single_response_safety_and_provider_rate_limits_still_fail_closed(self):
        opener = type('Opener', (), {'open': lambda self, request, timeout: Response(b'{"large":123}')})()
        api = GitHubRest('argus-intel-data', 'token', opener=opener)
        with patch('tools.github_api_store.MAX_METADATA_BYTES', 5):
            with self.assertRaisesRegex(GitHubApiError, 'per-response safety'):
                api.request('GET', 'matching-refs/heads/')
        self.assertEqual(api.downloaded_bytes, 6)
        for status in (403, 429):
            class RateLimited:
                def open(self, request, timeout):
                    raise urllib.error.HTTPError(request.full_url, status, 'rate limited', {}, io.BytesIO(b'secret'))
            api = GitHubRest('argus-intel-data', 'token', opener=RateLimited())
            with self.subTest(status=status), self.assertRaises(GitHubApiError) as error:
                api.request('GET', 'matching-refs/heads/')
            self.assertEqual(error.exception.status, status)
            self.assertEqual(api.requests, 1)
            self.assertNotIn('secret', str(error.exception))


if __name__ == '__main__':
    unittest.main()
