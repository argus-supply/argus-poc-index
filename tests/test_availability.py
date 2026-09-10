"""A11 bounded HEAD failures/recovery through real transport handlers and Git."""
import copy
import email.message
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
import urllib.request
import urllib.response
from unittest.mock import patch

from sync.adapters import AdapterResult
from sync.availability import refresh, validate_policy
from sync.core import ROOT, canonical, digest, load_policy, read_snapshot, build_snapshot
from sync.dependency import coverage_summary
from sync.gitstore import GitStore
from sync.http import BudgetExceeded, FetchError, Http, Redirects, reference_allowed
from sync.run import run

NOW = '2026-09-09T00:00:00Z'
LATER = '2026-09-10T00:00:00Z'
URL = 'https://github.com/example/poc'


def poc(number=1, url=URL):
    return {'schema_version': '1.0', 'kind': 'poc', 'source_id': 'poc-in-github',
        'native_id': str(number), 'record_id': 'poc-in-github/' + str(number),
        'status': 'active', 'title': 'Synthetic reference fixture', 'aliases': ['CVE-2026-12345'],
        'published_at': NOW, 'source_modified_at': NOW, 'first_seen_at': NOW,
        'affected': [], 'references': [{'url': url}], 'provenance': [], 'url': url,
        'availability': 'not-checked', 'verification': {'executed': False, 'status': 'unverified'}}


class ResponseHandler(urllib.request.BaseHandler):
    """Replace socket I/O only; urllib's actual HTTP error/redirect handling runs."""
    handler_order = 100

    def __init__(self, statuses):
        self.statuses, self.calls = iter(statuses), []

    def https_open(self, request):
        self.calls.append(request)
        value = next(self.statuses)
        if isinstance(value, Exception):
            raise value
        headers = email.message.Message()
        headers['Location'] = 'https://github.com/example/redirected'
        headers['Retry-After'] = '0'
        response = urllib.response.addinfourl(io.BytesIO(b''), headers, request.full_url, value)
        response.msg = 'fixture'
        return response


def transport(policy, statuses, **kwargs):
    handler = ResponseHandler(statuses)
    return Http(policy, token='never-forward-this-token',
        opener=urllib.request.build_opener(handler, Redirects()), sleep=lambda _: None, **kwargs), handler


class AvailabilityTests(unittest.TestCase):
    def setUp(self):
        self.policy = load_policy(ROOT / 'policy.json')
        self.records = {'poc-in-github/1': poc()}

    def test_strict_roots_reject_navigation_credentials_ports_and_encoded_paths(self):
        for url in ('https://github.com/orgs/argus-supply', 'https://github.com/settings/profile',
            'https://github.com/topics/security', 'https://github.com/example/poc/tree/main',
            'https://user:password@github.com/example/poc', 'https://github.com:443/example/poc',
            'https://github.com/example/%2e%2e', 'https://github.com/example/../poc',
            'https://github.com/example/poc?x=1', 'https://github.com/example/poc#readme',
            'http://github.com/example/poc', 'https://evil.test/example/poc',
            'https://www.exploit-db.com/exploits/1/download', 'https://github.com/example/poc\n'):
            with self.subTest(url=url), self.assertRaises(FetchError):
                reference_allowed(url)
        self.assertEqual(reference_allowed(URL), URL)
        self.assertEqual(reference_allowed('https://www.exploit-db.com/exploits/12345'),
                         'https://www.exploit-db.com/exploits/12345')

    def test_actual_opener_refuses_redirects_and_never_forwards_token_or_gets_content(self):
        for status in (302, 307, 405, 200):
            http, handler = transport(self.policy, [status])
            state, metrics = refresh(self.records, None, http, NOW, self.policy)
            check = next(iter(state['entries'].values()))
            self.assertEqual(check['availability'], 'available' if status == 200 else 'unknown')
            self.assertEqual(metrics['requests'], 1)
            self.assertEqual(len(handler.calls), 1)
            self.assertEqual(handler.calls[0].get_method(), 'HEAD')
            self.assertNotIn('Authorization', handler.calls[0].headers)
            self.assertNotIn('Cookie', handler.calls[0].headers)
            self.assertEqual(http.bytes, 0)

    def test_404_persists_rechecks_after_24h_and_unchanged_poll_is_identical(self):
        original = copy.deepcopy(self.records)
        http, _ = transport(self.policy, [404])
        state, _ = refresh(self.records, None, http, NOW, self.policy)
        saved = json.loads(canonical(state))
        client, handler = transport(self.policy, [])
        same, metrics = refresh(self.records, saved, client, '2026-09-09T06:00:00Z', self.policy)
        self.assertEqual(canonical(same), canonical(state))
        self.assertEqual(metrics['requests'], 0)
        self.assertFalse(handler.calls)
        recovered, metrics = refresh(self.records, saved, transport(self.policy, [200])[0], LATER, self.policy)
        self.assertEqual(next(iter(state['entries'].values()))['availability'], 'temporarily-unavailable')
        self.assertEqual(next(iter(recovered['entries'].values()))['availability'], 'available')
        self.assertEqual(metrics['observed'], 1)
        self.assertEqual(self.records, original)

    def test_shared_fixture_is_generated_by_real_bounded_checker(self):
        fixture = json.loads((ROOT / 'fixtures/reference-availability.json').read_text())
        row = fixture['record']
        checkpoint, _ = refresh({row['record_id']: row}, None, transport(self.policy, [404])[0], NOW, self.policy)
        self.assertEqual(checkpoint, fixture['checkpoint'])

    def test_timeout_retry_uses_four_request_background_batch_and_resumes_due_state(self):
        first, _ = refresh(self.records, None, transport(self.policy, [404])[0], NOW, self.policy)
        disabled = {**self.policy, 'reference_probe_requests': 0}
        exhausted, _ = transport(disabled, [], max_requests=0)
        same, metrics = refresh(self.records, first, exhausted, LATER, disabled)
        self.assertEqual(first, same)
        self.assertTrue(metrics['deferred_by_batch'])
        self.assertEqual(metrics['pending_or_due'], 1)
        records = {str(i): poc(i, f'https://github.com/example/poc{i}') for i in range(8)}
        http, _ = transport(self.policy, [TimeoutError('private detail')] * 4)
        state, metrics = refresh(records, None, http, NOW, self.policy)
        self.assertEqual(http.requests, 4)
        self.assertEqual(metrics['observed'], 2)
        self.assertEqual(metrics['pending_or_due'], 6)
        self.assertNotIn('private detail', canonical(state).decode())
        self.assertEqual(metrics['coverage'], 'partial')
        self.assertTrue(metrics['deferred_by_batch'])

    def test_cursor_resumes_and_checkpoint_is_bounded_without_claiming_full_coverage(self):
        records = {str(i): poc(i, f'https://github.com/example/poc{i}') for i in range(20)}
        policy = {**self.policy, 'reference_probe_entries': 3}
        first, metrics = refresh(records, None, transport(policy, [200] * 4)[0], NOW, policy)
        second, _ = refresh(records, json.loads(canonical(first)), transport(policy, [200] * 4)[0], NOW, policy)
        self.assertNotEqual(first['cursor'], second['cursor'])
        self.assertLessEqual(len(second['entries']), 3)
        self.assertLessEqual(len(canonical(second)), policy['reference_probe_state_bytes'])
        self.assertEqual(metrics['pending_or_due'], 17)
        self.assertEqual(metrics['coverage'], 'partial')
        tiny = {**self.policy, 'reference_probe_state_bytes': 1024}
        state, _ = refresh(records, None, transport(tiny, [200] * 4)[0], NOW, tiny)
        self.assertLessEqual(len(canonical(state)), 1024)

    def test_changed_url_invalidates_previous_check_and_unsupported_is_explicit(self):
        first, _ = refresh(self.records, None, transport(self.policy, [200])[0], NOW, self.policy)
        self.records['poc-in-github/1']['url'] = 'https://vendor.example/advisory'
        state, metrics = refresh(self.records, first, transport(self.policy, [])[0], NOW, self.policy)
        self.assertFalse(state['entries'])
        self.assertEqual(metrics['unsupported_count'], 1)
        self.assertEqual(metrics['coverage'], 'partial')

    def test_reference_safety_settings_remain_bounded_and_manifest_target_only_warns(self):
        for key, value in {'reference_probe_requests': 5, 'reference_probe_retries': 2,
            'reference_probe_timeout_seconds': 11, 'reference_probe_bytes': 65537,
            'reference_probe_entries': 257, 'reference_probe_state_bytes': 65537,
            'reference_recheck_hours': 23}.items():
            with self.subTest(key=key), self.assertRaises(ValueError):
                validate_policy({**self.policy, key: value})
        with self.assertLogs('sync.observations', level='WARNING'):
            files, _ = build_snapshot('argus-supply/argus-poc-index', {}, {}, {}, self.policy, NOW, 'fixture',
                                     extra={'other_bounded_source_state': 'x' * 524288})
        self.assertGreater(len(files['manifest.json']), 524288)
        self.assertEqual(read_snapshot(files)[3]['other_bounded_source_state'], 'x' * 524288)

    def test_fresh_git_runners_keep_facts_while_reference_batch_pauses_and_recovers(self):
        def collect(source, *_args, **_kwargs):
            return AdapterResult(records=[poc()] if source == 'poc-in-github' else [],
                status='ok', revision='a' * 40, completed_watermark='source-progress')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            remote = root / 'remote.git'
            subprocess.run(['git', 'init', '--bare', str(remote)], check=True, capture_output=True)
            dependency = {'repository': 'argus-supply/argus-intel-data', 'commit_sha': 'a' * 40,
                          'manifest_sha256': 'b' * 64, 'records': [],
                          **coverage_summary({'sources': {source: {'status': 'ok', 'completed_watermark': NOW}
                              for source in ('cve', 'ghsa', 'kev')}})}
            snapshots = []
            for number, (stamp, statuses, limit) in enumerate([
                (NOW, [404], 500), ('2026-09-09T06:00:00Z', [], 500),
                (LATER, [], 0), (LATER, [200], 500)]):
                http, _ = transport(self.policy, statuses, max_requests=limit)
                policy = {**self.policy, 'reference_probe_requests': 0} if number == 2 else self.policy
                with patch('sync.run.collect', side_effect=collect), patch('sync.run.consume_intel',
                    return_value=(dependency, {}, {})), patch('sync.run.utcnow', return_value=stamp):
                    result = run('argus-poc-index', str(remote), root / f'runner-{number}',
                        f'job-{number}', policy=policy, http=http)
                self.assertEqual(result['status'], 'ok', result)
                _, files = GitStore(root / f'consumer-{number}', str(remote)).read('data')
                snapshots.append(read_snapshot(files))
                self.assertTrue(all(state['completed_watermark'] == 'source-progress' for state in snapshots[-1][2].values()))
                _, control = GitStore(root / f'control-{number}', str(remote)).read('control')
                self.assertIn('health.json', control)
                if number == 1:
                    self.assertFalse(result['published'])
                if number == 2:
                    self.assertTrue(result['reference_availability']['deferred_by_batch'])
            self.assertEqual([snapshot[0] for snapshot in snapshots], [snapshots[0][0]] * 4)
            self.assertEqual([snapshot[1] for snapshot in snapshots], [snapshots[0][1]] * 4)
            checks = [next(iter(snapshot[3]['reference_availability']['entries'].values()))['availability']
                      for snapshot in snapshots]
            self.assertEqual(checks, ['temporarily-unavailable'] * 3 + ['available'])


if __name__ == '__main__':
    unittest.main()
