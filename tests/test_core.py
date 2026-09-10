"""Determinism, semantic transitions, failure recovery and actual Git CAS tests."""
import copy
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
import urllib.error
from unittest.mock import patch

from sync.adapters import AdapterResult
from sync.core import (ROOT, apply_result, build_snapshot, canonical, digest,
    event_types, load_policy, read_snapshot, shard_rows)
from sync.gitstore import GitStore, Ledger, ParentMoved
from sync.http import BudgetExceeded, FetchError, Http, Redirects

NOW = '2026-09-09T00:00:00Z'


class CoreTests(unittest.TestCase):
    def setUp(self):
        self.policy = load_policy(ROOT / 'policy.json')
        self.row = json.loads((ROOT / 'fixtures/source-records.json').read_text())[0]
        self.records, self.events, self.sources = {}, {}, {}

    def apply(self, row=None, **kwargs):
        result = AdapterResult(records=[row or self.row], status='ok', revision='a' * 40, **kwargs)
        apply_result(self.records, self.events, self.sources, 'ghsa', result, NOW, self.policy)

    def snapshot(self, previous=None, now=NOW):
        return build_snapshot('argus-supply/argus-intel-data', self.records, self.events,
            self.sources, self.policy, now, 'test', previous)

    def test_proven_reactivation_in_bootstrap_is_not_a_withdrawal(self):
        row = copy.deepcopy(self.row)
        row['status'] = 'active'
        row['published_at'] = '2020-01-01T00:00:00Z'
        row['bootstrap_material_change'] = {'baseline_revision': 'b' * 40,
            'window_start': '2026-09-01T00:00:00Z', 'window_end': NOW,
            'changed_fields': ['status'], 'before_status': 'rejected',
            'timing': 'observed-state-difference-within-interval'}
        self.apply(row)
        event = next(iter(self.events.values()))
        self.assertEqual(event['event_type'], 'disclosure')
        self.assertIsNone(event['source_occurred_at'])
        self.assertEqual(event['source_occurrence_window']['from'], '2026-09-01T00:00:00Z')
        self.assertEqual(self.records[row['record_id']]['published_at'], '2020-01-01T00:00:00Z')

    def test_a01_same_input_preserves_records_events_and_same_day_manifest(self):
        self.apply()
        first, manifest = self.snapshot()
        self.apply()
        second, _ = self.snapshot(manifest, '2026-09-09T02:00:00Z')
        self.assertEqual(first, second)
        self.assertEqual(len(self.events), 1)

    def test_a01_upstream_poll_revision_does_not_rewrite_unchanged_facts(self):
        self.apply()
        original = copy.deepcopy(self.records)
        row = copy.deepcopy(self.row)
        row['provenance'][0]['revision'] = 'b' * 40
        row['source_modified_at'] = '2026-09-09T01:00:00Z'
        self.apply(row)
        self.assertEqual(original, self.records)

    def test_a02_failed_page_keeps_watermark_and_completed_units(self):
        self.apply(completed_watermark='old')
        result = AdapterResult(records=[dict(self.row, title='Corrected')], status='partial',
            revision='b' * 40, completed_watermark='old', continuation={'page': 2},
            coverage_gaps=['page 2 failed'])
        apply_result(self.records, self.events, self.sources, 'ghsa', result, NOW, self.policy)
        self.assertEqual(self.sources['ghsa']['completed_watermark'], 'old')
        self.assertEqual(self.sources['ghsa']['continuation'], {'page': 2})
        self.assertEqual(self.records[self.row['record_id']]['title'], 'Corrected')

    def test_a04_withdrawal_and_retention_expiry_are_distinct(self):
        self.apply()
        self.apply(dict(self.row, status='withdrawn'))
        self.assertIn('withdrawn', {e['event_type'] for e in self.events.values()})
        _, manifest = self.snapshot(now='2026-10-11T00:00:00Z')
        self.assertFalse(self.records)
        self.assertEqual({e['event_type'] for e in self.events.values()}, {'retention_removed'})
        self.assertEqual(manifest['retention']['event_days'], 30)

    def test_a04_partial_inventory_cannot_delete_and_complete_inventory_leaves_tombstone(self):
        self.apply()
        for status in ('partial', 'ok'):
            result = AdapterResult(status=status, authoritative_ids=[], revision='b' * 40)
            apply_result(self.records, self.events, self.sources, 'ghsa', result, NOW, self.policy)
            self.assertEqual(self.records[self.row['record_id']]['status'],
                             'active' if status == 'partial' else 'source_deleted')

    def test_a05_alias_does_not_merge_cna_and_ghsa_records(self):
        self.apply()
        other = dict(self.row, source_id='cve', record_id='cve/CVE-2026-12345', native_id='CVE-2026-12345')
        apply_result(self.records, self.events, self.sources, 'cve',
            AdapterResult(records=[other], status='ok'), NOW, self.policy)
        self.assertEqual(len(self.records), 2)

    def test_a06_classifier_and_format_changes_do_not_emit_disclosure(self):
        self.apply()
        row = copy.deepcopy(self.row)
        row['assessment'] = {'classifier_version': 'next', 'relevance': 'high'}
        self.apply(row)
        self.assertEqual(len(self.events), 1)
        self.apply(dict(self.row, affected=[{'original_ranges': '<2.0.0'}]))
        self.assertIn('affected_corrected', {e['event_type'] for e in self.events.values()})

    def test_a06_scoring_changes_are_not_disclosures(self):
        self.assertEqual(event_types(self.row, dict(self.row, metrics={'score': 9.8})), ['score_changed'])

    def test_a07_oversize_record_retains_old_watermark_and_range(self):
        self.apply(completed_watermark='old')
        row = dict(self.row, affected=[{'original_ranges': 'x' * 300000}])
        self.apply(row, completed_watermark='new')
        state = self.sources['ghsa']
        self.assertEqual(state['status'], 'partial')
        self.assertEqual(state['completed_watermark'], 'old')
        self.assertTrue(state['coverage_gaps'])
        self.assertEqual(self.records[self.row['record_id']]['affected'], self.row['affected'])

    def test_a07_schema_rejection_cannot_advance_watermark(self):
        self.apply(completed_watermark='old')
        self.apply(dict(self.row, affected='invalid'), completed_watermark='new')
        self.assertEqual(self.sources['ghsa']['completed_watermark'], 'old')

    def test_a07_tree_target_warns_without_losing_records(self):
        self.apply()
        self.policy['max_tree_bytes'] = 1
        with self.assertLogs('sync.observations', level='WARNING') as logs:
            files, _ = self.snapshot()
        self.assertTrue(any('current_tree_bytes' in line for line in logs.output))
        self.assertEqual(read_snapshot(files)[0], self.records)

    def test_a07_logical_snapshot_target_warns_without_losing_records(self):
        self.apply()
        with patch('sync.core.MAX_SNAPSHOT_LOGICAL_BYTES', 1), self.assertLogs(
                'sync.observations', level='WARNING') as logs:
            files, _ = self.snapshot()
        self.assertTrue(any('snapshot_logical_bytes' in line for line in logs.output))
        self.assertEqual(read_snapshot(files)[0], self.records)

    def test_a07_source_state_target_preserves_completed_checkpoint(self):
        self.policy['max_source_state_bytes'] = 1
        with self.assertLogs('sync.observations', level='WARNING'):
            self.apply(completed_watermark=NOW, state={'retained': 'full source state'})
        self.assertEqual(self.sources['ghsa']['completed_watermark'], NOW)
        self.assertEqual(self.sources['ghsa']['retained'], 'full source state')
        self.assertEqual(self.sources['ghsa']['status'], 'ok')

    def test_shard_target_below_one_record_keeps_that_record(self):
        with self.assertLogs('sync.observations', level='WARNING'):
            shards = shard_rows([self.row], 'records', {**self.policy, 'max_shard_bytes': 1})
        self.assertEqual(list(shards.values()), [canonical(self.row)])

    def test_a07_shards_split_stably_and_have_exact_hashes(self):
        rows = [dict(self.row, record_id=f'ghsa/{i}') for i in range(100)]
        small = {**self.policy, 'max_shard_bytes': 1600}
        shards = shard_rows(rows, 'records', small)
        self.assertEqual(shards, shard_rows(list(reversed(rows)), 'records', small))
        self.assertTrue(all(len(data) <= 1600 for data in shards.values()))
        self.apply()
        files, _ = self.snapshot()
        parsed, _, _, _ = read_snapshot(files)
        self.assertEqual(parsed, self.records)
        path = next(p for p in files if p.startswith('records/'))
        files[path] += b' '
        with self.assertRaisesRegex(ValueError, 'checksum'):
            read_snapshot(files)

    def test_project_targets_are_configurable_but_protocol_bounds_remain(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'policy.json'
            path.write_bytes(canonical({**self.policy, 'daily_bytes': 10485761}))
            self.assertEqual(load_policy(path)['daily_bytes'], 10485761)
            path.write_bytes(canonical({**self.policy, 'daily_bytes': 0}))
            with self.assertRaisesRegex(ValueError, 'threshold'):
                load_policy(path)
            path.write_bytes(canonical({**self.policy, 'max_record_bytes': 16385}))
            with self.assertRaisesRegex(ValueError, 'protocol ceiling'):
                load_policy(path)


class Response(io.BytesIO):
    headers = {}


class Opener:
    def __init__(self, values):
        self.values = iter(values)

    def open(self, request, timeout):
        value = next(self.values)
        if isinstance(value, Exception):
            raise value
        return Response(value)


class HttpTests(unittest.TestCase):
    def setUp(self):
        self.policy = load_policy(ROOT / 'policy.json')

    def test_a03_429_and_503_retry_bodies_are_counted(self):
        values = [urllib.error.HTTPError('https://api.github.com/x', status, 'failure',
            {'Retry-After': '0'}, io.BytesIO(b'bad')) for status in (429, 503)] + [b'{}']
        client = Http(self.policy, opener=Opener(values), sleep=lambda _: None)
        self.assertEqual(client.get_json('https://api.github.com/x'), {})
        self.assertEqual((client.requests, client.bytes), (3, 8))

    def test_a03_timeout_retries_are_bounded_and_redacted(self):
        client = Http(self.policy, opener=Opener([TimeoutError('secret')] * 3), sleep=lambda _: None)
        with self.assertRaisesRegex(FetchError, 'retries exhausted'):
            client.get_json('https://api.github.com/x')
        self.assertEqual(client.requests, 3)

    def test_project_transfer_targets_warn_without_truncating_source_data(self):
        client = Http(self.policy, max_bytes=5, opener=Opener([b'123456789']))
        child = client.fork(max_bytes=3, max_requests=2)
        self.assertEqual(child.get_bytes('https://api.github.com/x'), b'123456789')
        self.assertEqual((child.bytes, client.bytes), (9, 9))
        observation = {item['metric']: item for item in client.capacity_observations}
        self.assertEqual(observation['http_job_bytes'], {
            'metric': 'http_job_bytes', 'observed': 9, 'threshold': 5,
            'exceeded': True, 'enforcement': 'advisory'})

    def test_a14_arbitrary_origins_and_redirects_are_rejected(self):
        client = Http(self.policy)
        for url in ('http://api.github.com/x', 'https://localhost/x', 'https://a:b@api.github.com/x'):
            with self.subTest(url=url), self.assertRaises(FetchError):
                client.get_bytes(url)
        import urllib.request
        request = urllib.request.Request('https://api.github.com/x')
        with self.assertRaises(FetchError):
            Redirects().redirect_request(request, None, 302, '', {}, 'https://raw.githubusercontent.com/x')


class GitTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.remote = self.root / 'remote.git'
        subprocess.run(['git', 'init', '--bare', str(self.remote)], check=True, capture_output=True)
        self.one = GitStore(self.root / 'one', str(self.remote))
        self.two = GitStore(self.root / 'two', str(self.remote))
        self.policy = load_policy(ROOT / 'policy.json')

    def test_git_store_disables_background_object_maintenance(self):
        self.assertEqual(self.one.run('config', '--get', 'gc.auto').stdout.strip(), b'0')
        self.assertEqual(self.one.run('config', '--get', 'maintenance.auto').stdout.strip(), b'false')

    def test_a08_concurrent_parent_is_rejected_and_retry_converges(self):
        sha, _ = self.one.publish('data', None, {'manifest.json': b'old\n'}, 'initial')
        parent, _ = self.two.read('data')
        changed, _ = self.one.publish('data', sha, {'manifest.json': b'new\n'}, 'change')
        with self.assertRaises(ParentMoved):
            self.two.publish('data', parent, {'manifest.json': b'raced\n'}, 'race')
        parent, files = self.two.read('data')
        self.assertEqual(files, {'manifest.json': b'new\n'})
        same, published = self.two.publish('data', parent, files, 'retry after publish crash')
        self.assertEqual(same, changed)
        self.assertFalse(published)

    def test_a08_before_publish_crash_keeps_old_snapshot(self):
        sha, _ = self.one.publish('data', None, {'manifest.json': b'old'}, 'initial')
        self.one.run('hash-object', '-w', '--stdin', data=b'unpublished')
        observed, files = self.two.read('data')
        self.assertEqual((sha, files['manifest.json']), (observed, b'old'))

    def test_a03_reservation_survives_fresh_runner_and_crash(self):
        policy = {**self.policy, 'daily_bytes': 10}
        first = Ledger(self.one, policy, '2026-09-09')
        self.assertEqual(first.reserve('killed', 8), 8)
        fresh = Ledger(self.two, policy, '2026-09-09')
        with self.assertLogs('sync.observations', level='WARNING'):
            self.assertEqual(fresh.reserve('next', 8), 8)
            self.assertEqual(fresh.reserve('third', 8), 8)
        fresh.settle('next', 1, 1)
        self.assertEqual(first.reserve('fourth', 8), 8)
        state = first.read()[1]
        self.assertEqual(state['reservations']['killed']['charged_bytes'], 8)
        self.assertEqual(state['reservations']['next']['charged_bytes'], 1)
        self.assertEqual(Ledger(self.two, policy, '2026-09-10').reserve('newday', 8), 8)

    def test_a16_history_target_warns_and_allows_publication(self):
        ledger = Ledger(self.one, self.policy)
        ledger.reserve('test', 100)
        with self.assertLogs('sync.observations', level='WARNING'):
            self.assertTrue(ledger.publication_allowed(self.policy['history_bytes']))

    def test_git_snapshot_above_old_tree_and_blob_targets_roundtrips(self):
        body = b'lossless capacity fixture\n' * (1400000)
        self.assertGreater(len(body), 32 * 1024 * 1024)
        sha, _ = self.one.publish('data', None, {'records/large.jsonl': body}, 'large snapshot')
        with self.assertLogs('sync.observations', level='WARNING') as logs:
            observed, files = self.two.read('data')
        self.assertEqual((observed, files), (sha, {'records/large.jsonl': body}))
        self.assertTrue(any('published_tree_bytes' in line for line in logs.output))


if __name__ == '__main__':
    unittest.main()
