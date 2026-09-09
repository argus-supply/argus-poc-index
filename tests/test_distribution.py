"""Standalone drift checks and complete adapter-to-real-Git runner fixtures."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import urlsplit

from sync.core import ROOT, canonical, load_policy, read_snapshot, apply_result, build_snapshot
from sync.adapters import AdapterResult
from sync.dependency import consume_intel
from sync.gitstore import GitStore
from sync.http import Http
from sync.run import run


def module(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'tools' / (name + '.py'))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


class DistributionTests(unittest.TestCase):
    def test_generated_copy_is_pinned_and_drift_fails(self):
        if not (ROOT / 'tools/distribute.py').exists():
            # In a distribution, verify its actual pinned copy with the shipped checker.
            module('check_distribution').check(ROOT)
            return
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            module('distribute').generate(target, 'argus-intel-data', 'a' * 40)
            module('check_distribution').check(target)
            with (target / 'sync/core.py').open('a') as stream:
                stream.write('\n# unexpected local edit\n')
            with self.assertRaisesRegex(ValueError, 'drift'):
                module('check_distribution').check(target)


class FixtureHttp(Http):
    """Only the external HTTP transport is substituted; adapters and Git are real."""
    def __init__(self, policy, revision='a' * 40, rejected=False):
        super().__init__(policy)
        self.revision, self.rejected = revision, rejected

    def fork(self, **kwargs):
        return self

    def get_json(self, url, headers=None):
        self._before()
        if '/commits/' in url:
            result = {'sha': self.revision}
        elif url.endswith('/cves/deltaLog.json'):
            result = [{'fetchTime': '2026-09-09T00:00:00Z', 'new': [{'cveId': 'CVE-2026-12345'}], 'updated': []},
                      {'fetchTime': '2026-08-01T00:00:00Z', 'new': [], 'updated': []}]
        elif url.endswith('/CVE-2026-12345.json'):
            result = {'dataType': 'CVE_RECORD', 'dataVersion': '5.1',
                'cveMetadata': {'cveId': 'CVE-2026-12345', 'state': 'REJECTED' if self.rejected else 'PUBLISHED',
                    'datePublished': '2026-09-08T00:00:00Z', 'dateUpdated': '2026-09-09T00:00:00Z'},
                'containers': {'cna': {'title': 'Synthetic configuration advisory',
                    'providerMetadata': {'orgId': 'fixture'}, 'affected': [{'product': 'fixture-service',
                        'vendor': 'fixture', 'versions': [{'version': '1.0.0', 'status': 'affected'}]}]}}}
        elif '/advisories' in url:
            row = {'ghsa_id': 'GHSA-2345-6789-cfgh', 'type': 'reviewed', 'identifiers': [],
                'summary': 'Synthetic GHSA-only advisory', 'published_at': '2026-09-08T00:00:00Z',
                'updated_at': '2026-09-09T00:00:00Z', 'html_url': 'https://github.com/advisories/GHSA-2345-6789-cfgh',
                'references': [], 'vulnerabilities': []}
            result = row if '/advisories/GHSA-' in url else [row]
        elif url.endswith('/known_exploited_vulnerabilities.json'):
            result = {'count': 1, 'vulnerabilities': [{'cveID': 'CVE-2001-1234',
                'dateAdded': '2026-09-08', 'vulnerabilityName': 'Synthetic old advisory',
                'vendorProject': 'fixture', 'product': 'service'}]}
        else:
            raise AssertionError('unexpected fixture request: ' + urlsplit(url).path)
        self._charge(len(canonical(result)))
        return result


class RunnerTests(unittest.TestCase):
    def test_settlement_failure_keeps_data_evidence_and_durable_precharge(self):
        policy = load_policy(ROOT / 'policy.json')
        policy['bootstrap_days'] = policy['retention_days']
        with tempfile.TemporaryDirectory() as directory, patch('sync.run.utcnow', return_value='2026-09-09T00:00:00Z'):
            root = Path(directory)
            remote = root / 'remote.git'
            subprocess.run(['git', 'init', '--bare', str(remote)], check=True, capture_output=True)
            with patch('sync.run.Ledger.settle', side_effect=RuntimeError('settlement failed')):
                result = run('argus-intel-data', str(remote), root / 'runner', 'one', policy=policy, http=FixtureHttp(policy))
            self.assertTrue(result['published'])
            self.assertEqual(result['status'], 'partial')
            self.assertTrue(result['reservation_retained'])
            self.assertEqual(result['settlement_error'], 'RuntimeError')

    def test_a01_a05_a08_adapters_publish_restart_and_keep_ghsa_and_old_kev(self):
        policy = load_policy(ROOT / 'policy.json')
        policy['bootstrap_days'] = policy['retention_days']
        with tempfile.TemporaryDirectory() as directory, patch('sync.run.utcnow', return_value='2026-09-09T00:00:00Z'):
            root = Path(directory)
            remote = root / 'remote.git'
            subprocess.run(['git', 'init', '--bare', str(remote)], check=True, capture_output=True)
            first = run('argus-intel-data', str(remote), root / 'runner-1', 'one', policy=policy, http=FixtureHttp(policy))
            self.assertEqual(first['status'], 'ok', first)
            with patch('sync.run.utcnow', return_value='2026-09-09T02:00:00Z'):
                second = run('argus-intel-data', str(remote), root / 'runner-2', 'two', policy=policy, http=FixtureHttp(policy))
            self.assertEqual(second['status'], 'ok', second)
            self.assertEqual(second['data_commit'], first['data_commit'])
            self.assertFalse(second['published'])
            _, control = GitStore(root / 'health', str(remote)).read('control')
            self.assertEqual(json.loads(control['health.json'])['sources']['ghsa']['last_success_at'],
                             '2026-09-09T02:00:00Z')
            _, files = GitStore(root / 'consumer', str(remote)).read('data')
            records, events, _, _ = read_snapshot(files)
            self.assertEqual(len(records), 3)
            self.assertTrue(records['kev/CVE-2001-1234']['kev'])
            self.assertEqual(records['ghsa/GHSA-2345-6789-cfgh']['aliases'], ['GHSA-2345-6789-cfgh'])
            self.assertEqual({event['event_type'] for event in events.values()}, {'disclosure', 'kev_added'})


class DependencyTests(unittest.TestCase):
    def test_continuations_restore_references_and_unchanged_intel_only_resolves_head(self):
        policy = load_policy(ROOT / 'policy.json')
        row = json.loads((ROOT / 'fixtures/source-records.json').read_text())[0]
        row['affected'] = [{'original_ranges': 'range' * 9000}]
        records, events, sources = {}, {}, {}
        apply_result(records, events, sources, 'ghsa', AdapterResult(records=[row], status='ok'),
                     '2026-09-09T00:00:00Z', policy)
        files, manifest = build_snapshot('argus-supply/argus-intel-data', records, events, sources,
            policy, '2026-09-09T00:00:00Z', 'fixture')
        calls = []
        class Remote:
            def get_json(self, url):
                calls.append(url)
                return {'object': {'sha': 'a' * 40}}

            def get_bytes(self, url):
                calls.append(url)
                path = url.split('/' + 'a' * 40 + '/', 1)[1]
                if path.startswith('events/'):
                    raise AssertionError('PoC discovery must not download event history')
                return files[path]
        first, cache, cached_files = consume_intel(Remote(), None, None, {})
        self.assertEqual(first['records'][0]['references'], row['references'])
        count = len(calls)
        second, next_cache, _ = consume_intel(Remote(), None, {'dependency_cache': cache}, cached_files)
        self.assertEqual(second, first)
        self.assertEqual(next_cache, cache)
        self.assertEqual(len(calls) - count, 1)


if __name__ == '__main__':
    unittest.main()
