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

from sync.core import ROOT, canonical, digest, load_policy, read_snapshot, apply_result, build_snapshot
from sync.adapters import AdapterResult
from sync.dependency import consume_intel
from sync.gitstore import GitStore, Ledger
from sync.http import BudgetExceeded, Http
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
    def test_partial_git_baseline_does_not_regrant_http_initialization_budget(self):
        policy = load_policy(ROOT / 'policy.json')
        states = {source: {'completed_watermark': '2026-09-09T00:00:00Z', 'status': 'partial'}
                  for source in ('cve', 'ghsa', 'kev')}
        with tempfile.TemporaryDirectory() as directory, patch('sync.run.GitStore.read', return_value=('a' * 40, {})), \
                patch('sync.run.read_snapshot', return_value=({}, {}, states, {'created_at': '2026-09-09T00:00:00Z'})), \
                patch('sync.run.Ledger.initializing', return_value=True), \
                patch('sync.run.Ledger.reserve', side_effect=BudgetExceeded('probe')) as reserve:
            result = run('argus-intel-data', str(Path(directory) / 'remote.git'), Path(directory) / 'runner',
                         'phase', policy=policy)
        self.assertTrue(result['git_initialization'])
        self.assertFalse(result['bootstrap'])
        self.assertFalse(reserve.call_args.kwargs['bootstrap'])

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
    def intel_files(self, overrides=None):
        policy = load_policy(ROOT / 'policy.json')
        sources = {name: {'status': 'ok', 'completed_watermark': '2026-09-09T00:00:00Z',
            'continuation': None, 'coverage_gaps': [], 'errors': []} for name in ('cve', 'ghsa', 'kev')}
        for name, changes in (overrides or {}).items():
            if changes is None:
                sources.pop(name)
            else:
                sources[name].update(changes)
        return build_snapshot('argus-supply/argus-intel-data', {}, {}, sources,
            policy, '2026-09-09T00:00:00Z', 'fixture')[0]

    def test_dependency_coverage_requires_every_fixed_source_watermark_and_no_gaps(self):
        for override in ({}, {'cve': {'status': 'partial'}}, {'ghsa': {'completed_watermark': None}},
                         {'kev': {'continuation': {'offset': 1}}}, {'cve': {'coverage_gaps': ['missing']}},
                         {'ghsa': {'errors': ['failed']}}, {'kev': None}):
            with self.subTest(override=override):
                files = self.intel_files(override)
                class Remote:
                    def get_bytes(self, url):
                        return files['manifest.json']
                dependency, cache, _ = consume_intel(Remote(), 'a' * 40, None, {})
                self.assertEqual(dependency['coverage_complete'], not bool(override))
                self.assertEqual(cache['coverage_complete'], not bool(override))
                self.assertEqual(set(dependency['required_sources']), {'cve', 'ghsa', 'kev'})
                self.assertEqual(dependency['manifest_sha256'], digest(files['manifest.json']))
                self.assertEqual(bool(dependency['coverage_errors']), bool(override))

    def test_old_dependency_cache_upgrades_exact_sha_with_one_manifest_fetch_then_reuses(self):
        files = self.intel_files({'cve': {'status': 'partial', 'completed_watermark': None}})
        old = {'repository': 'argus-supply/argus-intel-data', 'commit_sha': 'a' * 40,
            'manifest_sha256': digest(files['manifest.json']), 'shards': []}
        original = copy.deepcopy(old)
        calls = []
        class Remote:
            def get_json(self, url):
                raise AssertionError('legacy coverage must not borrow a newer head')

            def get_bytes(self, url):
                calls.append(url)
                self_expected = 'https://raw.githubusercontent.com/argus-supply/argus-intel-data/' + 'a' * 40 + '/manifest.json'
                if url != self_expected:
                    raise AssertionError('not the cached immutable SHA')
                return files['manifest.json']
        dependency, upgraded, projections = consume_intel(Remote(), None, {'dependency_cache': old}, {})
        self.assertEqual(len(calls), 1)
        self.assertEqual(old, original)
        self.assertFalse(dependency['coverage_complete'])
        self.assertEqual(dependency['commit_sha'], old['commit_sha'])
        repeated, _, _ = consume_intel(Remote(), 'a' * 40, {'dependency_cache': upgraded}, projections)
        self.assertEqual(repeated, dependency)
        self.assertEqual(len(calls), 1)

    def test_old_dependency_cache_rejects_manifest_hash_or_repository_mismatch(self):
        good = self.intel_files()
        for body in (good['manifest.json'] + b' ', canonical({**json.loads(good['manifest.json']), 'repository': 'wrong/repo'})):
            with self.subTest(body_length=len(body)):
                old = {'repository': 'argus-supply/argus-intel-data', 'commit_sha': 'a' * 40,
                    'manifest_sha256': digest(good['manifest.json']), 'shards': []}
                class Remote:
                    def get_bytes(self, url):
                        return body
                with self.assertRaisesRegex(ValueError, 'manifest.*mismatch'):
                    consume_intel(Remote(), None, {'dependency_cache': old}, {})

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


class PocDependencyHttp(Http):
    """Only public HTTP is substituted; dependency, adapters, Git and ledger are real."""
    def __init__(self, policy, files, sha='a' * 40):
        super().__init__(policy)
        self.files, self.sha = files, sha
        self.urls = []

    def fork(self, **kwargs):
        return self

    def get_json(self, url, headers=None):
        self._before()
        self.urls.append(url)
        if url.endswith('/git/ref/heads/data'):
            result = {'object': {'sha': self.sha}}
        elif 'gitlab.com' in url and '/repository/commits?' in url:
            result = [{'id': 'b' * 40}]
        elif '/commits/HEAD' in url:
            result = {'sha': 'c' * 40}
        else:
            raise AssertionError('unexpected fixture JSON URL: ' + url)
        self._charge(len(canonical(result)))
        return result

    def get_bytes(self, url, headers=None):
        self._before()
        self.urls.append(url)
        if url.endswith('/manifest.json'):
            if '/' + self.sha + '/' not in url:
                raise AssertionError('dependency SHA changed')
            result = self.files['manifest.json']
        elif 'files_exploits.csv/raw?' in url:
            result = b'id,description,codes,date_published\n'
        else:
            raise AssertionError('unexpected fixture bytes URL: ' + url)
        self._charge(len(result))
        return result


class PocDependencyRunnerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='argus-poc-dependency-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.remote = self.root / 'remote.git'
        subprocess.run(['git', 'init', '--bare', '-q', str(self.remote)], check=True, capture_output=True)
        self.policy = load_policy(ROOT / 'policy.json')
        self.now = '2026-09-09T00:00:00Z'

    def run_with_dependency(self, complete, job):
        files = DependencyTests().intel_files({} if complete else {'cve': {'status': 'partial', 'completed_watermark': None}})
        with patch('sync.run.utcnow', return_value=self.now), patch('sync.ledger.utcnow', return_value=self.now):
            return run('argus-poc-index', str(self.remote), self.root / job, job, policy=self.policy,
                       http=PocDependencyHttp(self.policy, files))

    def test_partial_intel_keeps_poc_sources_ok_but_manifest_health_and_gate_partial(self):
        result = self.run_with_dependency(False, 'partial')
        self.assertTrue(result['published'], result)
        self.assertEqual(result['status'], 'partial', result)
        self.assertTrue(all(source['status'] == 'ok' for source in result['sources'].values()))
        self.assertFalse(result['baseline_complete'])
        self.assertEqual(result['baseline_gate_version'], 2)
        coverage = result['dependency_coverage']['argus-supply/argus-intel-data']
        self.assertFalse(coverage['coverage_complete'])
        self.assertEqual(coverage['commit_sha'], 'a' * 40)
        self.assertEqual(coverage['required_sources']['cve']['status'], 'partial')
        consumer = GitStore(self.root / 'consumer', str(self.remote))
        _, data = consumer.read('data')
        manifest = json.loads(data['manifest.json'])
        self.assertEqual(manifest['dependency_coverage'], result['dependency_coverage'])
        self.assertTrue(manifest['dependency_errors'])
        _, control = consumer.read('control')
        ledger = json.loads(control['ledger.json'])
        health = json.loads(control['health.json'])
        self.assertIsNone(ledger['git_cost']['baseline_completed_at'])
        self.assertEqual(health['collection_status'], 'partial')
        self.assertEqual(health['dependency_coverage'], result['dependency_coverage'])
        intent = ledger['reservations']['partial']['git_publication']
        self.assertFalse(intent['baseline_complete'])
        self.assertEqual(intent['baseline_gate_version'], 2)
        self.assertEqual(intent['dependency_coverage'], result['dependency_coverage'])
        # Own source watermarks completed: partial dependency must not grant a
        # second HTTP initialization allowance in the same UTC day.
        self.policy['daily_bytes'] = result['upstream_bytes']
        denied = self.run_with_dependency(False, 'no-new-http')
        self.assertFalse(denied['bootstrap'])
        self.assertFalse(denied['published'])
        self.assertIn('daily byte budget exhausted', denied['error'])

    def test_complete_intel_and_own_sources_allow_gate_and_exact_noop_proof(self):
        first = self.run_with_dependency(True, 'complete')
        self.assertEqual(first['status'], 'ok', first)
        self.assertTrue(first['baseline_complete'])
        reader = GitStore(self.root / 'reader', str(self.remote))
        _, control = reader.read('control')
        ledger = json.loads(control['ledger.json'])
        self.assertEqual(ledger['git_cost']['baseline_completed_at'], self.now)
        self.assertEqual(ledger['reservations']['complete']['git_publication']['baseline_gate_version'], 2)
        second = self.run_with_dependency(True, 'complete-noop')
        self.assertEqual(second['status'], 'ok', second)
        self.assertTrue(second['baseline_complete'])
        self.assertFalse(second['published'])
        self.assertEqual(second['data_commit'], first['data_commit'])
        self.assertEqual(second['dependency_coverage'], first['dependency_coverage'])
        self.assertEqual(second['baseline_gate_version'], 2)


if __name__ == '__main__':
    unittest.main()
