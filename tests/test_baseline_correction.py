"""Real bare-Git evidence for dependency baseline correction and gate version two."""
import copy
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from sync.adapters import AdapterResult
from sync.core import ROOT, apply_result, build_snapshot, digest, load_policy
from sync.gitstore import GitStore
from sync.ledger import CostMigrationRequired, Ledger


DAY = '2026-09-09'
OLD_SUCCESS = DAY + 'T01:00:00Z'
OLD_MARKER = DAY + 'T02:00:00Z'
NOW = DAY + 'T03:00:00Z'
INTEL = 'argus-supply/argus-intel-data'
POC = 'argus-supply/argus-poc-index'


class BaselineCorrectionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='argus-baseline-correction-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.remote = self.bare('poc-remote.git')
        self.policy = load_policy(ROOT / 'policy.json')
        self.store = GitStore(self.root / 'poc-runner.git', str(self.remote))
        self.ledger = Ledger(self.store, self.policy, DAY)
        self.clock = patch('sync.ledger.utcnow', return_value=NOW)
        self.clock.start()
        self.addCleanup(self.clock.stop)

    def bare(self, name):
        path = self.root / name
        subprocess.run(['git', 'init', '--bare', '-q', str(path)], check=True,
                       capture_output=True, timeout=30)
        return path

    def fresh(self, name='fresh-reader.git'):
        return Ledger(GitStore(self.root / name, str(self.remote)), self.policy, DAY)

    def snapshot(self, repository, *, partial=False, dependencies=None):
        records, events, sources = {}, {}, {}
        names = ('cve', 'ghsa', 'kev') if repository == INTEL else ('exploitdb', 'official-references', 'poc-in-github')
        for name in names:
            apply_result(records, events, sources, name,
                AdapterResult(status='ok', revision='a' * 40, completed_watermark=OLD_SUCCESS),
                OLD_SUCCESS, self.policy)
        if partial:
            apply_result(records, events, sources, 'cve', AdapterResult(status='partial', revision='b' * 40,
                completed_watermark=OLD_SUCCESS, continuation={'offset': 1},
                coverage_gaps=[{'reason': 'unfinished historical window'}]), NOW, self.policy)
        return build_snapshot(repository, records, events, sources, self.policy,
                              NOW, 'baseline-correction-fixture', dependencies=dependencies)

    def dependency(self, *, complete=False):
        files, manifest = self.snapshot(INTEL, partial=not complete)
        remote = self.bare('intel-remote.git')
        store = GitStore(self.root / 'intel-runner.git', str(remote))
        sha, _ = store.prepare('data', None, files, 'pinned upstream fixture')
        store.push_prepared('data', sha)
        self.proof = {'repository': INTEL, 'commit_sha': sha, 'manifest_bytes': files['manifest.json']}
        self.dependency_reference = {'repository': INTEL, 'commit_sha': sha,
                                     'manifest_sha256': digest(files['manifest.json'])}
        self.coverage = {INTEL: {**self.dependency_reference, 'coverage_complete': complete}}
        return manifest

    def prepare_data(self, job, *, complete_dependency=False, extra_dependencies=()):
        self.dependency(complete=complete_dependency)
        files, manifest = self.snapshot(POC, dependencies=[self.dependency_reference, *extra_dependencies])
        self.ledger.reserve(job, 1024, bootstrap=True)
        candidate, _ = self.store.prepare('data', None, files, 'PoC snapshot with pinned dependency')
        return candidate, files, manifest

    def mistaken_baseline(self, *, complete_dependency=False, extra_dependencies=()):
        candidate, files, manifest = self.prepare_data('old-success', complete_dependency=complete_dependency,
                                                     extra_dependencies=extra_dependencies)
        self.ledger.reserve_publication('old-success', 'data', candidate, sum(map(len, files.values())))
        self.store.push_prepared('data', candidate)
        health = {'status': 'ok', 'last_success_at': OLD_SUCCESS, 'sources': copy.deepcopy(manifest['sources'])}
        self.ledger.settle('old-success', 123, 3, published=True, runner_seconds=61, health=health)
        parent, state = self.ledger.read()
        # Reconstruct the persisted historical defect. Current public APIs reject
        # gate-one completion; a measured append supplies only this legacy fixture.
        state['git_cost']['baseline_completed_at'] = OLD_MARKER
        state['reservations']['old-success']['git_publication'].update(
            baseline_complete=True, baseline_gate_version=1, dependency_coverage=None, reserved_at=OLD_MARKER)
        self.ledger.write(parent, state, 'fixture historical incomplete baseline claim', initialization=True)
        self.ledger.reserve('later-steady-work', 32)
        self.ledger.settle('later-steady-work', 7, 1, runner_seconds=1)
        self.data_sha, self.data_files = candidate, files
        self.ledger.control_measurements.clear()
        return self.ledger.read()

    def test_correction_appends_evidence_preserving_costs_quotas_success_and_old_marker(self):
        parent, before = self.mistaken_baseline()
        _, original_control = self.store.read('control')
        result = self.ledger.correct_incomplete_dependency_baseline(self.data_sha, [self.proof])
        corrected_parent, after = self.fresh().read()
        _, corrected_control = self.store.read('control')
        correction = after['git_cost']['baseline_corrections'][0]
        self.assertEqual(corrected_parent, result['control_sha'])
        self.assertNotEqual(corrected_parent, parent)
        parents = self.store.run('cat-file', 'commit', corrected_parent).stdout.split(b'\n\n', 1)[0].splitlines()
        self.assertIn(('parent ' + parent).encode(), parents)
        self.assertEqual(self.store.read('data'), (self.data_sha, self.data_files))
        self.assertEqual(corrected_control['health.json'], original_control['health.json'])
        self.assertEqual(json.loads(corrected_control['health.json'])['last_success_at'], OLD_SUCCESS)
        self.assertEqual(after['reservations'], before['reservations'])
        self.assertEqual(after['runner_minutes_used'], before['runner_minutes_used'])
        self.assertEqual(after['runner_minutes_used'], 3)
        self.assertEqual(after['reservations']['old-success']['charged_bytes'], 123)
        self.assertEqual(after['reservations']['old-success']['requests'], 3)
        self.assertEqual(after['reservations']['later-steady-work']['charged_bytes'], 7)
        self.assertEqual(correction['invalidated_completed_at'], OLD_MARKER)
        self.assertIsNone(correction['replacement_completed_at'])
        self.assertEqual(correction['data_commit'], self.data_sha)
        self.assertEqual(correction['dependencies'], [{**self.dependency_reference, 'coverage_complete': False}])
        self.assertEqual(correction['cost_refund_bytes'], 0)
        self.assertEqual(correction['accounted_bytes_before'], before['git_cost']['accounted_upper_bound_bytes'])
        self.assertEqual(correction['prior_steady_charges_retained'], before['git_cost']['steady_daily_bytes'])
        self.assertEqual(after['git_cost']['steady_daily_bytes'], before['git_cost']['steady_daily_bytes'])
        self.assertEqual(after['git_cost']['full_changed_file_bytes'], before['git_cost']['full_changed_file_bytes'])
        measured = result['control_measurements']
        self.assertEqual(len(measured), 1)
        charge = measured[0]['charged_upper_bound_bytes']
        self.assertGreater(measured[0]['measured_pack_bytes'], 0)
        self.assertLessEqual(measured[0]['measured_pack_bytes'], charge)
        self.assertEqual(after['git_cost']['accounted_upper_bound_bytes'], before['git_cost']['accounted_upper_bound_bytes'] + charge)
        self.assertEqual(after['git_cost']['initialization_bytes'], before['git_cost']['initialization_bytes'] + charge)
        self.assertIsNone(after['git_cost']['baseline_completed_at'])
        self.assertIn(self.data_sha, after['git_cost']['invalidated_baseline_candidates'])
        self.assertTrue(self.fresh('another-reader.git').initializing())

    def test_fresh_read_cannot_revive_corrected_marker_from_old_or_invalidated_intent(self):
        self.mistaken_baseline()
        self.ledger.correct_incomplete_dependency_baseline(self.data_sha, [self.proof])
        for version in (1, 2):
            with self.subTest(baseline_gate_version=version):
                parent, state = self.ledger.read()
                state['git_cost']['accounted_refs'].pop('refs/heads/data')
                state['reservations']['old-success']['git_publication']['baseline_gate_version'] = version
                self.ledger.write(parent, state, 'fixture stale accounted ref after correction', initialization=True)
                _, fresh = self.fresh('recovery-' + str(version) + '.git').read()
                self.assertEqual(fresh['git_cost']['accounted_refs']['refs/heads/data'], self.data_sha)
                self.assertIsNone(fresh['git_cost']['baseline_completed_at'])
                self.assertEqual(fresh['reservations']['old-success']['git_publication']['baseline_complete'], True)
                self.assertEqual(fresh['git_cost']['baseline_corrections'][0]['invalidated_completed_at'], OLD_MARKER)

    def test_fifth_proven_correction_retains_existing_evidence_and_all_costs(self):
        parent, state = self.mistaken_baseline()
        existing = [{'at': OLD_MARKER, 'reason': f'historical correction {index}'} for index in range(4)]
        state['git_cost']['baseline_corrections'] = copy.deepcopy(existing)
        self.ledger.write(parent, state, 'fixture existing correction history', initialization=True)
        before = self.ledger.read()[1]['git_cost']['accounted_upper_bound_bytes']
        with self.assertLogs('sync.observations', level='WARNING'):
            self.ledger.correct_incomplete_dependency_baseline(self.data_sha, [self.proof])
        after = self.fresh().read()[1]['git_cost']
        self.assertEqual(after['baseline_corrections'][:4], existing)
        self.assertEqual(len(after['baseline_corrections']), 5)
        self.assertEqual(after['baseline_corrections'][4]['data_commit'], self.data_sha)
        self.assertEqual(after['baseline_corrections'][4]['cost_refund_bytes'], 0)
        self.assertGreater(after['accounted_upper_bound_bytes'], before)

    def test_complete_pinned_dependency_cannot_invalidate_a_baseline(self):
        _, before = self.mistaken_baseline(complete_dependency=True)
        old_heads = self.store.observe_heads()
        with self.assertRaisesRegex(ValueError, 'no incomplete pinned dependency'):
            self.ledger.correct_incomplete_dependency_baseline(self.data_sha, [self.proof])
        self.assertEqual(self.store.observe_heads(), old_heads)
        self.assertEqual(self.fresh().read()[1], before)

    def test_wrong_data_sha_dependency_sha_hash_or_repository_never_writes_correction(self):
        repository = 'argus-supply/argus-detection-resources'
        extra_files, _ = self.snapshot(repository)
        extra_store = GitStore(self.root / 'detection-runner.git', str(self.bare('detection-remote.git')))
        extra_sha, _ = extra_store.prepare('data', None, extra_files, 'fixed non-intel dependency')
        extra_store.push_prepared('data', extra_sha)
        extra_reference = {'repository': repository, 'commit_sha': extra_sha,
                           'manifest_sha256': digest(extra_files['manifest.json'])}
        _, before = self.mistaken_baseline(extra_dependencies=[extra_reference])
        old_heads = self.store.observe_heads()
        cases = [
            ('f' * 40, self.proof, CostMigrationRequired),
            (self.data_sha, {**self.proof, 'commit_sha': 'e' * 40}, ValueError),
            (self.data_sha, {**self.proof, 'manifest_bytes': self.proof['manifest_bytes'] + b' '}, ValueError),
            (self.data_sha, {**self.proof, 'repository': 'argus-supply/another-repository'}, ValueError),
        ]
        for expected, proof, exception in cases:
            with self.subTest(expected_data_sha=expected, proof_repository=proof['repository'], proof_sha=proof['commit_sha']):
                with self.assertRaises(exception):
                    self.ledger.correct_incomplete_dependency_baseline(expected, [proof])
                self.assertEqual(self.store.observe_heads(), old_heads)
                self.assertEqual(self.fresh().read()[1], before)
        # Matching published SHA/hash and a declared dependency cannot widen the
        # correction scope to a repository that does not supply the intel baseline.
        non_intel_proof = {'repository': repository, 'commit_sha': extra_sha,
                           'manifest_bytes': extra_files['manifest.json']}
        with self.assertRaisesRegex(ValueError, 'configured intel dependency'):
            self.ledger.correct_incomplete_dependency_baseline(self.data_sha, [non_intel_proof])
        self.assertEqual(self.store.observe_heads(), old_heads)
        self.assertEqual(self.fresh().read()[1], before)

    def test_gate_two_rejects_complete_reservation_with_partial_pinned_dependency(self):
        candidate, files, _ = self.prepare_data('partial-reserve')
        parent, before = self.ledger.read()
        with self.assertRaisesRegex(ValueError, 'complete pinned dependencies'):
            self.ledger.reserve_publication('partial-reserve', 'data', candidate,
                sum(map(len, files.values())), baseline_complete=True,
                baseline_gate_version=2, dependency_coverage=self.coverage)
        self.assertEqual(self.fresh().read(), (parent, before))
        self.assertNotIn('refs/heads/data', self.store.observe_heads())
        self.assertNotIn('git_publication', before['reservations']['partial-reserve'])

    def test_gate_two_rejects_complete_settlement_with_partial_pinned_dependency(self):
        candidate, files, _ = self.prepare_data('partial-settle')
        self.ledger.reserve_publication('partial-settle', 'data', candidate, sum(map(len, files.values())),
            baseline_complete=False, baseline_gate_version=2, dependency_coverage=self.coverage)
        self.store.push_prepared('data', candidate)
        parent, before = self.fresh().read()
        with self.assertRaisesRegex(ValueError, 'complete pinned dependencies'):
            self.ledger.settle('partial-settle', 123, 3, published=True, runner_seconds=61,
                baseline_complete=True, baseline_gate_version=2, dependency_coverage=self.coverage)
        self.assertEqual(self.fresh().read(), (parent, before))
        self.assertIsNone(before['git_cost']['baseline_completed_at'])
        self.assertEqual(before['reservations']['partial-settle']['status'], 'reserved')

    def test_gate_two_complete_dependency_allows_reservation_recovery_and_settlement(self):
        candidate, files, _ = self.prepare_data('complete-dependency', complete_dependency=True)
        self.ledger.reserve_publication('complete-dependency', 'data', candidate, sum(map(len, files.values())),
            baseline_complete=True, baseline_gate_version=2, dependency_coverage=self.coverage)
        reserved = self.fresh().read()[1]
        self.assertIsNone(reserved['git_cost']['baseline_completed_at'])
        intent = reserved['reservations']['complete-dependency']['git_publication']
        self.assertEqual(intent['dependency_coverage'], self.coverage)
        self.assertEqual(intent['baseline_gate_version'], 2)
        self.store.push_prepared('data', candidate)
        recovered = self.fresh().read()[1]
        self.assertEqual(recovered['git_cost']['baseline_completed_at'], intent['reserved_at'])
        self.ledger.settle('complete-dependency', 123, 3, published=True, runner_seconds=61,
            baseline_complete=True, baseline_gate_version=2, dependency_coverage=self.coverage)
        settled = self.fresh().read()[1]
        self.assertEqual(settled['reservations']['complete-dependency']['status'], 'settled')
        self.assertEqual(settled['git_cost']['accounted_refs']['refs/heads/data'], candidate)
        self.assertEqual(settled['git_cost']['baseline_completed_at'], NOW)
        self.assertFalse(self.fresh().initializing())


if __name__ == '__main__':
    unittest.main()
