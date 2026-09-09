"""Local Git publication evidence: reservations precede main and survive failures."""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

from sync.core import ROOT, load_policy
from sync.gitstore import GitStore
from sync.ledger import CostMigrationRequired, Ledger
from tools import publish


class PublishCostTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='argus-publish-test-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.remote = self.root / 'remote.git'
        self.target = self.root / 'target'
        self.git('init', '--bare', '-q', str(self.remote))
        self.store = GitStore(self.root / 'shadow.git', str(self.remote))
        self.ledger = Ledger(self.store, load_policy(ROOT / 'policy.json'))
        self.record = {}
        self.saved = []

    def git(self, *args):
        return subprocess.run(['git', *args], check=True, capture_output=True, text=True, timeout=30).stdout.strip()

    def seed(self, *, metered=True, complete=False):
        if metered:
            self.ledger.reserve('seed-main', 0, publication_only=True)
        files = {'code.py': b'old code\n', 'deleted.txt': b'removed later\n'}
        parent, _ = self.store.prepare('main', None, files, 'initial main')
        if metered:
            self.ledger.reserve_publication('seed-main', 'main', parent, sum(map(len, files.values())))
        self.store.push_prepared('main', parent)
        if metered:
            self.ledger.settle('seed-main', 0, 0, published=True, runner_seconds=0)
        if complete:
            self.ledger.reserve('seed-data', 0, publication_only=True)
            data, _ = self.store.prepare('data', None, {'data.json': b'{}'}, 'complete baseline')
            self.ledger.reserve_publication('seed-data', 'data', data, 2)
            self.store.push_prepared('data', data)
            self.ledger.settle('seed-data', 0, 0, published=True, runner_seconds=0, baseline_complete=True)
        self.git('init', '-q', '-b', 'main', str(self.target))
        self.git('-C', str(self.target), 'config', 'user.name', 'ARGUS fixture')
        self.git('-C', str(self.target), 'config', 'user.email', 'fixture@argus.invalid')
        self.git('-C', str(self.target), 'fetch', str(self.remote), 'refs/heads/main')
        self.git('-C', str(self.target), 'reset', '--hard', 'FETCH_HEAD')
        self.ledger.control_measurements.clear()
        return parent

    def candidate(self):
        (self.target / 'code.py').write_bytes(b'new code\n' * 50)
        (self.target / 'new\nname.bin').write_bytes(b'\x00\xff\x00')
        (self.target / 'deleted.txt').unlink()
        return publish.prepare_candidate(self.target, publish.REPOS[0], self.root)

    def run_candidate(self, prepared):
        return publish.publish_candidate(publish.REPOS[0], prepared, self.store, self.ledger,
            self.record, lambda: self.saved.append(copy.deepcopy(self.record)))

    def fresh(self):
        return Ledger(GitStore(self.root / 'fresh.git', str(self.remote)), self.ledger.policy)

    def test_main_is_precharged_with_control_costs_and_does_not_complete_baseline(self):
        self.seed()
        prepared = self.candidate()
        self.assertEqual(prepared['full_changed_file_bytes'], 453)
        before = self.ledger.read()[1]['git_cost']['accounted_upper_bound_bytes']
        original_push = self.store.push_prepared

        def inspect_before_push(branch, candidate):
            if branch == 'main':
                state = self.fresh().read()[1]
                intent = state['reservations'][self.record['job_id']]['git_publication']
                self.assertEqual(intent['candidate'], candidate)
                self.assertEqual(intent['state'], 'reserved')
                self.assertGreater(state['git_cost']['accounted_upper_bound_bytes'], before)
                self.assertNotEqual(self.store.observe_heads()['refs/heads/main'], candidate)
            return original_push(branch, candidate)

        with patch.object(self.store, 'push_prepared', side_effect=inspect_before_push):
            self.run_candidate(prepared)
        state = self.fresh().read()[1]
        reservation = state['reservations'][self.record['job_id']]
        self.assertEqual(self.record['status'], 'published')
        self.assertEqual(self.record['phase'], 'initialization')
        self.assertEqual(reservation['status'], 'settled')
        self.assertEqual(reservation['runner_minutes'], 0)
        self.assertEqual(reservation['charged_bytes'], 0)
        self.assertEqual(reservation['git_publication']['full_changed_file_bytes'], 453)
        self.assertEqual(state['git_cost']['accounted_refs']['refs/heads/main'], prepared['candidate'])
        self.assertIsNone(state['git_cost']['baseline_completed_at'])
        self.assertEqual(len(self.record['control_measurements']), 3)
        self.assertEqual(state['git_cost']['accounted_upper_bound_bytes'] - before,
            self.record['measurement']['compressed_object_upper_bound_bytes'] + self.record['control_charged_upper_bound_bytes'])
        self.assertTrue(all(row['measured_pack_bytes'] <= row['charged_upper_bound_bytes']
                            for row in self.record['control_measurements']))
        self.assertEqual([row['status'] for row in self.saved],
                         ['pending', 'work-reserved', 'publication-reserved', 'pushed', 'published'])

    def test_completed_data_baseline_puts_main_in_steady_phase(self):
        self.seed(complete=True)
        baseline = self.ledger.read()[1]['git_cost']['baseline_completed_at']
        self.run_candidate(self.candidate())
        state = self.fresh().read()[1]
        reservation = state['reservations'][self.record['job_id']]
        self.assertEqual(self.record['phase'], 'steady')
        self.assertFalse(reservation['bootstrap'])
        self.assertFalse(reservation['initialization'])
        self.assertEqual(state['git_cost']['baseline_completed_at'], baseline)

    def test_unmigrated_history_refuses_all_remote_writes(self):
        parent = self.seed(metered=False)
        with patch.object(self.store, 'push_prepared', wraps=self.store.push_prepared) as push:
            with self.assertRaises(CostMigrationRequired):
                self.run_candidate(self.candidate())
        push.assert_not_called()
        self.assertEqual(self.store.observe_heads(), {'refs/heads/main': parent})
        self.assertEqual(self.record['failed_stage'], 'check-cost-baseline')
        self.assertEqual(self.record['control_measurements'], [])

    def test_failed_main_push_retains_reserved_intent_without_refund(self):
        parent = self.seed()
        prepared = self.candidate()
        original_push = self.store.push_prepared

        def fail_main(branch, candidate):
            if branch == 'main':
                raise RuntimeError('fixture connection lost')
            return original_push(branch, candidate)

        with patch.object(self.store, 'push_prepared', side_effect=fail_main):
            with self.assertRaisesRegex(RuntimeError, 'connection lost'):
                self.run_candidate(prepared)
        state = self.fresh().read()[1]
        item = state['reservations'][self.record['job_id']]
        self.assertEqual(item['status'], 'reserved')
        self.assertEqual(item['git_publication']['candidate'], prepared['candidate'])
        self.assertEqual(self.store.observe_heads()['refs/heads/main'], parent)
        self.assertTrue(self.record['publication_intent_retained'])
        self.assertEqual(self.record['failed_stage'], 'push-main')
        self.assertEqual(len(self.record['control_measurements']), 2)

    def test_lost_push_ack_keeps_cost_and_reconciles_on_a_fresh_reader(self):
        self.seed()
        prepared = self.candidate()
        original_push = self.store.push_prepared

        def lose_ack(branch, candidate):
            result = original_push(branch, candidate)
            if branch == 'main':
                raise RuntimeError('fixture acknowledgement lost')
            return result

        with patch.object(self.store, 'push_prepared', side_effect=lose_ack):
            with self.assertRaisesRegex(RuntimeError, 'acknowledgement lost'):
                self.run_candidate(prepared)
        state = self.fresh().read()[1]
        item = state['reservations'][self.record['job_id']]
        self.assertEqual(item['status'], 'reserved')
        self.assertEqual(state['git_cost']['accounted_refs']['refs/heads/main'], prepared['candidate'])
        self.assertGreater(item['git_publication']['compressed_upper_bound_bytes'], 0)
        self.assertTrue(self.record['publication_intent_retained'])

    def test_failed_settlement_retains_pushed_commit_and_intent(self):
        self.seed()
        prepared = self.candidate()
        with patch.object(self.ledger, 'settle', side_effect=RuntimeError('fixture settlement interrupted')):
            with self.assertRaisesRegex(RuntimeError, 'settlement interrupted'):
                self.run_candidate(prepared)
        state = self.fresh().read()[1]
        self.assertEqual(self.record['main_sha'], prepared['candidate'])
        self.assertEqual(self.record['failed_stage'], 'settle-publication')
        self.assertEqual(state['reservations'][self.record['job_id']]['status'], 'reserved')
        self.assertTrue(self.record['publication_intent_retained'])

    def test_unchanged_main_has_no_new_reservation_or_control_cost(self):
        parent = self.seed()
        prepared = publish.prepare_candidate(self.target, publish.REPOS[0], self.root)
        self.run_candidate(prepared)
        self.assertEqual(self.record['status'], 'unchanged')
        self.assertEqual(self.record['main_sha'], parent)
        self.assertEqual(self.record['control_measurements'], [])
        self.assertNotIn(self.record['job_id'], self.fresh().read()[1]['reservations'])


class PublishPreparationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='argus-publish-preparation-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.repository = publish.REPOS[0]

    def run_tests(self):
        publish.test_target(self.root, self.root, self.repository, 'a' * 40, self.root)

    def test_all_tests_have_bounded_timeout_and_no_publication_credentials(self):
        with patch.object(publish, 'output', side_effect=[str(self.root), 'main', '']), \
             patch.object(publish, 'command') as command, \
             patch.object(publish.subprocess, 'run', return_value=Mock(returncode=0, stdout='passed\n', stderr='')) as run, \
             patch.dict(os.environ, GH_TOKEN='fixture-token', GITHUB_TOKEN='another-fixture-token'):
            self.run_tests()
        self.assertEqual(run.call_args.kwargs['timeout'], 600)
        self.assertNotIn('GH_TOKEN', run.call_args.kwargs['env'])
        self.assertNotIn('GITHUB_TOKEN', run.call_args.kwargs['env'])
        self.assertEqual(len(command.call_args_list), 3)
        self.assertIn('check_distribution.py', command.call_args_list[-1].args[0][-1])

    def test_detached_inspected_worktree_is_supported(self):
        with patch.object(publish, 'output', side_effect=[str(self.root), 'HEAD', '']), \
             patch.object(publish, 'command'), \
             patch.object(publish.subprocess, 'run', return_value=Mock(returncode=0, stdout='passed', stderr='')):
            self.run_tests()

    def test_unrelated_named_branch_is_refused_before_regeneration(self):
        with patch.object(publish, 'output', side_effect=[str(self.root), 'unrelated-work']), \
             patch.object(publish, 'command') as command:
            with self.assertRaisesRegex(ValueError, 'detached or on main'):
                self.run_tests()
        command.assert_not_called()

    def test_timeout_preserves_partial_logs_and_fails(self):
        with patch.object(publish, 'output', side_effect=[str(self.root), 'main', '']), \
             patch.object(publish, 'command'), \
             patch.object(publish.subprocess, 'run', side_effect=subprocess.TimeoutExpired('unittest', 600, output=b'partial stdout', stderr=b'partial stderr')):
            with self.assertRaisesRegex(RuntimeError, 'timed out'):
                self.run_tests()
        log = (self.root / (self.repository + '-local-tests.txt')).read_text()
        self.assertIn('partial stdout', log)
        self.assertIn('partial stderr', log)
        self.assertIn('FAILED', log)

    def test_failed_tests_are_not_reported_passed(self):
        with patch.object(publish, 'output', side_effect=[str(self.root), 'main', '']), \
             patch.object(publish, 'command'), \
             patch.object(publish.subprocess, 'run', return_value=Mock(returncode=1, stdout='', stderr='FAILED')):
            with self.assertRaisesRegex(RuntimeError, 'tests failed'):
                self.run_tests()
        self.assertEqual((self.root / (self.repository + '-local-tests.txt')).read_text(), 'FAILED')

    def test_skipped_tests_are_not_reported_passed(self):
        with patch.object(publish, 'output', side_effect=[str(self.root), 'main', '']), \
             patch.object(publish, 'command'), \
             patch.object(publish.subprocess, 'run', return_value=Mock(returncode=0, stdout='', stderr='OK (skipped=1)')):
            with self.assertRaisesRegex(RuntimeError, 'skipped required verification'):
                self.run_tests()

    def test_hash_drift_after_tests_refuses_candidate(self):
        with patch.object(publish, 'output', side_effect=[str(self.root), 'main', '']), \
             patch.object(publish, 'command', side_effect=[None, None, RuntimeError('hash drift')]), \
             patch.object(publish.subprocess, 'run', return_value=Mock(returncode=0, stdout='passed', stderr='')):
            with self.assertRaisesRegex(RuntimeError, 'hash drift'):
                self.run_tests()

    def test_all_three_test_results_are_saved_before_failed_run_can_prepare_or_push(self):
        report_path = self.root / 'distribution.json'
        report_path.write_text(json.dumps({'worktrees': {name: str(self.root / name) for name in publish.REPOS}}))

        def test(source, target, name, commit, report_directory):
            if name == publish.REPOS[1]:
                raise RuntimeError('fixture test failure')

        with patch.object(sys, 'argv', ['publish.py', '--source-commit', 'a' * 40, '--report-directory', str(self.root)]), \
             patch.object(publish, 'output', return_value='a' * 40), \
             patch.object(publish, 'command', return_value=Mock(stdout=b'')) as command, \
             patch.object(publish.tarfile, 'open'), \
             patch.object(publish.tempfile, 'mkdtemp', return_value=str(self.root / 'export')), \
             patch.object(publish, 'test_target', side_effect=test) as tests, \
             patch.object(publish, 'prepare_candidate') as prepare, \
             patch.object(publish, 'publish_candidate') as push:
            with self.assertRaisesRegex(SystemExit, 'standalone verification failed'):
                publish.main()
        prepare.assert_not_called()
        push.assert_not_called()
        self.assertEqual(tests.call_count, 3)
        self.assertEqual(command.call_count, 1)
        report = json.loads(report_path.read_text())
        self.assertEqual([report['standalone_tests'][name]['status'] for name in publish.REPOS], ['passed', 'failed', 'passed'])

    def test_remote_allowlist_rejects_other_repositories(self):
        for name in publish.REPOS:
            self.assertEqual(publish.remote_url(name), 'https://github.com/argus-supply/' + name + '.git')
        with self.assertRaises(ValueError):
            publish.remote_url('another-repository')


if __name__ == '__main__':
    unittest.main()
