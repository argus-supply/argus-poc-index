"""Bounded migration replay over real local bare Git repositories, without network."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from sync.gitcost import GitCostUnavailable, measure_increment
from tools.measure_git_history import Commands, DEFAULTS, encoded, measure_history


class GitHistoryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='argus-history-fixture-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.remote = self.root / 'remote.git'
        self.remote.mkdir()
        self.env = dict(os.environ, GIT_AUTHOR_NAME='Fixture', GIT_COMMITTER_NAME='Fixture',
            GIT_AUTHOR_EMAIL='fixture@example.invalid', GIT_COMMITTER_EMAIL='fixture@example.invalid')
        self.git('init', '--bare', '--template=', '-q')
        self.cutoffs = {branch: None for branch in ('main', 'data', 'control')}

    def git(self, *args, data=None, stamp='2026-09-09T00:00:00Z'):
        return subprocess.run(['git', '-C', str(self.remote), *args], input=data,
            capture_output=True, check=True, timeout=10,
            env={**self.env, 'GIT_AUTHOR_DATE': stamp, 'GIT_COMMITTER_DATE': stamp}).stdout

    def commit(self, branch, body, *, parent=None, stamp='2026-09-09T00:00:00Z', message=None):
        blob = self.git('hash-object', '-w', '--stdin', data=body).decode().strip()
        tree = self.git('mktree', data=f'100644 blob {blob}\t{branch}.json\n'.encode()).decode().strip()
        arguments = ['commit-tree', tree]
        parents = [parent] if isinstance(parent, str) else parent or []
        for value in parents:
            arguments.extend(['-p', value])
        oid = self.git(*arguments, data=((message or branch) + '\n').encode(), stamp=stamp).decode().strip()
        self.git('update-ref', 'refs/heads/' + branch, oid)
        self.cutoffs[branch] = oid
        return oid

    def measure(self, **kwargs):
        return measure_history('argus-intel-data', self.remote, self.cutoffs,
                               work_parent=self.root, **kwargs)

    def history(self):
        main = self.commit('main', b'code\n' * 100)
        data = self.commit('data', b'first reference\n' * 100, stamp='2026-09-09T00:01:00Z')
        control = self.commit('control', b'{"reserved":true}', stamp='2026-09-09T00:02:00Z')
        last_data = self.commit('data', b'second reference\n' * 100, parent=data, stamp='2026-09-09T00:03:00Z')
        last_control = self.commit('control', b'{"settled":true}', parent=control, stamp='2026-09-09T00:04:00Z')
        last_main = self.commit('main', b'fixed code\n' * 100, parent=main, stamp='2026-09-09T00:05:00Z')
        return [main, data, control, last_data, last_control, last_main]

    def test_all_branches_replay_historical_tips_and_keep_real_pack_evidence(self):
        expected = self.history()
        before = self.git('for-each-ref', '--format=%(refname) %(objectname)')
        report = self.measure()
        self.assertTrue(report['complete'], report['coverage_gaps'])
        self.assertTrue(report['ancestry_closed'])
        self.assertEqual([row['sha'] for row in report['commits']], expected)
        self.assertEqual(report['audited_commit_count'], 6)
        self.assertEqual(report['shallow_snapshot_fetches'], 6)
        self.assertEqual(set(report['by_branch']), {'main', 'data', 'control'})
        self.assertEqual(set(report['by_phase']), {'initialization'})
        self.assertIsNone(report['git_protocol_bytes'])
        self.assertEqual(before, self.git('for-each-ref', '--format=%(refname) %(objectname)'))
        self.assertFalse(list(self.root.glob('argus-git-history-*')))
        for row in report['commits']:
            measurement = measure_increment(self.remote, row['sha'], row['historical_tips'], baseline_complete=True)
            self.assertEqual(measurement['pack_sha256'], row['measurement']['pack_sha256'])
            self.assertEqual(measurement['actual_pack_bytes'], row['measurement']['actual_pack_bytes'])
            self.assertEqual(row['day'], '2026-09-09')
        first_data = report['commits'][1]
        self.assertNotIn('refs/heads/data', first_data['historical_tips'])
        self.assertNotIn(expected[-1], first_data['historical_tips'].values())
        self.assertEqual(first_data['measurement']['object_counts']['blob'], 1)
        self.assertEqual(report['totals']['actual_pack_bytes_sum'],
                         sum(row['measurement']['actual_pack_bytes'] for row in report['commits']))
        digest = report.pop('evidence_sha256')
        self.assertEqual(hashlib.sha256(encoded(report)).hexdigest(), digest)

    def test_explicit_baseline_groups_initialization_and_steady_without_old_flags(self):
        self.history()
        report = self.measure(baseline_completed_at='2026-09-09T00:03:00Z')
        self.assertTrue(report['complete'], report['coverage_gaps'])
        self.assertEqual([row['phase'] for row in report['commits']], ['initialization'] * 4 + ['steady'] * 2)
        self.assertEqual(report['totals']['compressed_object_upper_bound_bytes'],
            sum(group['compressed_object_upper_bound_bytes'] for group in report['by_phase'].values()))
        self.assertIn('steady', report['daily']['2026-09-09'])

    def test_fresh_replays_are_deterministic_and_commit_clock_skew_keeps_topology(self):
        parent = self.commit('main', b'parent', stamp='2026-09-10T00:00:00Z')
        child = self.commit('main', b'child', parent=parent, stamp='2026-09-09T00:00:00Z')
        first, second = self.measure(), self.measure()
        self.assertTrue(first['complete'], first['coverage_gaps'])
        self.assertEqual([row['sha'] for row in first['commits']], [parent, child])
        self.assertEqual(first['commits'], second['commits'])
        self.assertEqual(first['totals'], second['totals'])

    def test_fetches_only_explicit_sha_depth_one_and_never_clone_or_push(self):
        self.history()
        original, commands = subprocess.Popen, []
        def observe(command, **kwargs):
            commands.append(command)
            return original(command, **kwargs)
        with patch('tools.measure_git_history.subprocess.Popen', side_effect=observe):
            report = self.measure()
        self.assertTrue(report['complete'], report['coverage_gaps'])
        fetches = [command for command in commands if 'fetch' in command]
        self.assertEqual(len(fetches), 6)
        for command in fetches:
            self.assertIn('--depth=1', command)
            self.assertIn('--no-tags', command)
            self.assertRegex(command[-1], '^[0-9a-f]{40}$')
        self.assertFalse(any(argument in ('clone', 'push', '--unshallow', '--all')
                             for command in commands for argument in command))

    def test_unknown_cutoff_and_missing_parent_are_explicitly_incomplete(self):
        self.cutoffs['main'] = 'a' * 40
        missing = self.measure()
        self.assertFalse(missing['complete'])
        self.assertFalse(missing['ancestry_closed'])
        self.assertTrue(missing['coverage_gaps'])
        self.assertNotIn('history_baseline', missing)
        parent = self.commit('main', b'parent')
        self.commit('main', b'child', parent=parent, stamp='2026-09-09T00:01:00Z')
        # Model an explicitly shallow upstream: its known parent object is absent.
        (self.remote / 'shallow').write_text(self.cutoffs['main'] + '\n')
        (self.remote / 'objects' / parent[:2] / parent[2:]).unlink()
        incomplete = self.measure()
        self.assertFalse(incomplete['complete'])
        self.assertNotIn('history_baseline', incomplete)

    def test_commit_and_cumulative_raw_pack_limits_never_return_a_baseline(self):
        self.history()
        for limits in ({'max_commits': 2}, {'max_total_raw_bytes': 1}, {'max_total_pack_bytes': 1},
                       {'max_snapshot_raw_bytes': 1}, {'max_pack_bytes': 1}, {'max_objects': 1}):
            with self.subTest(limits=limits):
                report = self.measure(limits=limits)
                self.assertFalse(report['complete'])
                self.assertTrue(report['coverage_gaps'])
                self.assertNotIn('history_baseline', report)

    def test_disk_budget_stops_fetch_and_cleans_private_temporary_repository(self):
        self.commit('main', b'payload')
        report = self.measure(limits={'max_repository_bytes': 65536})
        self.assertFalse(report['complete'])
        self.assertIn('allocation', report['coverage_gaps'][0])
        self.assertLessEqual(report['temporary_repository_peak_bytes'], 65536)
        self.assertFalse(list(self.root.glob('argus-git-history-*')))
        commands = Commands(self.remote, {**DEFAULTS, 'max_repository_bytes': 131072}, time.monotonic())
        target = self.remote / 'quota-probe'
        with self.assertRaises(GitCostUnavailable):
            commands.run([sys.executable, '-c',
                'import pathlib,sys; pathlib.Path(sys.argv[1]).write_bytes(b"x" * 2000000)', str(target)], fetch=True)
        self.assertLessEqual(commands.disk(), 131072)
        self.assertLess(target.stat().st_size, 65536)

    def test_total_deadline_terminates_real_process_and_invalid_limits_fail(self):
        limits = {**DEFAULTS, 'timeout_seconds': 1}
        commands = Commands(self.remote, limits, time.monotonic())
        started = time.monotonic()
        with self.assertRaisesRegex(GitCostUnavailable, 'time limit'):
            commands.run([sys.executable, '-c', 'import time; time.sleep(60)'])
        self.assertLess(time.monotonic() - started, 2)
        for limits in ({'max_commits': 129}, {'timeout_seconds': 721}, {'max_repository_bytes': 536870913}):
            with self.subTest(limits=limits), self.assertRaises(ValueError):
                self.measure(limits=limits)

    def test_merge_and_shared_ref_histories_are_not_invented(self):
        main = self.commit('main', b'main')
        data = self.commit('data', b'data')
        self.commit('main', b'merged', parent=[main, data])
        merged = self.measure()
        self.assertFalse(merged['complete'])
        self.assertIn('Merge ancestry', merged['coverage_gaps'][0])
        self.cutoffs = {'main': main, 'data': main, 'control': None}
        shared = self.measure()
        self.assertFalse(shared['complete'])
        self.assertIn('Shared branch ancestry', shared['coverage_gaps'][0])

    def test_cli_writes_verifiable_report_and_does_not_publish(self):
        self.commit('main', b'fixture code')
        output = self.root / 'report.json'
        tool = Path(__file__).resolve().parents[1] / 'tools/measure_git_history.py'
        result = subprocess.run([sys.executable, str(tool), '--repository', 'argus-intel-data',
            '--main', self.cutoffs['main'], '--data', 'none', '--control', 'none',
            '--remote', str(self.remote), '--output', str(output)], capture_output=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        report = json.loads(output.read_text())
        self.assertTrue(report['complete'])
        self.assertEqual(report['cutoffs'], self.cutoffs)
        self.assertEqual(json.loads(result.stdout)['status'], 'measured')


if __name__ == '__main__':
    unittest.main()
