"""Real bare-Git regressions for durable compressed-cost reservations."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from sync.core import ROOT, canonical, load_policy
from sync.gitcost import measure_increment
from sync.gitstore import GitStore, Ledger
from sync.http import BudgetExceeded
from sync.ledger import CostMigrationRequired


DAY = '2026-09-09'
NOW = DAY + 'T12:00:00Z'
MIB = 1048576


class LedgerCostTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='argus-ledger-cost-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.remote = self.root / 'remote.git'
        subprocess.run(['git', 'init', '--bare', '-q', str(self.remote)], check=True, capture_output=True)
        self.policy = load_policy(ROOT / 'policy.json')
        self.store = GitStore(self.root / 'runner-one', str(self.remote))
        self.ledger = Ledger(self.store, self.policy, DAY)
        self.clock = patch('sync.ledger.utcnow', return_value=NOW)
        self.clock.start()
        self.addCleanup(self.clock.stop)

    def fresh(self, name='runner-two', day=DAY):
        return Ledger(GitStore(self.root / name, str(self.remote)), self.policy, day)

    def prepare(self, ledger, job, branch, files):
        ledger.reserve(job, 0, publication_only=True)
        parent, before = ledger.store.read(branch)
        candidate, changed = ledger.store.prepare(branch, parent, files, 'fixture ' + job)
        self.assertTrue(changed)
        full_bytes = sum(len(data) for name, data in files.items() if before.get(name) != data)
        measured = ledger.reserve_publication(job, branch, candidate, full_bytes)
        return candidate, measured

    def publish(self, ledger, job, branch, files, *, complete=False):
        candidate, measured = self.prepare(ledger, job, branch, files)
        ledger.store.push_prepared(branch, candidate)
        ledger.settle(job, 0, 0, published=True, baseline_complete=complete, runner_seconds=0)
        return candidate, measured

    def test_control_commits_charge_a_verified_upper_bound_before_publication(self):
        self.ledger.reserve('one', 128)
        self.ledger.settle('one', 12, 1, runner_seconds=2)
        _, state = self.fresh().read()
        measurements = self.ledger.control_measurements
        self.assertEqual(len(measurements), 2)
        self.assertTrue(all(0 < row['measured_pack_bytes'] <= row['charged_upper_bound_bytes'] for row in measurements))
        self.assertEqual(state['git_cost']['accounted_upper_bound_bytes'],
                         sum(row['charged_upper_bound_bytes'] for row in measurements))
        self.assertEqual(state['git_cost']['initialization_bytes'], state['git_cost']['accounted_upper_bound_bytes'])
        self.assertEqual(state['last_control_charge']['upper_bound_bytes'], measurements[-1]['charged_upper_bound_bytes'])
        self.assertEqual(state['reservations']['one']['charged_bytes'], 12)

    def test_main_and_data_are_precharged_and_shared_objects_are_not_charged_twice(self):
        files = {'shared.json': b'cross-branch shared content\n' * 100}
        main, main_measurement = self.publish(self.ledger, 'main', 'main', files)
        before = self.ledger.read()[1]['git_cost']['accounted_upper_bound_bytes']
        data, data_measurement = self.prepare(self.ledger, 'data', 'data', files)
        fresh = self.fresh()
        _, state = fresh.read()
        self.assertNotIn('refs/heads/data', fresh.store.observe_heads())
        self.assertEqual(state['git_cost']['accounted_refs']['refs/heads/main'], main)
        self.assertEqual(state['reservations']['data']['git_publication']['candidate'], data)
        self.assertGreaterEqual(state['git_cost']['accounted_upper_bound_bytes'] - before,
                                data_measurement['compressed_object_upper_bound_bytes'])
        self.assertEqual(data_measurement['object_counts'], {'commit': 1, 'tree': 0, 'blob': 0})
        self.assertGreater(main_measurement['object_counts']['blob'], 0)
        self.store.push_prepared('data', data)
        fresh.settle('data', 0, 0, published=True, runner_seconds=0)
        settled = fresh.read()[1]
        self.assertEqual(settled['git_cost']['accounted_refs']['refs/heads/data'], data)

    def test_process_exit_after_push_before_settlement_is_charged_on_fresh_runner(self):
        script = '''import json, os, sys
from pathlib import Path
from sync.core import ROOT, load_policy
from sync.gitstore import GitStore, Ledger
store = GitStore(Path(sys.argv[1]), sys.argv[2])
ledger = Ledger(store, load_policy(ROOT / 'policy.json'), '2026-09-09')
ledger.reserve('killed', 0, publication_only=True)
candidate, _ = store.prepare('data', None, {'record.json': b'fixture'}, 'before killed runner')
measurement = ledger.reserve_publication('killed', 'data', candidate, 7)
before = ledger.read()[1]['git_cost']['accounted_upper_bound_bytes']
store.push_prepared('data', candidate)
print(json.dumps({'candidate': candidate, 'charged': before, 'measurement': measurement}), flush=True)
os._exit(23)
'''
        child = subprocess.run([sys.executable, '-c', script, str(self.root / 'killed-runner'), str(self.remote)],
            cwd=ROOT, capture_output=True, text=True, timeout=90)
        self.assertEqual(child.returncode, 23, child.stderr)
        evidence = json.loads(child.stdout)
        fresh = self.fresh()
        _, state = fresh.read()
        self.assertEqual(state['git_cost']['accounted_upper_bound_bytes'], evidence['charged'])
        self.assertEqual(state['git_cost']['accounted_refs']['refs/heads/data'], evidence['candidate'])
        self.assertEqual(state['reservations']['killed']['git_publication']['state'], 'reserved')
        with self.assertRaisesRegex(BudgetExceeded, 'already reserved'):
            fresh.reserve('killed', 0, publication_only=True)
        fresh.settle('killed', 0, 0, published=True, runner_seconds=0)
        final = fresh.read()[1]
        self.assertEqual(final['reservations']['killed']['git_publication']['state'], 'committed')
        self.assertEqual(final['git_cost']['accounted_upper_bound_bytes'], evidence['charged'] +
                         sum(row['charged_upper_bound_bytes'] for row in fresh.control_measurements))
        self.assertEqual(len(fresh.control_measurements), 1)

    def test_complete_data_intent_recovers_steady_phase_after_push_without_settlement(self):
        self.ledger.reserve('complete-before-exit', 0, publication_only=True)
        candidate, _ = self.store.prepare('data', None, {'record.json': b'complete fixture'}, 'complete baseline')
        self.ledger.reserve_publication('complete-before-exit', 'data', candidate, 16, baseline_complete=True)
        reserved = self.ledger.read()[1]
        intent = reserved['reservations']['complete-before-exit']['git_publication']
        self.assertTrue(intent['baseline_complete'])
        self.assertEqual(intent['reserved_at'], NOW)
        self.assertIsNone(reserved['git_cost']['baseline_completed_at'])
        self.store.push_prepared('data', candidate)
        fresh = self.fresh()
        self.assertFalse(fresh.initializing())
        recovered = fresh.read()[1]
        self.assertEqual(recovered['git_cost']['baseline_completed_at'], intent['reserved_at'])
        self.assertEqual(recovered['git_cost']['accounted_refs']['refs/heads/data'], candidate)
        self.assertEqual(recovered['reservations']['complete-before-exit']['status'], 'reserved')
        self.assertEqual(recovered['git_cost']['accounted_upper_bound_bytes'],
                         reserved['git_cost']['accounted_upper_bound_bytes'])
        fresh.reserve('next-steady', 1)
        persisted = self.fresh('runner-three').read()[1]
        self.assertEqual(persisted['git_cost']['baseline_completed_at'], intent['reserved_at'])
        self.assertFalse(persisted['reservations']['next-steady']['initialization'])
        self.assertTrue(persisted['reservations']['complete-before-exit']['initialization'])
        self.assertGreater(persisted['git_cost']['steady_daily_bytes'][DAY], 0)

    def test_unresolved_publication_survives_utc_rollover_without_refund(self):
        candidate, measured = self.prepare(self.ledger, 'unresolved', 'data', {'record.json': b'not pushed'})
        self.ledger.settle('unresolved', 0, 0, published=False, runner_seconds=0)
        before = self.ledger.read()[1]
        next_day = self.fresh(day='2026-09-10')
        state = next_day.read()[1]
        intent = state['reservations']['unresolved']
        self.assertEqual(intent['status'], 'publication_unresolved')
        self.assertEqual(intent['day'], DAY)
        self.assertEqual(intent['git_publication']['candidate'], candidate)
        self.assertEqual(intent['git_publication']['compressed_upper_bound_bytes'], measured['actual_pack_bytes'])
        self.assertEqual(state['git_cost']['accounted_upper_bound_bytes'], before['git_cost']['accounted_upper_bound_bytes'])
        next_day.reserve('new-day', 8)
        persisted = self.fresh('runner-three', '2026-09-10').read()[1]
        self.assertIn('unresolved', persisted['reservations'])
        self.assertEqual(persisted['reservations']['unresolved']['git_publication'], intent['git_publication'])

    def test_baseline_completion_requires_committed_complete_data_and_never_resets(self):
        self.publish(self.ledger, 'partial', 'data', {'record.json': b'partial'}, complete=False)
        self.assertIsNone(self.ledger.read()[1]['git_cost']['baseline_completed_at'])
        self.publish(self.ledger, 'complete', 'data', {'record.json': b'complete'}, complete=True)
        self.assertEqual(self.ledger.read()[1]['git_cost']['baseline_completed_at'], NOW)
        self.ledger.reserve('later-failure', 10, bootstrap=True)
        self.ledger.settle('later-failure', 10, 1, published=False, baseline_complete=False, runner_seconds=1)
        state = self.fresh().read()[1]
        self.assertEqual(state['git_cost']['baseline_completed_at'], NOW)
        self.assertFalse(state['reservations']['later-failure']['initialization'])
        self.assertFalse(self.fresh('runner-three').initializing())

    def test_unpushed_or_non_data_work_cannot_claim_baseline_completion(self):
        self.ledger.reserve('phantom', 8)
        self.ledger.settle('phantom', 0, 0, published=True, baseline_complete=True, runner_seconds=1)
        self.assertIsNone(self.ledger.read()[1]['git_cost']['baseline_completed_at'])
        self.publish(self.ledger, 'code-only', 'main', {'README.md': b'code'}, complete=True)
        self.assertIsNone(self.ledger.read()[1]['git_cost']['baseline_completed_at'])
        self.prepare(self.ledger, 'unpushed', 'data', {'record.json': b'not published'})
        self.ledger.settle('unpushed', 0, 0, published=True, baseline_complete=True, runner_seconds=0)
        self.assertIsNone(self.ledger.read()[1]['git_cost']['baseline_completed_at'])

    def test_complete_noop_requires_exact_accounted_data_tip(self):
        tip, _ = self.publish(self.ledger, 'partial', 'data', {'record.json': b'fixed snapshot'})
        self.ledger.reserve('wrong-tip', 0, publication_only=True)
        self.ledger.settle('wrong-tip', 0, 0, baseline_complete=True,
            baseline_data_commit='a' * 40, runner_seconds=0)
        self.assertIsNone(self.ledger.read()[1]['git_cost']['baseline_completed_at'])
        self.ledger.reserve('complete-noop', 0, publication_only=True)
        self.ledger.settle('complete-noop', 0, 0, baseline_complete=True,
            baseline_data_commit=tip, runner_seconds=0)
        state = self.fresh().read()[1]
        self.assertEqual(state['git_cost']['baseline_completed_at'], NOW)
        self.assertEqual(state['git_cost']['accounted_refs']['refs/heads/data'], tip)
        self.assertNotIn('git_publication', state['reservations']['complete-noop'])
        before = state['git_cost']['accounted_upper_bound_bytes']
        self.ledger.settle('complete-noop', 0, 0, baseline_complete=True,
            baseline_data_commit=tip, runner_seconds=0)
        self.assertEqual(self.ledger.read()[1]['git_cost']['accounted_upper_bound_bytes'], before)

    def test_full_changed_file_metric_above_one_mib_does_not_replace_small_pack_cost(self):
        self.publish(self.ledger, 'baseline', 'data', {'record.json': b'baseline'}, complete=True)
        payload = b'repeated-json-value\n' * 80000
        self.assertGreater(len(payload), self.policy['daily_git_change_bytes'])
        _, measured = self.publish(self.ledger, 'steady', 'data', {'record.json': payload})
        state = self.fresh().read()[1]
        self.assertLess(measured['actual_pack_bytes'], 16384)
        self.assertEqual(state['git_cost']['full_changed_file_bytes']['steady'], len(payload))
        self.assertLess(state['git_cost']['steady_daily_bytes'][DAY], self.policy['daily_git_change_bytes'])
        self.assertEqual(state['reservations']['steady']['git_publication']['full_changed_file_bytes'], len(payload))

    def test_existing_legacy_history_requires_migration(self):
        self.store.publish('control', None, {'ledger.json': canonical({'day': DAY,
            'history_upper_bound_bytes': 1234, 'reservations': {}})}, 'legacy')
        with self.assertRaisesRegex(CostMigrationRequired, 'needs bounded compressed-object audit'):
            self.fresh().read()

    def test_migration_preserves_legacy_http_and_runner_quotas_and_separate_metrics(self):
        rows, cutoffs = [], {}
        legacy = {'schema_version': '1.0', 'day': DAY, 'runner_month': DAY[:7], 'runner_minutes_used': 37,
            'history_upper_bound_bytes': 9999999, 'daily_history': {DAY: 777777},
            'reservations': {'old-job': {'charged_bytes': 123, 'reserved_bytes': 200, 'status': 'reserved',
                'started_at': NOW, 'reserved_minutes': 12, 'requests': 2}}}
        for branch, files in (('main', {'README.md': b'legacy code'}),
                ('data', {'record.json': b'legacy data'}), ('control', {'ledger.json': canonical(legacy)})):
            tips = self.store.observe_heads()
            candidate, _ = self.store.prepare(branch, None, files, 'legacy ' + branch)
            measured = measure_increment(self.store.path, candidate, tips, baseline_complete=True)
            self.store.push_prepared(branch, candidate)
            cutoffs[branch] = candidate
            rows.append({'phase': 'initialization', 'day': DAY, 'measurement': measured})
        report = {'complete': True, 'cutoffs': cutoffs, 'commits': rows, 'baseline_completed_at': None}
        self.ledger.migrate(report)
        state = self.fresh().read()[1]
        self.assertEqual(state['runner_minutes_used'], 37)
        self.assertEqual(state['reservations']['old-job']['charged_bytes'], 123)
        self.assertEqual(state['reservations']['old-job']['reserved_bytes'], 200)
        self.assertEqual(state['legacy_git_cost']['counters']['history_upper_bound_bytes'], 9999999)
        self.assertEqual(state['legacy_git_cost']['counters']['daily_history'], {DAY: 777777})
        self.assertEqual(state['git_cost']['accounted_upper_bound_bytes'],
                         sum(row['measurement']['actual_pack_bytes'] for row in rows) +
                         sum(row['charged_upper_bound_bytes'] for row in self.ledger.control_measurements))
        self.assertNotEqual(state['git_cost']['accounted_upper_bound_bytes'], 9999999)
        self.assertEqual(state['git_cost']['migration']['commit_count'], 3)

    def test_http_migrated_same_day_charge_reduces_new_bootstrap_allocation(self):
        self.policy.update(job_bytes=20, daily_bytes=10)
        legacy = {'day': DAY, 'runner_month': DAY[:7], 'runner_minutes_used': 1,
            'history_upper_bound_bytes': 1000, 'reservations': {'legacy-normal': {
                'charged_bytes': 7, 'reserved_bytes': 10, 'status': 'settled',
                'started_at': NOW, 'reserved_minutes': 12, 'requests': 1, 'bootstrap': False}}}
        candidate, _ = self.store.prepare('control', None, {'ledger.json': canonical(legacy)}, 'legacy HTTP charge')
        measured = measure_increment(self.store.path, candidate, {}, baseline_complete=True)
        self.store.push_prepared('control', candidate)
        self.ledger.migrate({'complete': True, 'cutoffs': {'main': None, 'data': None, 'control': candidate},
            'commits': [{'phase': 'initialization', 'day': DAY, 'measurement': measured}],
            'baseline_completed_at': None})
        fresh = self.fresh()
        self.assertEqual(fresh.reserve('new-bootstrap', 20, bootstrap=True), 13)
        state = fresh.read()[1]
        self.assertEqual(state['reservations']['legacy-normal']['charged_bytes'], 7)
        self.assertEqual(state['reservations']['new-bootstrap']['charged_bytes'], 13)
        self.assertEqual(sum(item['charged_bytes'] for item in state['reservations'].values()), 20)
        with self.assertRaisesRegex(BudgetExceeded, 'daily byte budget exhausted'):
            self.fresh('runner-three').reserve('another-bootstrap', 1, bootstrap=True)

    def test_http_initialization_to_steady_transition_retains_same_day_usage(self):
        self.policy.update(job_bytes=20, daily_bytes=10)
        self.assertEqual(self.ledger.reserve('initial-http', 7, bootstrap=True), 7)
        self.ledger.settle('initial-http', 7, 1, bootstrap=True, runner_seconds=1)
        self.publish(self.ledger, 'complete-baseline', 'data', {'record.json': b'complete'}, complete=True)
        fresh = self.fresh()
        self.assertFalse(fresh.initializing())
        self.assertEqual(fresh.reserve('steady-http', 10, bootstrap=False), 3)
        state = fresh.read()[1]
        self.assertTrue(state['reservations']['initial-http']['initialization'])
        self.assertFalse(state['reservations']['steady-http']['initialization'])
        self.assertEqual(sum(item['charged_bytes'] for item in state['reservations'].values()), 10)
        with self.assertRaisesRegex(BudgetExceeded, 'daily byte budget exhausted'):
            self.fresh('runner-three').reserve('steady-exhausted', 1, bootstrap=False)

    def test_unknown_external_data_publication_is_rejected(self):
        original, _ = self.publish(self.ledger, 'baseline', 'data', {'record.json': b'baseline'}, complete=True)
        outsider = GitStore(self.root / 'outside', str(self.remote))
        outsider.read('data')
        outsider.publish('data', original, {'record.json': b'external'}, 'unaccounted external update')
        with self.assertRaisesRegex(CostMigrationRequired, 'unaccounted data publication'):
            self.fresh().read()

    def test_unmetered_control_append_reusing_previous_ledger_is_rejected(self):
        self.ledger.reserve('accounted', 128)
        outsider = GitStore(self.root / 'outside-control', str(self.remote))
        parent, files = outsider.read('control')
        old_ledger = files['ledger.json']
        files['unmetered.json'] = b'unaccounted control data\n' * 1000
        candidate, changed = outsider.publish('control', parent, files, 'unmetered external append')
        self.assertTrue(changed)
        self.assertNotEqual(candidate, parent)
        _, published = outsider.read('control')
        self.assertEqual(published['ledger.json'], old_ledger)
        with self.assertRaisesRegex(CostMigrationRequired, 'unaccounted control publication'):
            self.fresh().read()

    def test_unknown_remote_branch_is_rejected_instead_of_omitted_from_cost(self):
        self.ledger.reserve('one', 1)
        control = self.store.observe_heads()['refs/heads/control']
        self.store.run('push', str(self.remote), control + ':refs/heads/unexpected')
        with self.assertRaisesRegex(ValueError, 'unexpected remote branch'):
            self.fresh().read()

    def test_exact_steady_day_history_and_initialization_inclusive_month_limits(self):
        self.ledger.reserve('one', 1)
        cost = copy.deepcopy(self.ledger.read()[1]['git_cost'])
        cost.update(accounted_upper_bound_bytes=2 * MIB, initialization_month_bytes={},
                    steady_daily_bytes={DAY: MIB})
        self.ledger.guard(cost)
        cost['steady_daily_bytes'][DAY] = MIB + 1
        with self.assertRaisesRegex(BudgetExceeded, 'steady UTC-day'):
            self.ledger.guard(cost)
        cost.update(accounted_upper_bound_bytes=128 * MIB, steady_daily_bytes={})
        with self.assertRaisesRegex(BudgetExceeded, 'history bound'):
            self.ledger.guard(cost)
        cost.update(accounted_upper_bound_bytes=80 * MIB, initialization_month_bytes={DAY[:7]: 75 * MIB},
                    steady_daily_bytes={DAY: MIB})
        with self.assertRaisesRegex(BudgetExceeded, 'monthly projection'):
            self.ledger.guard(cost)
        cost['initialization_month_bytes'][DAY[:7]] = 69 * MIB
        self.ledger.guard(cost)

    def test_control_reservation_also_obeys_budget_and_failed_write_does_not_advance_remote(self):
        self.publish(self.ledger, 'baseline', 'data', {'record.json': b'baseline'}, complete=True)
        before_tip, before = self.ledger.read()
        self.policy['daily_git_change_bytes'] = before['git_cost']['steady_daily_bytes'].get(DAY, 0) + 1
        with self.assertRaisesRegex(BudgetExceeded, 'steady UTC-day'):
            self.ledger.reserve('denied', 1)
        after_tip, after = self.fresh().read()
        self.assertEqual(after_tip, before_tip)
        self.assertEqual(after['git_cost'], before['git_cost'])
        self.assertNotIn('denied', after['reservations'])


if __name__ == '__main__':
    unittest.main()
