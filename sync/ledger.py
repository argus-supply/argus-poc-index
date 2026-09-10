"""Durable HTTP reservations and separately measured compressed Git costs.

Data/code costs are reserved before push. Control commits carry a conservative
self-reservation whose bound is verified against the exact prepared commit before
push; they never need to embed their own SHA or recursively exact pack length.
"""
from __future__ import annotations

import calendar
import copy
import datetime as dt
import hashlib
import json
import math

from .core import canonical, utcnow
from .gitcost import PACK_PARAMETERS, measure_increment
from .http import BudgetExceeded
from .observations import threshold_observation


class CostMigrationRequired(RuntimeError):
    """Existing or externally changed history has no complete cost baseline."""


def empty_cost():
    return {'metric': 'git-object-cost-v1', 'pack_parameters': PACK_PARAMETERS,
        'accounted_upper_bound_bytes': 0, 'initialization_bytes': 0,
        'initialization_month_bytes': {}, 'steady_daily_bytes': {},
        'full_changed_file_bytes': {'initialization': 0, 'steady': 0},
        'baseline_completed_at': None, 'accounted_refs': {}}


class Ledger:
    """All limits include outstanding reservations, including interrupted pushes."""
    def __init__(self, store, policy, day=None):
        self.store, self.policy = store, policy
        self.day = day or utcnow()[:10]
        self.control_measurements = []

    def read(self, *, migration=False):
        parent, files = self.store.read('control')
        self.health = files.get('health.json')
        ledger = json.loads(files.get('ledger.json', b'{}'))
        old_day = ledger.get('day', self.day)
        ledger.setdefault('reservations', {})
        for item in ledger['reservations'].values():
            item.setdefault('day', old_day)
            item.setdefault('bootstrap', False)
        if old_day != self.day:
            # UTC rollover releases yesterday's HTTP allocation, not unclosed
            # publication cost or its original phase/date attribution.
            ledger['reservations'] = {key: value for key, value in ledger['reservations'].items()
                                      if value.get('status') != 'settled'}
        ledger.update(schema_version='1.0', day=self.day)
        if ledger.get('runner_month') != self.day[:7]:
            ledger.update(runner_month=self.day[:7], runner_minutes_used=0)
        ledger.setdefault('runner_minutes_used', 0)
        if 'git_cost' not in ledger:
            if self.store.observe_heads() and not migration:
                raise CostMigrationRequired('existing history needs bounded compressed-object audit')
            if not migration:
                ledger['git_cost'] = empty_cost()
        if 'git_cost' in ledger:
            cost = ledger['git_cost']
            if cost.get('metric') != 'git-object-cost-v1' or cost.get('pack_parameters') != PACK_PARAMETERS:
                raise CostMigrationRequired('incompatible Git cost measurement version')
            if parent:
                recorded_parent = ledger.get('last_control_charge', {}).get('parent')
                commit = self.store.run('cat-file', 'commit', parent).stdout
                parents = [line[7:].decode() for line in commit.split(b'\n\n', 1)[0].splitlines() if line.startswith(b'parent ')]
                if parents != ([recorded_parent] if recorded_parent else []):
                    raise CostMigrationRequired('unaccounted control publication; audit before collection')
            refs = self.store.observe_heads()
            for branch in ('main', 'data'):
                ref = 'refs/heads/' + branch
                actual, accounted = refs.get(ref), cost['accounted_refs'].get(ref)
                if actual != accounted:
                    intent = next((item.get('git_publication') for item in ledger['reservations'].values()
                        if item.get('git_publication', {}).get('branch') == branch
                        and item['git_publication'].get('candidate') == actual), None)
                    if not intent:
                        raise CostMigrationRequired('unaccounted ' + branch + ' publication; audit before collection')
                    cost['accounted_refs'][ref] = actual
                    if (branch == 'data' and intent.get('baseline_complete') and intent.get('baseline_gate_version', 1) >= 2
                            and intent.get('candidate') not in cost.get('invalidated_baseline_candidates', [])
                            and cost['baseline_completed_at'] is None):
                        cost['baseline_completed_at'] = intent['reserved_at']
            cost['steady_daily_bytes'] = {day: value for day, value in cost['steady_daily_bytes'].items()
                                           if day.startswith(self.day[:7])}
            cost['initialization_month_bytes'] = {month: value for month, value in cost['initialization_month_bytes'].items()
                                                 if month == self.day[:7]}
        return parent, ledger

    def initializing(self):
        return self.read()[1]['git_cost']['baseline_completed_at'] is None

    def files(self, ledger, health=None):
        files = {'ledger.json': canonical(ledger)}
        current = canonical(health) if health is not None else self.health
        if current:
            threshold_observation('control_health_bytes', len(current), 65536)
            files['health.json'] = current
        threshold_observation('control_tree_bytes', sum(map(len, files.values())),
                              self.policy['git_control_max_bytes'])
        return files

    def measure(self, candidate, tips):
        """Account all local candidate objects without enforcing capacity targets."""
        return measure_increment(self.store.path, candidate, tips, baseline_complete=True,
            max_objects=None, max_raw_bytes=None, max_object_bytes=None,
            max_pack_bytes=None, metadata_limit=None)

    def charge(self, cost, amount, initialization, day=None):
        day = day or self.day
        cost['accounted_upper_bound_bytes'] += amount
        if initialization:
            cost['initialization_bytes'] += amount
            month = day[:7]
            cost['initialization_month_bytes'][month] = cost['initialization_month_bytes'].get(month, 0) + amount
        else:
            cost['steady_daily_bytes'][day] = cost['steady_daily_bytes'].get(day, 0) + amount

    def guard(self, cost):
        """Persist advisory Git cost observations without rejecting publication."""
        daily = cost['steady_daily_bytes']
        month = self.day[:7]
        initialization = cost['initialization_month_bytes'].get(month, 0)
        days = calendar.monthrange(int(self.day[:4]), int(self.day[5:7]))[1]
        steady = sum(value for day, value in daily.items() if day.startswith(month))
        observed_days = max(1, len([day for day in daily if day.startswith(month)]))
        projection = initialization + steady / observed_days * days
        cost['capacity_observations'] = [threshold_observation(name, observed, threshold)
            for name, observed, threshold in (
                ('git_history_bytes', cost['accounted_upper_bound_bytes'], self.policy['history_bytes']),
                ('git_steady_daily_bytes', daily.get(self.day, 0), self.policy['daily_git_change_bytes']),
                ('git_monthly_projection_bytes', projection, self.policy['monthly_history_growth_bytes']))]
        return cost['capacity_observations']

    def write(self, parent, ledger, message, *, initialization, health=None):
        from .gitstore import ParentMoved
        tips = self.store.observe_heads()
        if tips.get('refs/heads/control') != parent:
            raise ParentMoved('control parent moved')
        # Solve a verified conservative bound, not an exact self-referential
        # number. Failed candidates remain local and never become budget state.
        allowance = 0
        for _ in range(8):
            candidate_ledger = copy.deepcopy(ledger)
            self.charge(candidate_ledger['git_cost'], allowance, initialization)
            candidate_ledger['last_control_charge'] = {'upper_bound_bytes': allowance,
                'phase': 'initialization' if initialization else 'steady', 'day': self.day,
                'parent': parent, 'metric': 'git-object-cost-v1'}
            self.guard(candidate_ledger['git_cost'])
            candidate, changed = self.store.prepare('control', parent, self.files(candidate_ledger, health), message)
            measured = self.measure(candidate, tips)
            actual = measured['compressed_object_upper_bound_bytes']
            if actual > allowance:
                allowance = actual + self.policy['git_control_reservation_margin_bytes']
                continue
            self.store.push_prepared('control', candidate)
            self.control_measurements.append({'candidate': candidate, 'measured_pack_bytes': actual,
                'charged_upper_bound_bytes': allowance, 'measurement': measured})
            return candidate
        raise RuntimeError('unable to bound control commit cost before push')

    def reserve(self, job_id, requested, *, bootstrap=False, publication_only=False):
        from .gitstore import ParentMoved
        for _ in range(3):
            parent, ledger = self.read()
            if job_id in ledger['reservations']:
                raise BudgetExceeded('job already reserved; use a new run attempt')
            limit = self.policy['job_bytes'] if bootstrap else self.policy['daily_bytes']
            used = sum(item['charged_bytes'] for item in ledger['reservations'].values()
                       if item['day'] == self.day)
            if type(requested) is not int or requested < 0:
                raise ValueError('invalid transfer reservation')
            allocation = requested
            minutes = 0 if publication_only else 12
            runner_limit = self.policy.get('repository_runner_minutes', self.policy['monthly_runner_minutes'])
            ledger['capacity_observations'] = [
                threshold_observation('http_daily_reserved_bytes', used + allocation, limit),
                threshold_observation('runner_monthly_reserved_minutes',
                    ledger['runner_minutes_used'] + minutes, runner_limit)]
            ledger['runner_minutes_used'] += minutes
            ledger['reservations'][job_id] = {'charged_bytes': allocation, 'reserved_bytes': allocation,
                'status': 'reserved', 'started_at': utcnow(), 'day': self.day,
                'bootstrap': bootstrap, 'initialization': ledger['git_cost']['baseline_completed_at'] is None,
                'requests': 0, 'reserved_minutes': minutes}
            try:
                self.write(parent, ledger, 'chore(data): reserve bounded work', initialization=ledger['reservations'][job_id]['initialization'])
                return allocation
            except ParentMoved:
                continue
        raise ParentMoved('budget reservation contention')

    def reserve_publication(self, job_id, branch, candidate, full_changed_bytes, *, baseline_complete=False,
                            baseline_gate_version=2, dependency_coverage=None):
        from .gitstore import ParentMoved
        for _ in range(3):
            parent, ledger = self.read()
            item = ledger['reservations'][job_id]
            if item.get('git_publication'):
                raise BudgetExceeded('publication already reserved for this job')
            tips = self.store.observe_heads()
            measured = self.measure(candidate, tips)
            self.validate_baseline_proof(baseline_complete, baseline_gate_version, dependency_coverage)
            amount = measured['compressed_object_upper_bound_bytes']
            self.charge(ledger['git_cost'], amount, item['initialization'], item['day'])
            item['git_publication'] = {'branch': branch, 'candidate': candidate,
                'parent': tips.get('refs/heads/' + branch), 'compressed_upper_bound_bytes': amount,
                'full_changed_file_bytes': full_changed_bytes, 'measurement': measured,
                'state': 'reserved', 'baseline_complete': bool(baseline_complete and branch == 'data'),
                'reserved_at': utcnow(), 'baseline_gate_version': baseline_gate_version,
                'dependency_coverage': dependency_coverage}
            phase = 'initialization' if item['initialization'] else 'steady'
            ledger['git_cost']['full_changed_file_bytes'][phase] += full_changed_bytes
            try:
                self.write(parent, ledger, 'chore(data): reserve measured publication', initialization=item['initialization'])
                return measured
            except ParentMoved:
                continue
        raise ParentMoved('publication reservation contention')

    def settle(self, job_id, actual_bytes, requests, changed_bytes=0, *, bootstrap=False,
               health=None, runner_seconds=720, published=False, baseline_complete=False, baseline_data_commit=None,
               baseline_gate_version=2, dependency_coverage=None):
        from .gitstore import ParentMoved
        for _ in range(3):
            parent, ledger = self.read()
            item = ledger['reservations'].get(job_id)
            if not item:
                raise ValueError('missing daily reservation')
            if item['status'] == 'settled':
                return
            if type(actual_bytes) is not int or actual_bytes < 0:
                raise ValueError('invalid actual transfer measurement')
            item['transfer_observation'] = threshold_observation(
                'http_job_bytes', actual_bytes, item['reserved_bytes'])
            item.update(charged_bytes=actual_bytes, requests=requests, completed_at=utcnow())
            intent = item.get('git_publication')
            if intent:
                observed = self.store.observe_heads().get('refs/heads/' + intent['branch'])
                if observed == intent['candidate']:
                    intent['state'] = 'committed'
                    ledger['git_cost']['accounted_refs']['refs/heads/' + intent['branch']] = observed
                else:
                    # A failed connection can hide a successful push. Its cost
                    # remains reserved across days; never refund on uncertainty.
                    intent['state'] = 'unresolved'
            item['status'] = 'settled' if not intent or intent['state'] == 'committed' else 'publication_unresolved'
            actual_minutes = max(1, math.ceil(runner_seconds / 60)) if item['reserved_minutes'] else 0
            if 'runner_minutes' not in item and item['day'].startswith(ledger['runner_month']):
                ledger['runner_minutes_used'] -= item['reserved_minutes'] - actual_minutes
            item['runner_minutes'] = actual_minutes
            # A recovery must not start a second initialization exemption.
            self.validate_baseline_proof(baseline_complete, baseline_gate_version, dependency_coverage)
            data_tip = self.store.observe_heads().get('refs/heads/data')
            proven_publication = bool(published and intent and intent['branch'] == 'data' and intent['state'] == 'committed')
            proven_noop = bool(baseline_data_commit and data_tip == baseline_data_commit
                and ledger['git_cost']['accounted_refs'].get('refs/heads/data') == baseline_data_commit)
            if baseline_complete and baseline_gate_version >= 2 and (proven_publication or proven_noop) and item['status'] == 'settled' and ledger['git_cost']['baseline_completed_at'] is None:
                ledger['git_cost']['baseline_completed_at'] = utcnow()
            try:
                self.write(parent, ledger, 'chore(data): settle measured work', initialization=item['initialization'], health=health)
                return
            except ParentMoved:
                continue
        raise ParentMoved('budget settlement contention')

    @staticmethod
    def validate_baseline_proof(complete, version, coverage):
        if type(version) is not int or version != 2:
            raise ValueError('unsupported baseline gate version')
        if complete and coverage is not None:
            if not isinstance(coverage, dict) or not coverage or any(
                    not isinstance(proof, dict) or proof.get('coverage_complete') is not True
                    for proof in coverage.values()):
                raise ValueError('complete baseline requires complete pinned dependencies')

    def correct_incomplete_dependency_baseline(self, expected_data_sha, proofs):
        """Append an evidence-bound correction without refunding any incurred cost.

        Only a published PoC baseline referencing an incomplete fixed intel
        manifest qualifies. Historical success and the old marker remain in the
        correction record; even prior steady charges are conservatively retained.
        """
        from .core import validate
        parent, ledger = self.read()
        sha, files = self.store.read('data')
        if sha != expected_data_sha:
            raise CostMigrationRequired('data changed before baseline correction')
        manifest = json.loads(files['manifest.json'])
        if manifest['repository'] != 'argus-supply/argus-poc-index':
            raise ValueError('dependency baseline correction is scoped to PoC')
        dependencies = {item['repository']: item for item in manifest.get('dependencies', [])}
        evidence = []
        for proof in proofs:
            if proof.get('repository') != 'argus-supply/argus-intel-data':
                raise ValueError('baseline correction requires the configured intel dependency')
            dependency = dependencies.get(proof['repository'])
            body = proof['manifest_bytes']
            if (not dependency or dependency['commit_sha'] != proof['commit_sha']
                    or hashlib.sha256(body).hexdigest() != dependency['manifest_sha256']):
                raise ValueError('baseline correction dependency proof mismatch')
            source_manifest = json.loads(body)
            validate('manifest', source_manifest)
            if source_manifest['repository'] != proof['repository']:
                raise ValueError('dependency proof belongs to another repository')
            states = source_manifest['sources']
            complete = all(states.get(name, {}).get('status') == 'ok'
                and states[name].get('completed_watermark') and not states[name].get('continuation')
                and not states[name].get('coverage_gaps') and not states[name].get('errors')
                for name in ('cve', 'ghsa', 'kev'))
            if not complete:
                evidence.append({**dependency, 'coverage_complete': False})
        if not evidence:
            raise ValueError('no incomplete pinned dependency was proven')
        cost = ledger['git_cost']
        if not cost['baseline_completed_at']:
            raise ValueError('no completed baseline marker to correct')
        threshold_observation('baseline_correction_count', len(cost.get('baseline_corrections', [])) + 1, 4)
        before = cost['accounted_upper_bound_bytes']
        correction = {'at': utcnow(), 'data_commit': sha, 'invalidated_completed_at': cost['baseline_completed_at'],
            'replacement_completed_at': None, 'gate_version': 2, 'dependencies': evidence,
            'reason': 'own-source success was incorrectly treated as full baseline despite incomplete pinned intel',
            'accounted_bytes_before': before, 'cost_refund_bytes': 0,
            'prior_steady_charges_retained': copy.deepcopy(cost['steady_daily_bytes'])}
        cost.setdefault('baseline_corrections', []).append(correction)
        cost.setdefault('invalidated_baseline_candidates', []).append(sha)
        cost['baseline_completed_at'] = None
        result = self.write(parent, ledger, 'fix(data): correct incomplete dependency baseline claim', initialization=True)
        return {'control_sha': result, 'correction': correction, 'control_measurements': self.control_measurements}

    def publication_allowed(self, proposed_bytes, *, bootstrap=False):
        _, ledger = self.read()
        cost = copy.deepcopy(ledger['git_cost'])
        self.charge(cost, proposed_bytes, bootstrap)
        try:
            self.guard(cost)
            return True
        except BudgetExceeded:
            return False

    def migrate(self, report):
        """Install a complete bounded audit without resetting legacy work quotas."""
        parent, ledger = self.read(migration=True)
        if 'git_cost' in ledger:
            raise ValueError('Git cost migration already applied')
        tips = self.store.observe_heads()
        expected = {'refs/heads/' + key: value for key, value in report['cutoffs'].items() if value}
        if not report.get('complete') or tips != expected:
            raise CostMigrationRequired('audit is incomplete or remote cutoffs changed')
        cost = empty_cost()
        for row in report['commits']:
            measured = row['measurement']
            if measured['pack_parameters'] != PACK_PARAMETERS:
                raise ValueError('history audit uses incompatible compression parameters')
            amount = measured['compressed_object_upper_bound_bytes']
            if type(amount) is not int or amount < 0 or amount != measured['actual_pack_bytes']:
                raise ValueError('invalid measured historical object bytes')
            self.charge(cost, amount, row['phase'] == 'initialization', row['day'])
        legacy_full = report.get('legacy_data_full_changed_file_bytes', 0)
        if type(legacy_full) is not int or legacy_full < 0:
            raise ValueError('invalid legacy rewrite diagnostic')
        cost['full_changed_file_bytes']['initialization'] = legacy_full
        cost['full_changed_file_bytes_scope'] = 'legacy data publications plus post-migration main/data candidates; outstanding intents are conservative'
        cost['accounted_refs'] = {ref: sha for ref, sha in tips.items() if not ref.endswith('/control')}
        cost['baseline_completed_at'] = report.get('baseline_completed_at')
        cost['migration'] = {'audit_sha256': hashlib.sha256(canonical(report)).hexdigest(),
            'control_cutoff': parent, 'commit_count': len(report['commits']), 'applied_at': utcnow()}
        legacy = {key: ledger.pop(key) for key in ('history_upper_bound_bytes', 'daily_history') if key in ledger}
        ledger['legacy_git_cost'] = {'metric': 'full-changed-files-plus-legacy-overhead', 'counters': legacy,
            'note': 'Preserved, not relabelled or mixed into measured compressed costs.'}
        # Preserve every pre-existing reservation and runner/HTTP charge. Old
        # bootstrap labels are historical evidence, not the new completion gate.
        for item in ledger['reservations'].values():
            item['initialization'] = cost['baseline_completed_at'] is None or item.get('started_at', '') < cost['baseline_completed_at']
        ledger['git_cost'] = cost
        self.write(parent, ledger, 'chore(data): migrate measured Git cost accounting',
                   initialization=cost['baseline_completed_at'] is None)
