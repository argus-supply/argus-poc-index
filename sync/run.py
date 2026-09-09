"""Standalone runner: reserve, resume adapters, validate, CAS publish, settle."""
from __future__ import annotations

import argparse
import copy
import json
import os
from pathlib import Path
import time

from .adapters import AdapterResult, collect
from .core import ROOT, apply_result, build_snapshot, canonical, digest, expire, load_policy, read_snapshot, utcnow
from .gitstore import GitStore, Ledger, ParentMoved
from .ledger import CostMigrationRequired
from .http import BudgetExceeded, Http
from .dependency import consume_intel
from .availability import refresh as refresh_reference_availability

REPOSITORIES = ('argus-intel-data', 'argus-poc-index', 'argus-detection-resources')


def run(repository, remote, work, job_id, *, policy, token=None, manual=False, http=None):
    if repository not in REPOSITORIES:
        raise ValueError('repository is outside authorized publisher scope')
    policy = {**policy, 'repository_runner_minutes': policy['runner_minutes_by_repository'][repository]}
    started = time.monotonic()
    now = utcnow()
    store = GitStore(work / 'git', remote, token)
    parent, before_files = store.read('data')
    records, events, sources, previous = read_snapshot(before_files)
    registry = json.loads((ROOT / 'sources.json').read_text())
    enabled = [item for item in registry['sources'] if item['repository'].split('/')[-1] == repository]
    enabled.sort(key=lambda item: policy['source_order'].index(item['id']))
    ledger = Ledger(store, policy)
    try:
        git_initializing = ledger.initializing()
        bootstrap = not previous or any(not sources.get(item['id'], {}).get('completed_watermark') for item in enabled)
    except CostMigrationRequired as error:
        return {'schema_version': '1.0', 'repository': 'argus-supply/' + repository, 'job_id': job_id,
            'started_at': now, 'status': 'partial', 'published': False, 'data_commit': parent,
            'error': str(error), 'git_cost_migration_required': True}
    metrics = {'schema_version': '1.0', 'repository': 'argus-supply/' + repository,
        'job_id': job_id, 'started_at': now, 'status': 'partial', 'data_parent': parent,
        'bootstrap': bootstrap, 'git_initialization': git_initializing, 'sources': {}, 'data_commit': parent, 'published': False}
    try:
        reservation = ledger.reserve(job_id, policy['job_bytes'], bootstrap=bootstrap)
    except BudgetExceeded as error:
        metrics['error'] = str(error)
        metrics['elapsed_seconds'] = time.monotonic() - started
        return metrics
    client = http or Http(policy, token=token, max_bytes=reservation)
    results, dependencies, dependency = {}, [], None
    dependency_cache, dependency_files = {}, {}
    changed_bytes = 0
    baseline_complete = False
    try:
        if repository == 'argus-poc-index':
            requested = {state.get('continuation', {}).get('intel_commit_sha') for state in sources.values()
                         if isinstance(state.get('continuation'), dict)} - {None}
            if len(requested) > 1:
                raise ValueError('conflicting pinned intel continuations')
            dependency, dependency_cache, dependency_files = consume_intel(client, next(iter(requested), None), previous, before_files)
            dependencies = [{k: dependency[k] for k in ('repository', 'commit_sha', 'manifest_sha256')}]
            # All dependency HTTP transfers consume the same durable reservation.
            metrics['dependency_current_bytes'] = sum(map(len, dependency_files.values()))
        for index, registration in enumerate(enabled):
            source_id = registration['id']
            remaining = len(enabled) - index
            local = client.fork(max_bytes=max(0, (reservation - client.bytes) // remaining),
                max_requests=max(0, (policy['job_requests'] - client.requests) // remaining))
            try:
                result = collect(source_id, local,
                    {'records': [row for row in records.values() if row['source_id'] == source_id],
                     'state': sources.get(source_id, {})}, now=now,
                    policy={**policy, 'manual': manual}, dependency=dependency)
            except Exception as error:
                result = AdapterResult(state=copy.deepcopy(sources.get(source_id, {})), status='failed',
                    errors=[{'code': type(error).__name__}], coverage_gaps=['source attempt failed'])
            results[source_id] = result
            apply_result(records, events, sources, source_id, result, now, policy)
            sources[source_id].update(bytes=local.bytes, requests=local.requests)
            metrics['sources'][source_id] = {'status': sources[source_id]['status'],
                'bytes': local.bytes, 'requests': local.requests,
                'coverage_gaps': sources[source_id]['coverage_gaps'], 'errors': sources[source_id]['errors']}
        extra = {'dependency_cache': dependency_cache} if dependency_cache else {}
        if repository == 'argus-poc-index':
            expire(records, events, now, policy)
            checkpoint, metrics['reference_availability'] = refresh_reference_availability(
                records, (previous or {}).get('reference_availability'), client, now, policy)
            extra['reference_availability'] = checkpoint
        provenance_path = ROOT / 'distribution.json'
        version = json.loads(provenance_path.read_text())['source_commit'] if provenance_path.exists() else 'working-tree'
        for attempt in range(3):
            files, manifest = build_snapshot('argus-supply/' + repository, records, events, sources,
                policy, now, version, previous, dependencies,
                extra)
            files.update(dependency_files)
            if sum(map(len, files.values())) > policy['max_tree_bytes']:
                raise ValueError('current data tree including dependency cache exceeds budget')
            changed_bytes = sum(len(value) for key, value in files.items() if before_files.get(key) != value)
            baseline_complete = all(sources.get(item['id'], {}).get('status') == 'ok'
                and sources[item['id']].get('completed_watermark')
                and not sources[item['id']].get('continuation')
                and not sources[item['id']].get('coverage_gaps') for item in enabled)
            candidate, changed = store.prepare('data', parent, files, 'chore(data): synchronize bounded public metadata')
            try:
                if changed:
                    metrics['git_cost'] = ledger.reserve_publication(job_id, 'data', candidate, changed_bytes, baseline_complete=baseline_complete)
                    sha, published = store.push_prepared('data', candidate)
                else:
                    sha, published = parent, False
                    metrics['git_cost'] = {'metric': 'git-object-cost-v1', 'compressed_object_upper_bound_bytes': 0}
                metrics.update(data_commit=sha, published=published, changed_bytes=changed_bytes,
                    current_tree_bytes=sum(map(len, files.values())), manifest_sha256=digest(files['manifest.json']),
                    record_count=len(records), event_count=len(events), dependencies=dependencies,
                    status='ok' if all(s['status'] == 'ok' for s in sources.values()) else 'partial')
                break
            except ParentMoved:
                # A newer publisher may have withdrawn records. Recollect from its
                # current snapshot on the next run instead of replaying stale facts.
                metrics['error'] = 'remote parent moved; next run rereads and recollects current state'
                metrics['status'] = 'partial'
                break
        return metrics
    except Exception as error:
        metrics['error'] = {'code': type(error).__name__, 'message': str(error)[:180]}
        return metrics
    finally:
        metrics.update(completed_at=utcnow(), upstream_bytes=client.bytes, upstream_requests=client.requests,
            decompressed_bytes=client.decompressed_bytes,
            elapsed_seconds=round(time.monotonic() - started, 3))
        health = {'schema_version': '1.0', 'updated_at': utcnow(), 'collection_status': metrics['status'],
            'data_commit': metrics['data_commit'], 'sources': {name: {key: value.get(key) for key in
                ('status', 'last_attempt_at', 'last_success_at', 'coverage_gaps', 'errors')}
                for name, value in sources.items()}}
        try:
            ledger.settle(job_id, client.bytes, client.requests, changed_bytes if metrics['published'] else 0,
                bootstrap=bootstrap, health=health, published=metrics['published'],
                baseline_complete=baseline_complete, baseline_data_commit=metrics['data_commit'],
                runner_seconds=time.time() - float(os.environ.get('ARGUS_JOB_STARTED_AT', time.time() - (time.monotonic() - started))))
        except Exception as error:
            metrics['status'] = 'partial'
            metrics['settlement_error'] = type(error).__name__
            metrics['reservation_retained'] = True
        metrics['git_control_cost'] = ledger.control_measurements
        metrics['git_cost_metric'] = 'git-object-cost-v1'
        metrics['candidate_full_changed_file_bytes'] = changed_bytes
        metrics['full_changed_file_bytes'] = changed_bytes if metrics['published'] else 0
        metrics['baseline_complete'] = baseline_complete


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--repository', choices=REPOSITORIES, required=True)
    parser.add_argument('--work', type=Path, default=Path('.work'))
    parser.add_argument('--report', type=Path, default=Path('.work/run-report.json'))
    parser.add_argument('--manual', action='store_true')
    args = parser.parse_args()
    args.work.mkdir(parents=True, exist_ok=True)
    policy = load_policy(ROOT / 'policy.json')
    if os.environ.get('ARGUS_COLLECT_SECONDS'):
        seconds = int(os.environ['ARGUS_COLLECT_SECONDS'])
        if not 1 <= seconds <= policy['job_seconds']:
            raise ValueError('invalid collector time allocation')
        policy['job_seconds'] = seconds
    job_id = os.environ.get('GITHUB_RUN_ID', 'local-' + str(time.time_ns())) + '-' + os.environ.get('GITHUB_RUN_ATTEMPT', '1')
    result = run(args.repository, 'https://github.com/argus-supply/' + args.repository + '.git', args.work,
        job_id, policy=policy, token=os.environ.get('GH_TOKEN') or os.environ.get('GITHUB_TOKEN'), manual=args.manual)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_bytes(canonical(result))
    summary = os.environ.get('GITHUB_STEP_SUMMARY')
    if summary:
        with open(summary, 'a') as stream:
            stream.write('```json\n' + json.dumps(result, indent=2) + '\n```\n')
    print(json.dumps(result, sort_keys=True))
    if result['status'] != 'ok':
        raise SystemExit(2)


if __name__ == '__main__':
    main()
