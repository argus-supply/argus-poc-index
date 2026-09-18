"""Deterministic records, semantic events, bounded shards and schema validation."""
from __future__ import annotations

import copy
import datetime as dt
import hashlib
import json
import re
from functools import lru_cache
from pathlib import Path

from jsonschema import Draft202012Validator
from .continuations import split_record, assemble_records, MAX_SNAPSHOT_LOGICAL_BYTES
from .observations import threshold_observation

ROOT = Path(__file__).resolve().parents[1]
RECORD_SHARD_TARGET_BYTES = 64 * 1024
CHECKPOINT_MAX_DELTAS = 168
NON_SEMANTIC_FIELDS = frozenset({
    'content_hash', 'first_seen_at', 'source_modified_at', 'observed_at',
    'last_seen_at', 'source_revision', 'upstream_revision', 'source_commit',
    'index_revision', 'intel_commit_sha', 'collected_at', 'fetched_at',
    'derived', 'assessment', 'last_material_event_at',
})
NESTED_REVISION_FIELDS = frozenset({
    'source_revision', 'upstream_revision', 'source_commit', 'index_revision',
    'intel_commit_sha', 'source_index_url', 'collected_at', 'fetched_at',
    'observed_at', 'last_seen_at',
})


def canonical(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':')) + '\n').encode()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def instant(value):
    result = dt.datetime.fromisoformat(value.replace('Z', '+00:00'))
    return result.replace(tzinfo=dt.timezone.utc) if result.tzinfo is None else result


def utcnow():
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec='seconds').replace('+00:00', 'Z')


@lru_cache(maxsize=3)
def validator(kind):
    schema = json.loads((ROOT / 'schemas' / f'{kind}.schema.json').read_text())
    return Draft202012Validator(schema)


def validate(kind, value):
    validator(kind).validate(value)
    if kind == 'manifest' and len(canonical(value.get('reference_availability', {}))) > 65536:
        raise ValueError('reference availability checkpoint exceeds 64 KiB bound')
    if kind == 'manifest':
        for entry in value.get('reference_availability', {}).get('entries', {}).values():
            if instant(entry['next_check_at']) <= instant(entry['checked_at']):
                raise ValueError('invalid reference recheck interval')
        storage = value.get('storage')
        if storage:
            _safe_run_id(storage['checkpoint']['id'])
            descriptors = {item['path']: item for item in value['shards']}
            referenced = [*storage['checkpoint']['shards'], *[
                path for delta in storage['deltas'] for path in delta['shards']]]
            if len(descriptors) != len(value['shards']) or set(referenced) != set(descriptors):
                raise ValueError('storage shard inventory mismatch')
            if len(referenced) != len(set(referenced)):
                raise ValueError('storage shard referenced more than once')
            run_ids = [item['run_id'] for item in storage['deltas']]
            if any(_safe_run_id(item) != item for item in run_ids):
                raise ValueError('invalid delta run identifier')
            if len(set(run_ids)) != len(storage['deltas']):
                raise ValueError('duplicate delta run identifier')
            checkpoint_paths = set(storage['checkpoint']['shards'])
            checkpoint_prefix = 'checkpoints/{}/'.format(storage['checkpoint']['id'])
            if any(not path.startswith(checkpoint_prefix) for path in checkpoint_paths):
                raise ValueError('checkpoint shard path does not match checkpoint identifier')
            previous_created_at = instant(storage['checkpoint']['created_at'])
            for delta in storage['deltas']:
                created_at = instant(delta['created_at'])
                if created_at < previous_created_at:
                    raise ValueError('delta batches are not chronologically ordered')
                previous_created_at = created_at
                prefix = 'deltas/{}/'.format(delta['run_id'])
                if any(not path.startswith(prefix) for path in delta['shards']):
                    raise ValueError('delta shard path does not match run identifier')
            for item in value['shards']:
                if any(part in ('', '.', '..') for part in item['path'].split('/')):
                    raise ValueError('unsafe storage shard path')
                operation = item.get('operation')
                if item['path'] in checkpoint_paths and operation != 'snapshot':
                    raise ValueError('checkpoint shard must use snapshot operation')
                if item['path'] not in checkpoint_paths and operation == 'snapshot':
                    raise ValueError('delta shard cannot use snapshot operation')
                if item['kind'] == 'events' and operation not in ('snapshot', 'append'):
                    raise ValueError('invalid event shard operation')
                if item['kind'] == 'records' and operation not in ('snapshot', 'upsert', 'delete'):
                    raise ValueError('invalid record shard operation')
                if operation == 'upsert' and '/records/upserts/' not in item['path']:
                    raise ValueError('record upsert operation/path mismatch')
                if operation == 'delete' and '/records/deletes/' not in item['path']:
                    raise ValueError('record delete operation/path mismatch')
                if operation == 'append' and '/events/' not in item['path']:
                    raise ValueError('event append operation/path mismatch')


def load_policy(path):
    from .availability import validate_policy
    policy = json.loads(Path(path).read_text())
    validate_policy(policy)
    if policy.get('git_cost_metric') != 'git-object-cost-v1' or policy.get('git_initialization_accounting') != 'separate':
        raise ValueError('unsupported Git accounting policy')
    for key in ('git_control_max_bytes', 'git_control_reservation_margin_bytes'):
        if type(policy.get(key)) is not int or policy[key] <= 0:
            raise ValueError('invalid Git accounting bound: ' + key)
    ceilings = {'max_record_bytes': 16384, 'max_shard_bytes': 524288,
        'max_tree_bytes': 33554432, 'job_seconds': 720, 'job_requests': 500,
        'job_bytes': 67108864, 'daily_bytes': 10485760, 'consumer_daily_bytes': 4194304,
        'history_bytes': 134217728, 'monthly_history_growth_bytes': 104857600,
        'monthly_runner_minutes': 900, 'max_pocs_per_vulnerability': 100,
        'max_source_state_bytes': 524288}
    for key in ceilings:
        if type(policy.get(key)) is not int or policy[key] <= 0:
            raise ValueError(f'invalid policy threshold: {key}')
    if ('record_shard_bytes' in policy and
            (type(policy['record_shard_bytes']) is not int
             or not 0 < policy['record_shard_bytes'] <= RECORD_SHARD_TARGET_BYTES)):
        raise ValueError('invalid record shard target')
    if ('checkpoint_max_deltas' in policy and
            (type(policy['checkpoint_max_deltas']) is not int
             or not 0 < policy['checkpoint_max_deltas'] <= 10000)):
        raise ValueError('invalid checkpoint delta bound')
    if policy['max_record_bytes'] > 16384:
        raise ValueError('physical record protocol ceiling exceeded')
    if policy.get('schema_version') != '1.0' or not policy.get('policy_version'):
        raise ValueError('unsupported policy version')
    for key in ('retention_days', 'event_days', 'bootstrap_days', 'overlap_hours', 'reconcile_hours',
                'http_timeout_seconds', 'http_retry_after_max_seconds'):
        if type(policy.get(key)) is not int or policy[key] <= 0:
            raise ValueError(f'invalid policy setting: {key}')
    if policy['bootstrap_days'] > policy['retention_days']:
        raise ValueError('bootstrap exceeds retained window')
    allocations = policy['runner_minutes_by_repository']
    if any(type(value) is not int or value <= 0 for value in allocations.values()):
        raise ValueError('invalid per-repository runner allocation')
    if len(policy['source_order']) != len(set(policy['source_order'])):
        raise ValueError('duplicate source in fair collection order')
    return policy


def semantic(record):
    """Return facts whose changes warrant a new record version and event.

    Collection revisions remain on stored records for provenance, but must not
    make an unchanged upstream body look like a semantic update.
    """
    def without_revisions(value):
        if isinstance(value, dict):
            return {key: without_revisions(item) for key, item in value.items()
                    if key not in NESTED_REVISION_FIELDS}
        if isinstance(value, list):
            return [without_revisions(item) for item in value]
        return copy.deepcopy(value)

    result = {key: without_revisions(value) for key, value in record.items()
              if key not in NON_SEMANTIC_FIELDS}
    for item in result.get('provenance', []):
        if isinstance(item, dict):
            item.pop('revision', None)
            # Immutable collection URLs carry the same revision already removed
            # above; stable public record URLs remain in the record body.
            item.pop('url', None)
    return result


def event_types(old, new):
    if old is None:
        proof = new.get('bootstrap_material_change')
        if proof:
            types = {'affected': 'affected_corrected', 'scores': 'score_changed', 'metrics': 'score_changed',
                     'status': 'rejected' if new.get('status') == 'rejected' else
                               'disclosure' if new.get('status') == 'active' else 'withdrawn'}
            return sorted({types[key] for key in proof['changed_fields'] if key in types})
        if new.get('kev') or new['source_id'] == 'kev':
            return ['kev_added']
        return [{'advisory': 'disclosure', 'poc': 'poc_added', 'resource': 'template_added'}[new['kind']]]
    result = []
    if old.get('status') != new.get('status'):
        status = new.get('status')
        if status in ('withdrawn', 'rejected', 'source_deleted', 'retention_removed'):
            result.append(status)
        elif old.get('status') in ('withdrawn', 'rejected', 'source_deleted'):
            result.append('disclosure' if new['kind'] == 'advisory' else
                          'poc_changed' if new['kind'] == 'poc' else 'template_logic_changed')
    if old.get('kev') != new.get('kev'):
        result.append('kev_added' if new.get('kev') else 'kev_removed')
    if old.get('affected') != new.get('affected'):
        result.append('affected_corrected')
    if any(old.get(key) != new.get(key) for key in ('scores', 'severity', 'metrics')) or (
            [x.get('metrics') for x in old.get('assertions', [])] !=
            [x.get('metrics') for x in new.get('assertions', [])]):
        result.append('score_changed')
    if new['kind'] == 'poc' and semantic(old) != semantic(new):
        result.append('poc_changed')
    if new['kind'] == 'resource':
        if old.get('requirements') != new.get('requirements') or old.get('dependencies') != new.get('dependencies'):
            result.append('template_requirements_changed')
        if old.get('sha256') != new.get('sha256'):
            result.append('template_logic_changed')
    return sorted(set(result))


def make_event(old, new, event_type, revision, now, policy):
    identity = [new['record_id'], old.get('content_hash') if old else None,
                new['content_hash'], event_type, revision, policy['policy_version']]
    result = {'schema_version': '1.0', 'event_id': digest(canonical(identity)),
        'record_id': new['record_id'], 'event_type': event_type,
        'previous_hash': identity[1], 'content_hash': new['content_hash'],
        'source_revision': revision, 'source_occurred_at': new.get('published_at') if event_type == 'disclosure' else new.get('source_modified_at'),
        'observed_at': now, 'policy_version': policy['policy_version']}
    if new.get('bootstrap_material_change'):
        proof = new['bootstrap_material_change']
        result['source_occurred_at'] = None
        result['source_occurrence_window'] = {'from': proof['window_start'], 'to': proof['window_end'],
                                              'baseline_revision': proof['baseline_revision']}
    validate('event', result)
    return result


def apply_result(records, events, sources, source_id, result, now, policy):
    """Commit completed units; schema/size exceptions retain the source's old watermark."""
    prior = sources.get(source_id, {})
    before = {key: value for key, value in records.items() if value['source_id'] == source_id}
    errors, gaps = list(result.errors), list(result.coverage_gaps)
    invalid = False
    for incoming in result.records:
        new = copy.deepcopy(incoming)
        key = new['record_id']
        old = records.get(key)
        new['schema_version'] = '1.0'
        new['first_seen_at'] = old['first_seen_at'] if old else now
        new['content_hash'] = digest(canonical(semantic(new)))
        # An unchanged upstream body must not refresh every record's timestamps.
        if old and new['content_hash'] == old['content_hash']:
            continue
        try:
            validate('record', new)
            split_record(new, max_record_bytes=policy['max_record_bytes'])
        except Exception as error:
            invalid = True
            errors.append({'record_id': key, 'code': type(error).__name__, 'bytes': len(canonical(new))})
            gaps.append({'record_id': key, 'reason': 'invalid_or_oversize_record'})
            continue
        types = event_types(old, new)
        new['last_material_event_at'] = now if types else (old or {}).get('last_material_event_at')
        for kind in types:
            event = make_event(old, new, kind, result.revision, now, policy)
            events.setdefault(event['event_id'], event)
        records[key] = new
    # Only a completed enumeration proves source deletion.
    if result.authoritative_ids is not None and result.status == 'ok' and not invalid:
        for key in before.keys() - set(result.authoritative_ids):
            old = records[key]
            status = 'kev_removed' if source_id == 'kev' else 'source_deleted'
            if old.get('status') == 'source_deleted':
                continue
            new = dict(old, status='source_deleted', source_modified_at=now, last_material_event_at=now)
            if source_id == 'kev':
                new['kev'] = False
            new['content_hash'] = digest(canonical(semantic(new)))
            event = make_event(old, new, status, result.revision, now, policy)
            events.setdefault(event['event_id'], event)
            records[key] = new
    state = {**result.state, 'revision': result.revision, 'status': 'partial' if invalid else result.status,
        'completed_watermark': prior.get('completed_watermark') if invalid else result.completed_watermark,
        'continuation': prior.get('continuation') if invalid else result.continuation,
        'coverage_gaps': gaps, 'errors': errors, 'last_attempt_at': now,
        'last_success_at': now if result.status == 'ok' and not invalid else prior.get('last_success_at')}
    if invalid:
        # Restart the same source window; valid units converge by content hash.
        state = {**prior, **{k: state[k] for k in ('status', 'coverage_gaps', 'errors', 'last_attempt_at')}}
    threshold_observation('source_state_bytes', len(canonical(state)), policy['max_source_state_bytes'])
    sources[source_id] = state


def expire(records, events, now, policy):
    cutoff = instant(now) - dt.timedelta(days=policy['retention_days'])
    event_cutoff = instant(now) - dt.timedelta(days=policy['event_days'])
    active_aliases = {alias for record in records.values() if record.get('kev')
                      for alias in record.get('aliases', [])}
    for key, old in list(records.items()):
        if old['kind'] == 'resource' or old.get('kev') or active_aliases.intersection(old.get('aliases', [])):
            continue
        dates = [instant(old[field]) for field in ('published_at', 'last_material_event_at') if old.get(field)]
        if not dates or max(dates) >= cutoff:
            continue
        new = dict(old, status='retention_removed')
        new['content_hash'] = digest(canonical(semantic(new)))
        event = make_event(old, new, 'retention_removed', cutoff.date().isoformat(), now, policy)
        events.setdefault(event['event_id'], event)
        del records[key]
    for key, event in list(events.items()):
        if instant(event['observed_at']) < event_cutoff:
            del events[key]


def shard_rows(rows, kind, policy):
    """Shard deterministically, partitioning records by their owning source."""
    output = {}
    keyfield = 'record_id' if kind == 'records' else 'event_id'
    limit = policy['max_shard_bytes']
    if kind == 'records':
        limit = min(limit, policy.get('record_shard_bytes', RECORD_SHARD_TARGET_BYTES))

    def source_partition(value):
        source = value.get('source_id', '')
        if re.fullmatch(r'[A-Za-z0-9._-]+', source):
            return source
        return 'source-' + digest(source.encode())[:16]

    def split(items, prefix):
        data = b''.join(canonical(item) for item in sorted(items, key=lambda item: item[keyfield]))
        if len(data) <= limit or len(items) == 1:
            threshold_observation('shard_bytes', len(data), limit)
            output[f'{kind}/{prefix}.jsonl'] = data
            return
        if len(prefix.rsplit('/', 1)[-1]) >= 64:
            raise ValueError('unsplittable shard')
        groups = {}
        depth = len(prefix.rsplit('/', 1)[-1])
        for item in items:
            groups.setdefault(digest(item[keyfield].encode())[depth], []).append(item)
        for suffix, members in sorted(groups.items()):
            split(members, prefix + suffix)
    groups = {}
    for row in rows:
        prefix = digest(row[keyfield].encode())[:2]
        if kind == 'records':
            prefix = source_partition(row) + '/' + prefix
        else:
            prefix = row['observed_at'][:10] + '/' + prefix
        groups.setdefault(prefix, []).append(row)
    for prefix, members in sorted(groups.items()):
        split(members, prefix)
    return output


def _relocate(shards, prefix):
    return {prefix + '/' + path.split('/', 1)[1]: data for path, data in shards.items()}


def _delete_shards(record_ids, policy):
    rows = [{'record_id': record_id} for record_id in sorted(record_ids)]
    if not rows:
        return {}
    output = {}
    limit = min(policy['max_shard_bytes'], RECORD_SHARD_TARGET_BYTES)

    def split(members, prefix):
        data = b''.join(canonical(item) for item in members)
        if len(data) <= limit or len(members) == 1:
            output[f'records/deletes/{prefix}.jsonl'] = data
            return
        depth = len(prefix)
        groups = {}
        for row in members:
            groups.setdefault(digest(row['record_id'].encode())[depth], []).append(row)
        for suffix, grouped in sorted(groups.items()):
            split(grouped, prefix + suffix)

    groups = {}
    for row in rows:
        groups.setdefault(digest(row['record_id'].encode())[:2], []).append(row)
    for prefix, members in sorted(groups.items()):
        split(members, prefix)
    return output


def _descriptor(path, data, operation):
    if '/events/' in '/' + path or path.startswith('events/'):
        kind = 'events'
    else:
        kind = 'records'
    return {'path': path, 'kind': kind, 'operation': operation,
            'count': data.count(b'\n'), 'bytes': len(data), 'sha256': digest(data)}


def _snapshot_identity(records, events):
    inventory = [[key, row['content_hash']] for key, row in sorted(records.items())]
    inventory.extend(['event', key, row['content_hash']] for key, row in sorted(events.items()))
    return digest(canonical(inventory))[:20]


def _safe_run_id(value):
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9._-]{1,96}', value):
        raise ValueError('invalid delta run identifier')
    return value


def build_snapshot(repository, records, events, sources, policy, now, collector_version,
                   previous=None, dependencies=None, extra=None, *, previous_files=None,
                   force_checkpoint=False, run_id=None):
    """Build a checkpoint plus immutable per-run deltas.

    ``previous_files`` enables delta publication. Omitting it remains safe and
    deterministic for callers that only know the previous v1 manifest: a fresh
    checkpoint is emitted. Existing positional arguments remain compatible.
    """
    # A semantic-hash policy change must not wait for every upstream source row
    # to be touched. The migration checkpoint rewrites hashes without inventing
    # change events; historical events intentionally retain their original
    # before/after hashes.
    for row in records.values():
        row['content_hash'] = digest(canonical(semantic(row)))
    expire(records, events, now, policy)
    threshold_observation('snapshot_logical_bytes',
        sum(len(canonical(row)) for row in records.values()), MAX_SNAPSHOT_LOGICAL_BYTES)
    manifest = {'schema_version': '1.0', 'repository': repository,
        'generation_id': (previous or {}).get('generation_id', digest(repository.encode())[:16] + '-1'),
        'policy_version': policy['policy_version'], 'collector_version': collector_version,
        'created_at': now, 'shards': [], 'sources': copy.deepcopy(sources),
        'retention': {'days': policy['retention_days'], 'event_days': policy['event_days'],
            'event_start_at': (instant(now) - dt.timedelta(days=policy['event_days'])).date().isoformat() + 'T00:00:00Z'},
        'dependencies': dependencies or []}
    manifest.update(extra or {})

    prior_records, prior_events = {}, {}
    prior_storage = (previous or {}).get('storage')
    can_delta = previous_files is not None and prior_storage and (
        prior_storage.get('format') == 'checkpoint-delta-v1')
    if can_delta:
        prior_records, prior_events, _, loaded = read_snapshot(previous_files)
        if loaded != previous:
            raise ValueError('previous files do not match previous manifest')
    delta_limit = policy.get('checkpoint_max_deltas', CHECKPOINT_MAX_DELTAS)
    make_checkpoint = (force_checkpoint or not can_delta
                       or len(prior_storage.get('deltas', [])) >= delta_limit)
    files = {}
    if make_checkpoint:
        checkpoint_id = now[:10].replace('-', '') + '-' + _snapshot_identity(records, events)
        prior_checkpoint = (prior_storage or {}).get('checkpoint', {})
        checkpoint_created_at = (prior_checkpoint.get('created_at')
                                 if prior_checkpoint.get('id') == checkpoint_id else now)
        record_rows = [item for row in records.values() for item in
                       split_record(row, max_record_bytes=policy['max_record_bytes'])]
        checkpoint_files = {
            **_relocate(shard_rows(record_rows, 'records', policy),
                        f'checkpoints/{checkpoint_id}/records'),
            **_relocate(shard_rows(events.values(), 'events', policy),
                        f'checkpoints/{checkpoint_id}/events'),
        }
        files.update(checkpoint_files)
        descriptors = [_descriptor(path, data, 'snapshot')
                       for path, data in sorted(checkpoint_files.items())]
        manifest['storage'] = {'format': 'checkpoint-delta-v1',
            'checkpoint': {'id': checkpoint_id, 'created_at': checkpoint_created_at,
                           'shards': [item['path'] for item in descriptors]},
            'deltas': []}
        manifest['shards'] = descriptors
    else:
        referenced = {item['path'] for item in previous['shards']}
        files = {path: data for path, data in previous_files.items()
                 if path != 'manifest.json' and path in referenced}
        manifest['storage'] = copy.deepcopy(prior_storage)
        manifest['shards'] = copy.deepcopy(previous['shards'])
        changed = {key: row for key, row in records.items()
                   if key not in prior_records or canonical(row) != canonical(prior_records[key])}
        deleted = set(prior_records) - set(records)
        new_events = {key: row for key, row in events.items() if key not in prior_events}
        if changed or deleted or new_events:
            identity = digest(canonical({'upserts': [[key, row['content_hash']]
                for key, row in sorted(changed.items())], 'deletes': sorted(deleted),
                'events': sorted(new_events), 'now': now}))[:16]
            delta_id = _safe_run_id(run_id or now.replace('-', '').replace(':', '')
                                    .replace('T', '-').removesuffix('Z') + '-' + identity)
            physical = [item for row in changed.values() for item in
                        split_record(row, max_record_bytes=policy['max_record_bytes'])]
            delta_files = {
                **_relocate(shard_rows(physical, 'records', policy),
                            f'deltas/{delta_id}/records/upserts'),
                **_relocate(_delete_shards(deleted, policy), f'deltas/{delta_id}/records'),
                **_relocate(shard_rows(new_events.values(), 'events', policy),
                            f'deltas/{delta_id}/events'),
            }
            operations = {}
            for path in delta_files:
                operations[path] = ('append' if f'deltas/{delta_id}/events/' in path else
                                    'delete' if '/records/deletes/' in path else 'upsert')
            for path, data in sorted(delta_files.items()):
                if path in files and files[path] != data:
                    raise ValueError('immutable delta path collision')
                files[path] = data
                manifest['shards'].append(_descriptor(path, data, operations[path]))
            manifest['storage']['deltas'].append({'run_id': delta_id, 'created_at': now,
                'shards': sorted(delta_files)})
    # Daily no-change health summarizes attempts without writing each poll to Git.
    if previous:
        def comparable(value):
            value = copy.deepcopy(value)
            value.pop('created_at', None)
            for source_id, state in value['sources'].items():
                for key in ('last_attempt_at', 'last_success_at', 'requests', 'bytes', 'elapsed_seconds'):
                    state.pop(key, None)
                # A completed CVE Git revision is the next incremental base.
                # Persist its checkpoint even when all normalized facts match,
                # otherwise the following run replays the same changed files.
                if source_id != 'cve' and state.get('status') == 'ok' and not state.get('continuation'):
                    for key in ('completed_watermark', 'revision', 'revision_history'):
                        state.pop(key, None)
            return value
        if comparable(manifest) == comparable(previous) and previous['created_at'][:10] == now[:10]:
            manifest = previous
    validate('manifest', manifest)
    files['manifest.json'] = canonical(manifest)
    threshold_observation('manifest_bytes', len(files['manifest.json']), 512 * 1024)
    threshold_observation('current_tree_bytes', sum(map(len, files.values())), policy['max_tree_bytes'])
    return files, manifest


def read_snapshot(files):
    if 'manifest.json' not in files:
        return {}, {}, {}, None
    manifest = json.loads(files['manifest.json'])
    validate('manifest', manifest)
    descriptors = {item['path']: item for item in manifest['shards']}

    def rows(path):
        shard = descriptors[path]
        try:
            data = files[shard['path']]
        except KeyError:
            raise ValueError('referenced shard is missing') from None
        if digest(data) != shard['sha256'] or len(data) != shard['bytes']:
            raise ValueError('shard checksum or byte count mismatch')
        result = [json.loads(line) for line in data.splitlines()]
        if len(result) != shard['count']:
            raise ValueError('shard record count mismatch')
        return shard, result

    storage = manifest.get('storage')
    if not storage:
        records, events = {}, {}
        for path in descriptors:
            shard, parsed = rows(path)
            for row in parsed:
                kind = 'record' if shard['kind'] == 'records' else 'event'
                validate(kind, row)
                (records if kind == 'record' else events)[row[kind + '_id']] = row
        logical = assemble_records(records, max_snapshot_logical_bytes=None)
        for row in logical:
            validate('record', row)
        return ({row['record_id']: row for row in logical}, events,
                copy.deepcopy(manifest['sources']), manifest)
    if storage.get('format') != 'checkpoint-delta-v1':
        raise ValueError('unsupported snapshot storage format')

    def logical_records(paths):
        physical = {}
        for path in paths:
            shard, parsed = rows(path)
            if shard['kind'] != 'records' or shard.get('operation') not in ('snapshot', 'upsert'):
                continue
            for row in parsed:
                validate('record', row)
                physical[row['record_id']] = row
        logical = assemble_records(physical, max_snapshot_logical_bytes=None)
        for row in logical:
            validate('record', row)
        return logical

    checkpoint_paths = storage['checkpoint']['shards']
    records = {row['record_id']: row for row in logical_records(checkpoint_paths)}
    events = {}
    for path in checkpoint_paths:
        shard, parsed = rows(path)
        if shard['kind'] == 'events':
            for row in parsed:
                validate('event', row)
                events[row['event_id']] = row
    for delta in storage['deltas']:
        paths = delta['shards']
        for path in paths:
            shard, parsed = rows(path)
            if shard.get('operation') == 'delete':
                for row in parsed:
                    if set(row) != {'record_id'} or not isinstance(row['record_id'], str):
                        raise ValueError('invalid record deletion tombstone')
                    records.pop(row['record_id'], None)
        for row in logical_records(paths):
            records[row['record_id']] = row
        for path in paths:
            shard, parsed = rows(path)
            if shard['kind'] == 'events':
                for row in parsed:
                    validate('event', row)
                    events[row['event_id']] = row
    event_start = instant(manifest['retention']['event_start_at'])
    events = {key: row for key, row in events.items()
              if instant(row['observed_at']) >= event_start}
    return records, events, copy.deepcopy(manifest['sources']), manifest
