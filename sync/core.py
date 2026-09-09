"""Deterministic records, semantic events, bounded shards and schema validation."""
from __future__ import annotations

import copy
import datetime as dt
import hashlib
import json
from functools import lru_cache
from pathlib import Path

from jsonschema import Draft202012Validator
from .continuations import split_record, assemble_records

ROOT = Path(__file__).resolve().parents[1]


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


def load_policy(path):
    policy = json.loads(Path(path).read_text())
    ceilings = {'max_record_bytes': 16384, 'max_shard_bytes': 524288,
        'max_tree_bytes': 33554432, 'job_seconds': 720, 'job_requests': 500,
        'job_bytes': 67108864, 'daily_bytes': 10485760, 'consumer_daily_bytes': 4194304,
        'history_bytes': 134217728, 'monthly_history_growth_bytes': 104857600,
        'monthly_runner_minutes': 900, 'max_pocs_per_vulnerability': 100,
        'max_source_state_bytes': 524288}
    for key, limit in ceilings.items():
        if type(policy.get(key)) is not int or not 0 < policy[key] <= limit:
            raise ValueError(f'invalid policy ceiling: {key}')
    if policy.get('schema_version') != '1.0' or not policy.get('policy_version'):
        raise ValueError('unsupported policy version')
    for key in ('retention_days', 'event_days', 'bootstrap_days', 'overlap_hours', 'reconcile_hours',
                'http_timeout_seconds', 'http_retry_after_max_seconds'):
        if type(policy.get(key)) is not int or policy[key] <= 0:
            raise ValueError(f'invalid policy setting: {key}')
    if policy['bootstrap_days'] > policy['retention_days']:
        raise ValueError('bootstrap exceeds retained window')
    allocations = policy['runner_minutes_by_repository']
    if any(type(value) is not int or value <= 0 for value in allocations.values()) or sum(allocations.values()) > policy['monthly_runner_minutes']:
        raise ValueError('invalid per-repository runner allocation')
    if len(policy['source_order']) != len(set(policy['source_order'])):
        raise ValueError('duplicate source in fair collection order')
    return policy


def semantic(record):
    result = {key: copy.deepcopy(value) for key, value in record.items() if key not in
        ('content_hash', 'first_seen_at', 'source_modified_at', 'observed_at',
         'last_seen_at', 'source_revision', 'derived', 'assessment', 'last_material_event_at',
         'index_revision', 'intel_commit_sha')}
    for item in result.get('provenance', []):
        if isinstance(item, dict):
            item.pop('revision', None)
    return result


def event_types(old, new):
    if old is None:
        proof = new.get('bootstrap_material_change')
        if proof:
            types = {'affected': 'affected_corrected', 'scores': 'score_changed', 'metrics': 'score_changed',
                     'status': 'rejected' if new.get('status') == 'rejected' else 'withdrawn'}
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
    if len(canonical(state)) > policy['max_source_state_bytes']:
        state = {**prior, 'status': 'partial', 'coverage_gaps': ['source_state_bytes_exceeded'],
                 'errors': ['source_state_bytes_exceeded'], 'last_attempt_at': now}
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
    """Stable hash prefixes only split the overflowing bucket, never the full corpus."""
    output = {}
    keyfield = 'record_id' if kind == 'records' else 'event_id'
    def split(items, prefix):
        data = b''.join(canonical(item) for item in sorted(items, key=lambda item: item[keyfield]))
        if len(data) <= policy['max_shard_bytes']:
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
        if kind == 'events':
            prefix = row['observed_at'][:10] + '/' + prefix
        groups.setdefault(prefix, []).append(row)
    for prefix, members in sorted(groups.items()):
        split(members, prefix)
    return output


def build_snapshot(repository, records, events, sources, policy, now, collector_version,
                   previous=None, dependencies=None, extra=None):
    expire(records, events, now, policy)
    physical = [item for row in records.values() for item in split_record(row, max_record_bytes=policy['max_record_bytes'])]
    files = {**shard_rows(physical, 'records', policy),
             **shard_rows(events.values(), 'events', policy)}
    manifest = {'schema_version': '1.0', 'repository': repository,
        'generation_id': (previous or {}).get('generation_id', digest(repository.encode())[:16] + '-1'),
        'policy_version': policy['policy_version'], 'collector_version': collector_version,
        'created_at': now, 'shards': [], 'sources': copy.deepcopy(sources),
        'retention': {'days': policy['retention_days'], 'event_days': policy['event_days'],
            'event_start_at': (instant(now) - dt.timedelta(days=policy['event_days'])).date().isoformat() + 'T00:00:00Z'},
        'dependencies': dependencies or []}
    manifest.update(extra or {})
    for path, data in sorted(files.items()):
        manifest['shards'].append({'path': path, 'kind': path.split('/')[0],
            'count': data.count(b'\n'), 'bytes': len(data), 'sha256': digest(data)})
    # Daily no-change health summarizes attempts without writing each poll to Git.
    if previous:
        def comparable(value):
            value = copy.deepcopy(value)
            value.pop('created_at', None)
            for state in value['sources'].values():
                for key in ('last_attempt_at', 'last_success_at', 'requests', 'bytes', 'elapsed_seconds'):
                    state.pop(key, None)
                if state.get('status') == 'ok' and not state.get('continuation'):
                    for key in ('completed_watermark', 'revision', 'revision_history'):
                        state.pop(key, None)
            return value
        if comparable(manifest) == comparable(previous) and previous['created_at'][:10] == now[:10]:
            manifest = previous
    validate('manifest', manifest)
    files['manifest.json'] = canonical(manifest)
    if sum(map(len, files.values())) > policy['max_tree_bytes']:
        raise ValueError('current data tree budget exceeded')
    return files, manifest


def read_snapshot(files):
    if 'manifest.json' not in files:
        return {}, {}, {}, None
    manifest = json.loads(files['manifest.json'])
    validate('manifest', manifest)
    records, events = {}, {}
    for shard in manifest['shards']:
        data = files[shard['path']]
        if digest(data) != shard['sha256'] or len(data) != shard['bytes']:
            raise ValueError('shard checksum or byte count mismatch')
        rows = [json.loads(line) for line in data.splitlines()]
        if len(rows) != shard['count']:
            raise ValueError('shard record count mismatch')
        for row in rows:
            kind = 'record' if shard['kind'] == 'records' else 'event'
            validate(kind, row)
            (records if kind == 'record' else events)[row[kind + '_id']] = row
    logical = assemble_records(records)
    for row in logical:
        validate('record', row)
    return {row['record_id']: row for row in logical}, events, copy.deepcopy(manifest['sources']), manifest
