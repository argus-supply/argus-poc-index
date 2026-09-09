"""Cache bounded active IDs and public references, reusing unchanged shards."""
import json
import re

from .core import canonical, digest, validate
from .continuations import assemble_records


INTEL_SOURCES = ('cve', 'ghsa', 'kev')


def coverage_summary(manifest):
    """Bind completeness to required sources in one immutable intel manifest."""
    required, errors = {}, []
    for name in INTEL_SOURCES:
        source = manifest['sources'].get(name, {})
        summary = {'status': source.get('status', 'missing'),
            'completed_watermark': source.get('completed_watermark'),
            'has_continuation': bool(source.get('continuation')),
            'has_gaps': bool(source.get('coverage_gaps')),
            'has_errors': bool(source.get('errors'))}
        required[name] = summary
        if (summary['status'] != 'ok' or not summary['completed_watermark']
                or summary['has_continuation'] or summary['has_gaps'] or summary['has_errors']):
            errors.append({'source_id': name, 'code': 'intel_dependency_incomplete',
                'reason': 'required fixed-revision source is missing, incomplete, or has unresolved errors'})
    return {'coverage_version': 1, 'coverage_complete': not errors,
            'required_sources': required, 'coverage_errors': errors}


def read_manifest(client, repository, sha, expected_hash=None):
    body = client.get_bytes(f'https://raw.githubusercontent.com/{repository}/{sha}/manifest.json')
    if len(body) > 524288 or (expected_hash is not None and digest(body) != expected_hash):
        raise ValueError('intel dependency manifest size or fixed-revision hash mismatch')
    manifest = json.loads(body)
    validate('manifest', manifest)
    if manifest['repository'] != repository:
        raise ValueError('intel dependency manifest repository mismatch')
    return body, manifest


def consume_intel(client, requested_sha, previous, previous_files):
    repository = 'argus-supply/argus-intel-data'
    old = (previous or {}).get('dependency_cache', {})
    needs_coverage = bool(old) and (old.get('coverage_version') != 1 or
        type(old.get('coverage_complete')) is not bool or
        set(old.get('required_sources', {})) != set(INTEL_SOURCES) or 'coverage_errors' not in old)
    sha = requested_sha
    if not sha and needs_coverage:
        # Upgrade the exact old projection first; a newer healthy head cannot
        # certify the partial dependency used by an unfinished prior publication.
        sha = old.get('commit_sha')
    if not sha:
        sha = client.get_json(f'https://api.github.com/repos/{repository}/git/ref/heads/data')['object']['sha']
    if not isinstance(sha, str) or not re.fullmatch(r'[a-f0-9]{40}', sha):
        raise ValueError('intel dependency requires an immutable SHA')
    if old.get('commit_sha') == sha:
        files = {item['path']: previous_files[item['path']] for item in old['shards']}
        metadata = dict(old)
        if needs_coverage:
            if not re.fullmatch(r'[a-f0-9]{64}', old.get('manifest_sha256', '')):
                raise ValueError('legacy intel dependency manifest checksum is missing')
            _, manifest = read_manifest(client, repository, sha, old['manifest_sha256'])
            metadata.update(coverage_summary(manifest))
    else:
        prefix = f'https://raw.githubusercontent.com/{repository}/{sha}/'
        manifest_bytes, manifest = read_manifest(client, repository, sha)
        prior = {item['upstream_path']: item for item in old.get('shards', [])}
        files, descriptors = {}, []
        for shard in manifest['shards']:
            if shard['kind'] != 'records':
                continue
            cached = prior.get(shard['path'])
            if cached and cached['upstream_sha256'] == shard['sha256']:
                body = previous_files[cached['path']]
                if digest(body) != cached['sha256']:
                    raise ValueError('dependency cache hash mismatch')
                descriptor = cached
            else:
                raw = client.get_bytes(prefix + shard['path'])
                if len(raw) != shard['bytes'] or digest(raw) != shard['sha256']:
                    raise ValueError('intel dependency shard hash mismatch')
                rows = [json.loads(line) for line in raw.splitlines()]
                if len(rows) != shard['count']:
                    raise ValueError('intel dependency count mismatch')
                projected = []
                for row in rows:
                    validate('record', row)
                    if row['kind'] == 'continuation' or row.get('continuation'):
                        projected.append(row)
                    elif row['status'] == 'active':
                        projected.append({key: row.get(key) for key in ('record_id', 'source_id', 'native_id',
                            'kind', 'aliases', 'status', 'title', 'references', 'published_at', 'source_modified_at')})
                body = b''.join(canonical(row) for row in projected)
                path = 'state/intel/' + shard['path'].removeprefix('records/')
                descriptor = {'path': path, 'upstream_path': shard['path'], 'upstream_sha256': shard['sha256'],
                    'bytes': len(body), 'sha256': digest(body)}
            files[descriptor['path']] = body
            descriptors.append(descriptor)
        metadata = {'repository': repository, 'commit_sha': sha,
            'manifest_sha256': digest(manifest_bytes), 'shards': descriptors, **coverage_summary(manifest)}
    records = []
    for descriptor in metadata['shards']:
        body = files[descriptor['path']]
        if len(body) != descriptor['bytes'] or digest(body) != descriptor['sha256']:
            raise ValueError('dependency projection checksum mismatch')
        records.extend(json.loads(line) for line in body.splitlines())
    logical = assemble_records(records)
    active = [{key: row.get(key) for key in ('record_id', 'source_id', 'native_id', 'kind', 'aliases',
                'status', 'title', 'references', 'published_at', 'source_modified_at')}
              for row in logical if row['status'] == 'active']
    dependency = {key: metadata[key] for key in ('repository', 'commit_sha', 'manifest_sha256',
        'coverage_version', 'coverage_complete', 'required_sources', 'coverage_errors')}
    return {**dependency, 'records': active}, metadata, files
