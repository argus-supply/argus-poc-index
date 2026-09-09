"""Cache bounded active IDs and public references, reusing unchanged shards."""
import json

from .core import canonical, digest, validate
from .continuations import assemble_records


def consume_intel(client, requested_sha, previous, previous_files):
    repository = 'argus-supply/argus-intel-data'
    sha = requested_sha
    if not sha:
        sha = client.get_json(f'https://api.github.com/repos/{repository}/git/ref/heads/data')['object']['sha']
    old = (previous or {}).get('dependency_cache', {})
    if old.get('commit_sha') == sha:
        files = {item['path']: previous_files[item['path']] for item in old['shards']}
        metadata = old
    else:
        prefix = f'https://raw.githubusercontent.com/{repository}/{sha}/'
        manifest_bytes = client.get_bytes(prefix + 'manifest.json')
        manifest = json.loads(manifest_bytes)
        validate('manifest', manifest)
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
            'manifest_sha256': digest(manifest_bytes), 'shards': descriptors}
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
    dependency = {key: metadata[key] for key in ('repository', 'commit_sha', 'manifest_sha256')}
    return {**dependency, 'records': active}, metadata, files
