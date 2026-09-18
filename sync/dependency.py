"""Read bounded Intel facts from an immutable revision without persisting copies."""
import json
import re
import base64
import io
from pathlib import PurePosixPath
import tarfile
import zlib

from .core import digest, validate
from .continuations import iter_records
from .observations import threshold_observation


INTEL_SOURCES = ('cve', 'ghsa', 'kev')
STATE_VERSION = 1
STATE_TARGET_BYTES = 512 * 1024
ARCHIVE_MAX_COMPRESSED_BYTES = 64 * 1024 * 1024
ARCHIVE_MAX_MEMBERS = 20000
ARCHIVE_MAX_MEMBER_BYTES = 4 * 1024 * 1024
ARCHIVE_MAX_MANIFEST_BYTES = 32 * 1024 * 1024
ARCHIVE_MAX_TOTAL_BYTES = 256 * 1024 * 1024


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
    threshold_observation('intel_dependency_manifest_bytes', len(body), 524288)
    if expected_hash is not None and digest(body) != expected_hash:
        raise ValueError('intel dependency manifest fixed-revision hash mismatch')
    manifest = json.loads(body)
    validate('manifest', manifest)
    if manifest['repository'] != repository:
        raise ValueError('intel dependency manifest repository mismatch')
    return body, manifest


def read_archive(client, repository, sha, expected_manifest_hash=None):
    """Read one strictly scoped codeload archive and materialize its records."""
    if repository != 'argus-supply/argus-intel-data' or not re.fullmatch(r'[a-f0-9]{40}', sha):
        raise ValueError('invalid intel dependency archive target')
    body = client.get_bytes(f'https://codeload.github.com/{repository}/tar.gz/{sha}')
    if len(body) > ARCHIVE_MAX_COMPRESSED_BYTES:
        raise ValueError('intel dependency archive exceeds compressed byte ceiling')
    root = f'argus-intel-data-{sha}'
    entries, names, total, manifest_bytes = {}, set(), 0, None

    def checked_member(member):
        nonlocal total
        name = member.name.removesuffix('/')
        if member.name in names:
            raise ValueError('duplicate intel dependency archive member')
        names.add(member.name)
        if name == root and member.isdir():
            return None
        if not name.startswith(root + '/'):
            raise ValueError('intel dependency archive has an unexpected top-level prefix')
        relative = name[len(root) + 1:]
        path = PurePosixPath(relative)
        if (not relative or relative.startswith('/') or '\\' in relative or '..' in path.parts
                or '.' in path.parts):
            raise ValueError('unsafe intel dependency archive member path')
        if member.isdir():
            return None
        if not member.isfile() or member.islnk() or member.issym():
            raise ValueError('intel dependency archive contains a non-regular member')
        member_limit = ARCHIVE_MAX_MANIFEST_BYTES if relative == 'manifest.json' else ARCHIVE_MAX_MEMBER_BYTES
        if member.size < 0 or member.size > member_limit:
            raise ValueError('intel dependency archive member exceeds byte ceiling')
        total += member.size
        if total > ARCHIVE_MAX_TOTAL_BYTES:
            raise ValueError('intel dependency archive exceeds expanded byte ceiling')
        if relative in entries:
            raise ValueError('duplicate intel dependency archive path')
        entries[relative] = member.size
        return relative

    try:
        with tarfile.open(fileobj=io.BytesIO(body), mode='r|gz') as archive:
            for count, member in enumerate(archive, 1):
                if count > ARCHIVE_MAX_MEMBERS:
                    raise ValueError('intel dependency archive has too many members')
                relative = checked_member(member)
                if relative == 'manifest.json':
                    stream = archive.extractfile(member)
                    if stream is None:
                        raise ValueError('unreadable intel dependency archive manifest')
                    manifest_bytes = stream.read(ARCHIVE_MAX_MANIFEST_BYTES + 1)
                    if len(manifest_bytes) != member.size:
                        raise ValueError('intel dependency archive member size mismatch')
    except (tarfile.TarError, EOFError, OSError):
        raise ValueError('invalid intel dependency archive') from None
    if 'manifest.json' not in entries:
        raise ValueError('intel dependency archive manifest is missing')
    if manifest_bytes is None:
        raise ValueError('unreadable intel dependency archive manifest')
    if expected_manifest_hash is not None and digest(manifest_bytes) != expected_manifest_hash:
        raise ValueError('intel dependency archive manifest hash mismatch')
    try:
        manifest = json.loads(manifest_bytes)
    except json.JSONDecodeError:
        raise ValueError('invalid intel dependency archive manifest') from None
    validate('manifest', manifest)
    if manifest['repository'] != repository:
        raise ValueError('intel dependency archive repository mismatch')
    declared = {item['path']: item for item in manifest['shards']}
    if len(declared) != len(manifest['shards']):
        raise ValueError('duplicate intel dependency manifest shard path')
    extra = set(entries) - {'manifest.json'} - set(declared)
    if extra:
        raise ValueError('intel dependency archive contains undeclared files')
    required = {path for path, item in declared.items() if item['kind'] == 'records'}
    if not required.issubset(entries):
        raise ValueError('intel dependency archive record shard is missing')
    if any(entries[path] != declared[path]['bytes'] for path in required):
        raise ValueError('intel dependency archive record shard size mismatch')
    files = {}
    try:
        with tarfile.open(fileobj=io.BytesIO(body), mode='r|gz') as archive:
            for count, member in enumerate(archive, 1):
                if count > ARCHIVE_MAX_MEMBERS:
                    raise ValueError('intel dependency archive has too many members')
                name = member.name.removesuffix('/')
                relative = name[len(root) + 1:] if name.startswith(root + '/') else None
                if relative not in required:
                    continue
                stream = archive.extractfile(member)
                if stream is None:
                    raise ValueError('unreadable intel dependency archive member')
                value = stream.read(ARCHIVE_MAX_MEMBER_BYTES + 1)
                if len(value) != member.size:
                    raise ValueError('intel dependency archive member size mismatch')
                files[relative] = value
    except (tarfile.TarError, EOFError, OSError):
        raise ValueError('invalid intel dependency archive') from None
    if set(files) != required:
        raise ValueError('intel dependency archive record shard is missing')
    for path in required:
        item, value = declared[path], files[path]
        if (len(value) != item['bytes'] or digest(value) != item['sha256']
                or value.count(b'\n') != item['count']):
            raise ValueError('intel dependency archive record shard mismatch')

    class ArchiveClient:
        def get_bytes(self, url):
            prefix = f'archive/{sha}/'
            if not url.startswith(prefix):
                raise ValueError('unexpected archive record path')
            path = url[len(prefix):]
            return files[path]

    logical = _remote_records(ArchiveClient(), f'archive/{sha}/', manifest)
    return manifest_bytes, manifest, logical


def _reader(client, prefix, manifest):
    descriptors = {item['path']: item for item in manifest['shards']}
    fetched = {}

    def rows(path):
        if path in fetched:
            return fetched[path]
        shard = descriptors[path]
        raw = client.get_bytes(prefix + path)
        if len(raw) != shard['bytes'] or digest(raw) != shard['sha256']:
            raise ValueError('intel dependency shard hash mismatch')
        parsed = [json.loads(line) for line in raw.splitlines()]
        if len(parsed) != shard['count']:
            raise ValueError('intel dependency count mismatch')
        fetched[path] = parsed
        return parsed

    return descriptors, rows


def _paths_records(descriptors, rows, paths, operations):
    physical = []
    for path in paths:
        shard = descriptors[path]
        if shard['kind'] == 'records' and shard.get('operation') in operations:
            physical.extend(rows(path))
    return iter_records(physical, max_snapshot_logical_bytes=None)


def _remote_records(client, prefix, manifest):
    """Materialize records from either a legacy snapshot or checkpoint+deltas."""
    descriptors, rows = _reader(client, prefix, manifest)
    storage = manifest.get('storage')
    if not storage:
        physical = []
        for shard in manifest['shards']:
            if shard['kind'] == 'records':
                physical.extend(rows(shard['path']))
        return iter_records(physical, max_snapshot_logical_bytes=None)
    if storage.get('format') != 'checkpoint-delta-v1':
        raise ValueError('unsupported intel dependency storage format')

    checkpoint = storage['checkpoint']['shards']
    current = {row['record_id']: row for row in
               _paths_records(descriptors, rows, checkpoint, {'snapshot'})}
    for delta in storage['deltas']:
        paths = delta['shards']
        for path in paths:
            shard = descriptors[path]
            if shard['kind'] != 'records' or shard.get('operation') != 'delete':
                continue
            for tombstone in rows(path):
                if set(tombstone) != {'record_id'} or not isinstance(tombstone['record_id'], str):
                    raise ValueError('invalid intel dependency deletion tombstone')
                current.pop(tombstone['record_id'], None)
        for row in _paths_records(descriptors, rows, paths, {'upsert'}):
            current[row['record_id']] = row
    return list(current.values())


def _aliases(record):
    return sorted({value for value in record.get('aliases', [])
                   if isinstance(value, str) and re.fullmatch(r'CVE-[0-9]{4}-[0-9]{4,}', value)})


def _encode_state(commit_sha, manifest_sha256, checkpoint_id, aliases_by_record):
    packed = zlib.compress(json.dumps(sorted(aliases_by_record.items()), ensure_ascii=True,
        separators=(',', ':')).encode(), level=9)
    threshold_observation('intel_dependency_compact_state_bytes', len(packed), STATE_TARGET_BYTES)
    return {'version': STATE_VERSION, 'commit_sha': commit_sha,
        'manifest_sha256': manifest_sha256, 'checkpoint_id': checkpoint_id,
        'active_aliases_zlib': base64.b64encode(packed).decode()}


def _decode_state(value):
    if (not isinstance(value, dict) or value.get('version') != STATE_VERSION
            or not re.fullmatch(r'[a-f0-9]{40}', value.get('commit_sha', ''))
            or not re.fullmatch(r'[a-f0-9]{64}', value.get('manifest_sha256', ''))
            or not isinstance(value.get('checkpoint_id'), str)
            or not isinstance(value.get('active_aliases_zlib'), str)):
        return None
    if len(value['active_aliases_zlib']) > 2 * 1024 * 1024:
        raise ValueError('oversize compact intel dependency state')
    try:
        compressed = base64.b64decode(value['active_aliases_zlib'], validate=True)
        decoder = zlib.decompressobj()
        raw = decoder.decompress(compressed, 8 * 1024 * 1024 + 1)
        if decoder.unconsumed_tail or not decoder.eof:
            raise ValueError('oversize compact intel dependency state')
    except (ValueError, zlib.error):
        raise ValueError('invalid compact intel dependency state') from None
    if len(raw) > 8 * 1024 * 1024:
        raise ValueError('oversize compact intel dependency state')
    try:
        pairs = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ValueError('invalid compact intel dependency state') from None
    result = {}
    if not isinstance(pairs, list):
        raise ValueError('invalid compact intel dependency state')
    for pair in pairs:
        if (not isinstance(pair, list) or len(pair) != 2 or not isinstance(pair[0], str)
                or pair[0] in result or not isinstance(pair[1], list)
                or pair[1] != sorted(set(pair[1]))
                or any(not re.fullmatch(r'CVE-[0-9]{4}-[0-9]{4,}', item) for item in pair[1])):
            raise ValueError('invalid compact intel dependency state')
        result[pair[0]] = pair[1]
    return result


def _incremental_records(client, prefix, manifest, old_manifest):
    storage, old_storage = manifest.get('storage'), old_manifest.get('storage')
    if (not storage or not old_storage or storage.get('format') != 'checkpoint-delta-v1'
            or old_storage.get('format') != 'checkpoint-delta-v1'
            or storage['checkpoint']['id'] != old_storage['checkpoint']['id']):
        return None
    old_deltas = old_storage['deltas']
    if storage['deltas'][:len(old_deltas)] != old_deltas:
        return None
    descriptors, rows = _reader(client, prefix, manifest)
    changed, deleted = {}, set()
    for delta in storage['deltas'][len(old_deltas):]:
        for path in delta['shards']:
            shard = descriptors[path]
            if shard['kind'] == 'records' and shard.get('operation') == 'delete':
                for tombstone in rows(path):
                    if set(tombstone) != {'record_id'} or not isinstance(tombstone['record_id'], str):
                        raise ValueError('invalid intel dependency deletion tombstone')
                    deleted.add(tombstone['record_id'])
                    changed.pop(tombstone['record_id'], None)
        for row in _paths_records(descriptors, rows, delta['shards'], {'upsert'}):
            changed[row['record_id']] = row
            deleted.discard(row['record_id'])
    return list(changed.values()), deleted


def consume_intel(client, requested_sha, previous=None, previous_files=None, *, base_sha=None,
                  force_full=False):
    """Return the active Intel projection bound to one immutable manifest.

    ``previous`` and ``previous_files`` remain accepted for rolling upgrades from
    publications that embedded ``state/intel`` shards. They are deliberately not
    read: every run verifies the dependency at its immutable commit, and the
    caller's next snapshot consequently drops all legacy projection files.
    """
    repository = 'argus-supply/argus-intel-data'
    sha = requested_sha
    if not sha:
        sha = client.get_json(f'https://api.github.com/repos/{repository}/git/ref/heads/data')['object']['sha']
    if not isinstance(sha, str) or not re.fullmatch(r'[a-f0-9]{40}', sha):
        raise ValueError('intel dependency requires an immutable SHA')
    prefix = f'https://raw.githubusercontent.com/{repository}/{sha}/'
    saved = (previous or {}).get('intel_dependency_state')
    aliases_by_record = _decode_state(saved) if saved else None
    previous_active_ids = (sorted({alias for aliases in aliases_by_record.values() for alias in aliases})
                           if aliases_by_record is not None else None)
    prior_sha = base_sha or ((saved or {}).get('commit_sha') if aliases_by_record is not None else None)
    incremental = None
    logical = None
    if force_full or aliases_by_record is None:
        manifest_bytes, manifest, logical = read_archive(client, repository, sha)
    else:
        manifest_bytes, manifest = read_manifest(client, repository, sha)
    manifest_hash = digest(manifest_bytes)
    target_checkpoint = (manifest.get('storage') or {}).get('checkpoint', {}).get('id', 'legacy')
    if logical is None:
        if (prior_sha == sha and saved['manifest_sha256'] == manifest_hash
                and saved['checkpoint_id'] == target_checkpoint):
            incremental = ([], set())
        elif prior_sha:
            old_expected = saved['manifest_sha256'] if prior_sha == saved['commit_sha'] else None
            _, old_manifest = read_manifest(client, repository, prior_sha, old_expected)
            old_checkpoint = (old_manifest.get('storage') or {}).get('checkpoint', {}).get('id', 'legacy')
            if old_checkpoint == saved['checkpoint_id'] or prior_sha != saved['commit_sha']:
                incremental = _incremental_records(client, prefix, manifest, old_manifest)
    if incremental is None:
        if logical is None:
            archive_manifest, manifest, logical = read_archive(
                client, repository, sha, manifest_hash)
            if archive_manifest != manifest_bytes:
                raise ValueError('intel dependency archive manifest mismatch')
        deleted = set()
        aliases_by_record = {row['record_id']: _aliases(row) for row in logical
                             if row['status'] == 'active' and _aliases(row)}
        mode = 'full'
    else:
        logical, deleted = incremental
        mode = 'incremental' if prior_sha != sha else 'unchanged'
        for record_id in deleted:
            aliases_by_record.pop(record_id, None)
        for row in logical:
            aliases_by_record.pop(row['record_id'], None)
            values = _aliases(row)
            if row['status'] == 'active' and values:
                aliases_by_record[row['record_id']] = values
    for row in logical:
        validate('record', row)
        if row['status'] != 'active':
            deleted.add(row['record_id'])
    active = [{key: row.get(key) for key in ('record_id', 'source_id', 'native_id', 'kind', 'aliases',
                'status', 'title', 'references', 'published_at', 'source_modified_at')}
              for row in logical if row['status'] == 'active']
    active_ids = sorted({alias for aliases in aliases_by_record.values() for alias in aliases})
    state = _encode_state(sha, manifest_hash, target_checkpoint, aliases_by_record)
    dependency = {'repository': repository, 'commit_sha': sha,
        'manifest_sha256': manifest_hash, 'base_commit_sha': prior_sha,
        'mode': mode, 'active_ids': active_ids, 'previous_active_ids': previous_active_ids,
        'deleted_record_ids': sorted(deleted),
        **coverage_summary(manifest)}
    # Keep the historical three-value API during rolling deployment. Empty
    # cache/files are intentional and ensure the next publication removes old
    # ``dependency_cache`` metadata and ``state/intel`` files.
    return {**dependency, 'records': active}, state, {}
