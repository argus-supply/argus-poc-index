"""Lossless, bounded physical records for oversized logical JSON records.

This stdlib-only module is shared byte-for-byte with the repository consumer.
Events, retention and indexing operate on reassembled logical records. Physical
parents are explicit stubs; fragments are never independent discoveries.
"""
from __future__ import annotations

import base64
import binascii
import copy
import hashlib
import json
import zlib
from collections.abc import Iterable, Mapping


FORMAT = 'json-utf8-v1'
AFFECTED_FORMAT = 'json-affected-v2'
COMPRESSED_FORMAT = 'json-zlib-v3'
COMPRESSED_AFFECTED_FORMAT = 'json-zlib-affected-v3'
COMPRESSION_LEVEL = 6
STORAGE_FORMAT = 'cve-indexed-assertions-v1'
MAX_RECORD_BYTES = 16 * 1024
MAX_LOGICAL_BYTES = 256 * 1024
MAX_PARTS = 64
MAX_AFFECTED_BYTES = 2 * 1024 * 1024
MAX_AFFECTED_PARTS = 256
MAX_SNAPSHOT_LOGICAL_BYTES = 64 * 1024 * 1024


def _canonical(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'),
                       allow_nan=False) + '\n').encode('utf-8')


def _digest(data):
    return hashlib.sha256(data).hexdigest()


def _bounds(max_record_bytes, max_logical_bytes):
    if type(max_record_bytes) is not int or not 0 < max_record_bytes <= MAX_RECORD_BYTES:
        raise ValueError('invalid physical record byte ceiling')
    if type(max_logical_bytes) is not int or not 0 < max_logical_bytes <= MAX_LOGICAL_BYTES:
        raise ValueError('invalid logical record byte ceiling')


def _stub(record):
    result = {key: copy.deepcopy(record[key]) for key in (
        'schema_version', 'record_id', 'source_id', 'native_id', 'kind', 'status',
        'published_at', 'source_modified_at', 'first_seen_at', 'content_hash')}
    result.update(title=record['native_id'], aliases=[], affected=[], references=[], provenance=[])
    return result


def _compact_record(record):
    """Deduplicate CVE assertion ownership while retaining an exact inverse."""
    if record.get('source_id') != 'cve' or 'record_encoding' in record:
        return copy.deepcopy(record)
    assertions, affected = record.get('assertions'), record.get('affected')
    if not isinstance(assertions, list) or not assertions or not isinstance(affected, list):
        return copy.deepcopy(record)
    owners = [None] * len(affected)
    for assertion_index, assertion in enumerate(assertions):
        if (not isinstance(assertion, dict) or not isinstance(assertion.get('role'), str)
                or not isinstance(assertion.get('provider'), dict)
                or not isinstance(assertion.get('affected_indices'), list)):
            return copy.deepcopy(record)
        provider = {key: value for key, value in assertion['provider'].items()
                    if key != 'dateUpdated'}
        for affected_index in assertion['affected_indices']:
            if (type(affected_index) is not int or not 0 <= affected_index < len(affected)
                    or owners[affected_index] is not None):
                return copy.deepcopy(record)
            item = affected[affected_index]
            if (not isinstance(item, dict) or item.get('assertion_role') != assertion['role']
                    or _canonical(item.get('provider')) != _canonical(provider)):
                return copy.deepcopy(record)
            owners[affected_index] = assertion_index
    if any(owner is None for owner in owners):
        return copy.deepcopy(record)
    provenance = record.get('provenance')
    if (not isinstance(provenance, list) or len(provenance) != len(assertions) + 1
            or not isinstance(provenance[0], dict)
            or any(_canonical(provenance[index + 1]) != _canonical({'source_id': 'cve',
                    'role': assertion['role'], 'provider': assertion['provider'],
                    'independent_evidence': assertion['role'] == 'cna'})
                   for index, assertion in enumerate(assertions))):
        return copy.deepcopy(record)

    result = copy.deepcopy(record)
    top_index = None
    top_field = None
    if 'descriptions' in result:
        for index, assertion in enumerate(assertions):
            for field in ('descriptions', 'rejectedReasons'):
                if (assertion.get('role') == 'cna'
                        and field in assertion
                        and _canonical(result['descriptions']) == _canonical(assertion.get(field))):
                    top_index, top_field = index, field
                    break
            if top_index is not None:
                break
        if top_index is None:
            return copy.deepcopy(record)
        result.pop('descriptions')
    for item in result['affected']:
        item.pop('assertion_role')
        item.pop('provider')
    result['provenance'] = [copy.deepcopy(provenance[0]), *[
        {'source_id': 'cve', 'assertion_index': index,
         'independent_evidence': assertion['role'] == 'cna'}
        for index, assertion in enumerate(assertions)]]
    expanded = _canonical(record)
    result['record_encoding'] = {'format': STORAGE_FORMAT,
        'expanded_bytes': len(expanded), 'expanded_sha256': _digest(expanded),
        'top_descriptions_assertion_index': top_index,
        'top_descriptions_source': top_field}
    return result if len(_canonical(result)) < len(expanded) else copy.deepcopy(record)


def _expand_record(record):
    descriptor = record.get('record_encoding')
    if descriptor is None:
        return copy.deepcopy(record)
    expected_keys = {'format', 'expanded_bytes', 'expanded_sha256',
                     'top_descriptions_assertion_index', 'top_descriptions_source'}
    if (not isinstance(descriptor, dict) or set(descriptor) != expected_keys
            or descriptor.get('format') != STORAGE_FORMAT
            or type(descriptor.get('expanded_bytes')) is not int
            or not 0 < descriptor['expanded_bytes'] <= MAX_AFFECTED_BYTES
            or not isinstance(descriptor.get('expanded_sha256'), str)
            or len(descriptor['expanded_sha256']) != 64):
        raise ValueError('invalid compact record descriptor')
    result = copy.deepcopy(record)
    result.pop('record_encoding')
    assertions, affected = result.get('assertions'), result.get('affected')
    if not isinstance(assertions, list) or not isinstance(affected, list):
        raise ValueError('invalid compact assertion inventory')
    owners = [None] * len(affected)
    projected_bytes = len(_canonical(result))
    for assertion_index, assertion in enumerate(assertions):
        if (not isinstance(assertion, dict) or not isinstance(assertion.get('role'), str)
                or not isinstance(assertion.get('provider'), dict)
                or not isinstance(assertion.get('affected_indices'), list)):
            raise ValueError('invalid compact assertion')
        provider = {key: value for key, value in assertion['provider'].items()
                    if key != 'dateUpdated'}
        for affected_index in assertion['affected_indices']:
            if (type(affected_index) is not int or not 0 <= affected_index < len(affected)
                    or owners[affected_index] is not None):
                raise ValueError('invalid compact affected ownership')
            item = affected[affected_index]
            if (not isinstance(item, dict) or 'provider' in item or 'assertion_role' in item):
                raise ValueError('ambiguous compact affected assertion')
            expanded_item = {**item, 'assertion_role': assertion['role'], 'provider': provider}
            projected_bytes += len(_canonical(expanded_item)) - len(_canonical(item))
            if projected_bytes > descriptor['expanded_bytes']:
                raise ValueError('compact record expansion exceeds declared bytes')
            owners[affected_index] = assertion_index
    if any(owner is None for owner in owners):
        raise ValueError('incomplete compact affected ownership')
    provenance = result.get('provenance')
    if (not isinstance(provenance, list) or len(provenance) != len(assertions) + 1
            or not isinstance(provenance[0], dict)):
        raise ValueError('invalid compact provenance inventory')
    for index, assertion in enumerate(assertions):
        compact = provenance[index + 1]
        if _canonical(compact) != _canonical({'source_id': 'cve', 'assertion_index': index,
                'independent_evidence': assertion['role'] == 'cna'}):
            raise ValueError('invalid compact provenance assertion')
        expanded = {'source_id': 'cve', 'role': assertion['role'],
            'provider': assertion['provider'], 'independent_evidence': assertion['role'] == 'cna'}
        projected_bytes += len(_canonical(expanded)) - len(_canonical(compact))
        if projected_bytes > descriptor['expanded_bytes']:
            raise ValueError('compact record expansion exceeds declared bytes')
    top_index = descriptor['top_descriptions_assertion_index']
    top_field = descriptor['top_descriptions_source']
    if top_index is None:
        if top_field is not None:
            raise ValueError('invalid compact description source')
    elif (type(top_index) is not int or not 0 <= top_index < len(assertions)
            or top_field not in ('descriptions', 'rejectedReasons')
            or top_field not in assertions[top_index] or 'descriptions' in result):
        raise ValueError('invalid compact description projection')
    else:
        projected_bytes += len(_canonical({'descriptions': assertions[top_index][top_field]})) - 2
    if projected_bytes != descriptor['expanded_bytes']:
        raise ValueError('compact record projected byte count mismatch')

    for affected_index, assertion_index in enumerate(owners):
        assertion = assertions[assertion_index]
        affected[affected_index]['assertion_role'] = assertion['role']
        affected[affected_index]['provider'] = {key: copy.deepcopy(value)
            for key, value in assertion['provider'].items() if key != 'dateUpdated'}
    result['provenance'] = [copy.deepcopy(provenance[0]), *[
        {'source_id': 'cve', 'role': assertion['role'],
         'provider': copy.deepcopy(assertion['provider']),
         'independent_evidence': assertion['role'] == 'cna'}
        for assertion in assertions]]
    if top_index is not None:
        result['descriptions'] = copy.deepcopy(assertions[top_index][top_field])
    expanded = _canonical(result)
    if (len(expanded) != descriptor['expanded_bytes']
            or _digest(expanded) != descriptor['expanded_sha256']):
        raise ValueError('compact record expansion mismatch')
    return result


def _format(record, size, max_logical_bytes):
    """Only an array of individually bounded advisory assertions may use v2."""
    if size <= max_logical_bytes:
        return FORMAT
    affected = record.get('affected')
    if (size > MAX_AFFECTED_BYTES or record.get('kind') != 'advisory'
            or not isinstance(affected, list) or not affected
            or any(not isinstance(item, dict) or len(_canonical(item)) > max_logical_bytes for item in affected)
            or len(_canonical({**record, 'affected': []})) > max_logical_bytes):
        raise ValueError('logical record exceeds continuation byte ceiling outside bounded affected-array format')
    return AFFECTED_FORMAT


def _part(parent, payload, index, count):
    chunk_hash = _digest(payload)
    identifier = f'{parent["record_id"]}/part/{index:03d}'
    return {'schema_version': parent['schema_version'], 'record_id': identifier,
        'source_id': parent['source_id'], 'native_id': f'{parent["native_id"]}/part/{index:03d}',
        'kind': 'continuation', 'status': 'fragment', 'title': identifier, 'aliases': [],
        'published_at': None, 'source_modified_at': None, 'first_seen_at': parent['first_seen_at'],
        'affected': [], 'references': [], 'provenance': [], 'content_hash': chunk_hash,
        'parent_record_id': parent['record_id'], 'part_index': index, 'total_parts': count,
        'payload_base64': base64.b64encode(payload).decode('ascii'), 'chunk_sha256': chunk_hash}


def split_record(record: dict, *, max_record_bytes=MAX_RECORD_BYTES,
                 max_logical_bytes=MAX_LOGICAL_BYTES) -> list[dict]:
    """Return a record or an explicit parent plus lossless bounded fragments.

    Input is a finalized logical record with its logical content hash. No input
    mutation occurs. Unsupported or oversized identities fail instead of losing
    facts. The logical body and each physical JSONL line include their final LF.
    """
    _bounds(max_record_bytes, max_logical_bytes)
    if record.get('kind') == 'continuation' or 'continuation' in record:
        raise ValueError('nested continuation is not allowed')
    expanded_data = _canonical(record)
    format_name = _format(record, len(expanded_data), max_logical_bytes)
    compression_allowed = record.get('source_id') == 'cve'
    record = _compact_record(record)
    data = _canonical(record)
    inline = [copy.deepcopy(record)] if len(data) <= max_record_bytes else None
    parent = _stub(record)
    payload = zlib.compress(data, COMPRESSION_LEVEL) if compression_allowed else data
    compressed = compression_allowed and len(payload) < len(data)
    if compressed:
        format_name = (COMPRESSED_AFFECTED_FORMAT
                       if format_name == AFFECTED_FORMAT else COMPRESSED_FORMAT)
    else:
        payload = data
    max_parts = (MAX_AFFECTED_PARTS if format_name in
                 (AFFECTED_FORMAT, COMPRESSED_AFFECTED_FORMAT) else MAX_PARTS)
    overhead = len(_canonical(_part(parent, b'', max_parts - 1, max_parts)))
    chunk_size = min(8192, (max_record_bytes - overhead) // 4 * 3)
    if chunk_size <= 0:
        if inline is not None:
            return inline
        raise ValueError('record identity exceeds continuation envelope ceiling')
    count = (len(payload) + chunk_size - 1) // chunk_size
    if count > max_parts:
        if inline is not None:
            return inline
        raise ValueError('continuation part count exceeds ceiling')
    parts = [_part(parent, payload[index * chunk_size:(index + 1) * chunk_size], index, count)
             for index in range(count)]
    parent['continuation'] = {'format': format_name, 'parts': [part['record_id'] for part in parts],
        'bytes': len(data), 'sha256': _digest(data), 'requires_reassembly': True}
    if format_name in (AFFECTED_FORMAT, COMPRESSED_AFFECTED_FORMAT):
        parent['continuation']['affected_count'] = len(record['affected'])
    if format_name in (COMPRESSED_FORMAT, COMPRESSED_AFFECTED_FORMAT):
        parent['continuation'].update(compression='zlib', compression_level=COMPRESSION_LEVEL,
            compressed_bytes=len(payload), compressed_sha256=_digest(payload))
    result = [parent, *parts]
    if any(len(_canonical(item)) > max_record_bytes for item in result):
        if inline is not None:
            return inline
        raise ValueError('continuation envelope exceeds physical byte ceiling')
    if inline is not None and (not compressed
                               or sum(len(_canonical(item)) for item in result) >= len(data)):
        return inline
    return result


def join_record(parent: dict, records_by_id: Mapping[str, dict], *,
                max_record_bytes=MAX_RECORD_BYTES, max_logical_bytes=MAX_LOGICAL_BYTES) -> dict:
    """Validate all declared fragments before returning the exact logical record."""
    _bounds(max_record_bytes, max_logical_bytes)
    if parent.get('kind') == 'continuation':
        raise ValueError('a continuation fragment cannot be a logical parent')
    if len(_canonical(parent)) > max_record_bytes:
        raise ValueError('physical parent exceeds byte ceiling')
    descriptor = parent.get('continuation')
    if descriptor is None:
        if len(_canonical(parent)) > max_logical_bytes:
            raise ValueError('logical record exceeds byte ceiling')
        logical = _expand_record(parent)
        _format(logical, len(_canonical(logical)), max_logical_bytes)
        return logical
    if not isinstance(descriptor, dict):
        raise ValueError('unsupported continuation descriptor')
    format_name = descriptor.get('format')
    expected_keys = {'format', 'parts', 'bytes', 'sha256', 'requires_reassembly'}
    if format_name in (AFFECTED_FORMAT, COMPRESSED_AFFECTED_FORMAT):
        expected_keys.add('affected_count')
    if format_name in (COMPRESSED_FORMAT, COMPRESSED_AFFECTED_FORMAT):
        expected_keys.update(('compression', 'compression_level', 'compressed_bytes',
                              'compressed_sha256'))
    if (format_name not in (FORMAT, AFFECTED_FORMAT, COMPRESSED_FORMAT,
                            COMPRESSED_AFFECTED_FORMAT) or set(descriptor) != expected_keys
            or descriptor['requires_reassembly'] is not True):
        raise ValueError('unsupported continuation descriptor')
    affected_format = format_name in (AFFECTED_FORMAT, COMPRESSED_AFFECTED_FORMAT)
    compressed_format = format_name in (COMPRESSED_FORMAT, COMPRESSED_AFFECTED_FORMAT)
    if affected_format and (type(descriptor['affected_count']) is not int
                            or descriptor['affected_count'] <= 0):
        raise ValueError('invalid affected continuation item count')
    max_parts = MAX_AFFECTED_PARTS if affected_format else MAX_PARTS
    max_total_bytes = MAX_AFFECTED_BYTES if affected_format else max_logical_bytes
    ids = descriptor['parts']
    size = descriptor['bytes']
    if (not isinstance(ids, list) or not 1 <= len(ids) <= max_parts or
            any(not isinstance(identifier, str) for identifier in ids) or len(set(ids)) != len(ids)):
        raise ValueError('invalid continuation part inventory')
    if type(size) is not int or not 0 < size <= max_total_bytes:
        raise ValueError('invalid continuation logical byte count')
    payload_size = size
    if compressed_format:
        payload_size = descriptor['compressed_bytes']
        if (descriptor['compression'] != 'zlib'
                or descriptor['compression_level'] != COMPRESSION_LEVEL
                or type(payload_size) is not int or not 0 < payload_size <= max_total_bytes
                or not isinstance(descriptor['compressed_sha256'], str)
                or len(descriptor['compressed_sha256']) != 64):
            raise ValueError('invalid compressed continuation descriptor')
    chunks, total = [], 0
    for index, identifier in enumerate(ids):
        if identifier != f'{parent["record_id"]}/part/{index:03d}':
            raise ValueError('continuation part order or identity mismatch')
        part = records_by_id.get(identifier)
        if not isinstance(part, dict) or part.get('record_id') != identifier:
            raise ValueError('missing continuation part')
        if len(_canonical(part)) > max_record_bytes:
            raise ValueError('physical continuation part exceeds byte ceiling')
        encoded = part.get('payload_base64')
        if not isinstance(encoded, str):
            raise ValueError('invalid continuation payload')
        try:
            chunk = base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error):
            raise ValueError('invalid continuation base64') from None
        if not chunk or base64.b64encode(chunk).decode('ascii') != encoded:
            raise ValueError('empty or noncanonical continuation payload')
        if _canonical(part) != _canonical(_part(parent, chunk, index, len(ids))):
            raise ValueError('continuation part metadata or hash mismatch')
        total += len(chunk)
        if total > payload_size or total > max_total_bytes:
            raise ValueError('continuation payload bytes exceed ceiling')
        chunks.append(chunk)
    payload = b''.join(chunks)
    if len(payload) != payload_size:
        raise ValueError('continuation payload size mismatch')
    if compressed_format:
        if _digest(payload) != descriptor['compressed_sha256']:
            raise ValueError('compressed continuation hash mismatch')
        inflater = zlib.decompressobj()
        try:
            data = inflater.decompress(payload, size + 1)
        except zlib.error:
            raise ValueError('invalid compressed continuation payload') from None
        if (len(data) > size or inflater.unconsumed_tail or not inflater.eof
                or inflater.unused_data):
            raise ValueError('compressed continuation exceeds logical byte ceiling')
    else:
        data = payload
    if len(data) != size or _digest(data) != descriptor['sha256']:
        raise ValueError('continuation logical size or hash mismatch')
    try:
        stored_logical = json.loads(data)
    except (ValueError, UnicodeError):
        raise ValueError('invalid continuation JSON') from None
    if (not isinstance(stored_logical, dict) or stored_logical.get('kind') == 'continuation'
            or 'continuation' in stored_logical):
        raise ValueError('nested or invalid logical continuation record')
    if _canonical(stored_logical) != data:
        raise ValueError('noncanonical logical continuation JSON')
    try:
        expected = _stub(stored_logical)
    except KeyError:
        raise ValueError('incomplete logical continuation identity') from None
    expected['continuation'] = descriptor
    if _canonical(expected) != _canonical(parent):
        raise ValueError('logical continuation identity or content hash mismatch')
    logical = _expand_record(stored_logical)
    logical_format = _format(logical, len(_canonical(logical)), max_logical_bytes)
    accepted_formats = ({FORMAT, COMPRESSED_FORMAT} if logical_format == FORMAT
                        else {AFFECTED_FORMAT, COMPRESSED_AFFECTED_FORMAT})
    if format_name not in accepted_formats:
        raise ValueError('continuation format does not match bounded logical structure')
    if affected_format and len(logical['affected']) != descriptor['affected_count']:
        raise ValueError('affected continuation item count mismatch')
    return logical


def iter_records(records: Iterable[dict] | Mapping[str, dict], *,
                 max_record_bytes=MAX_RECORD_BYTES,
                 max_logical_bytes=MAX_LOGICAL_BYTES,
                 max_snapshot_logical_bytes=MAX_SNAPSHOT_LOGICAL_BYTES) -> Iterable[dict]:
    """Yield logical rows with bounded per-record expansion.

    Consumers must exhaust the iterator before committing results: orphan
    fragments are checked at completion. ``None`` disables the optional whole
    snapshot capacity threshold without weakening any individual record checks.
    """
    _bounds(max_record_bytes, max_logical_bytes)
    if (max_snapshot_logical_bytes is not None and
            (type(max_snapshot_logical_bytes) is not int or max_snapshot_logical_bytes <= 0)):
        raise ValueError('invalid snapshot logical byte ceiling')
    values = records.values() if isinstance(records, Mapping) else records
    by_id = {}
    for record in values:
        identifier = record.get('record_id')
        if not isinstance(identifier, str) or identifier in by_id:
            raise ValueError('invalid or duplicate physical record identity')
        by_id[identifier] = record
    if isinstance(records, Mapping) and set(records) != set(by_id):
        raise ValueError('physical record map key mismatch')
    claimed, logical_bytes = set(), 0
    for identifier, parent in sorted(by_id.items()):
        if parent.get('kind') == 'continuation':
            continue
        row = join_record(parent, by_id, max_record_bytes=max_record_bytes,
                          max_logical_bytes=max_logical_bytes)
        logical_bytes += len(_canonical(row))
        if max_snapshot_logical_bytes is not None and logical_bytes > max_snapshot_logical_bytes:
            raise ValueError('snapshot logical records exceed byte ceiling')
        for part_id in parent.get('continuation', {}).get('parts', []):
            if part_id in claimed:
                raise ValueError('continuation fragment claimed by multiple parents')
            claimed.add(part_id)
        yield row
    fragments = {key for key, value in by_id.items() if value.get('kind') == 'continuation'}
    if fragments != claimed:
        raise ValueError('orphan or foreign continuation fragment')


def assemble_records(records: Iterable[dict] | Mapping[str, dict], *,
                     max_record_bytes=MAX_RECORD_BYTES,
                     max_logical_bytes=MAX_LOGICAL_BYTES,
                     max_snapshot_logical_bytes=MAX_SNAPSHOT_LOGICAL_BYTES) -> list[dict]:
    """Fully validate and materialize a snapshot before returning any results."""
    return list(iter_records(records, max_record_bytes=max_record_bytes,
        max_logical_bytes=max_logical_bytes,
        max_snapshot_logical_bytes=max_snapshot_logical_bytes))
