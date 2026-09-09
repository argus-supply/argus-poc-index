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
from collections.abc import Iterable, Mapping


FORMAT = 'json-utf8-v1'
AFFECTED_FORMAT = 'json-affected-v2'
MAX_RECORD_BYTES = 16 * 1024
MAX_LOGICAL_BYTES = 256 * 1024
MAX_PARTS = 64
MAX_AFFECTED_BYTES = 2 * 1024 * 1024
MAX_AFFECTED_PARTS = 256


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
    data = _canonical(record)
    format_name = _format(record, len(data), max_logical_bytes)
    if len(data) <= max_record_bytes:
        return [copy.deepcopy(record)]
    parent = _stub(record)
    max_parts = MAX_AFFECTED_PARTS if format_name == AFFECTED_FORMAT else MAX_PARTS
    overhead = len(_canonical(_part(parent, b'', max_parts - 1, max_parts)))
    chunk_size = min(8192, (max_record_bytes - overhead) // 4 * 3)
    if chunk_size <= 0:
        raise ValueError('record identity exceeds continuation envelope ceiling')
    count = (len(data) + chunk_size - 1) // chunk_size
    if count > max_parts:
        raise ValueError('continuation part count exceeds ceiling')
    parts = [_part(parent, data[index * chunk_size:(index + 1) * chunk_size], index, count)
             for index in range(count)]
    parent['continuation'] = {'format': format_name, 'parts': [part['record_id'] for part in parts],
        'bytes': len(data), 'sha256': _digest(data), 'requires_reassembly': True}
    if format_name == AFFECTED_FORMAT:
        parent['continuation']['affected_count'] = len(record['affected'])
    result = [parent, *parts]
    if any(len(_canonical(item)) > max_record_bytes for item in result):
        raise ValueError('continuation envelope exceeds physical byte ceiling')
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
        return copy.deepcopy(parent)
    if not isinstance(descriptor, dict):
        raise ValueError('unsupported continuation descriptor')
    format_name = descriptor.get('format')
    expected_keys = {'format', 'parts', 'bytes', 'sha256', 'requires_reassembly'}
    if format_name == AFFECTED_FORMAT:
        expected_keys.add('affected_count')
    if (format_name not in (FORMAT, AFFECTED_FORMAT) or set(descriptor) != expected_keys
            or descriptor['requires_reassembly'] is not True):
        raise ValueError('unsupported continuation descriptor')
    if format_name == AFFECTED_FORMAT and (type(descriptor['affected_count']) is not int
            or descriptor['affected_count'] <= 0):
        raise ValueError('invalid affected continuation item count')
    max_parts = MAX_AFFECTED_PARTS if format_name == AFFECTED_FORMAT else MAX_PARTS
    max_total_bytes = MAX_AFFECTED_BYTES if format_name == AFFECTED_FORMAT else max_logical_bytes
    ids = descriptor['parts']
    size = descriptor['bytes']
    if (not isinstance(ids, list) or not 1 <= len(ids) <= max_parts or
            any(not isinstance(identifier, str) for identifier in ids) or len(set(ids)) != len(ids)):
        raise ValueError('invalid continuation part inventory')
    if type(size) is not int or not 0 < size <= max_total_bytes:
        raise ValueError('invalid continuation logical byte count')
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
        if total > size or total > max_total_bytes:
            raise ValueError('continuation decoded bytes exceed ceiling')
        chunks.append(chunk)
    data = b''.join(chunks)
    if len(data) != size or _digest(data) != descriptor['sha256']:
        raise ValueError('continuation logical size or hash mismatch')
    try:
        logical = json.loads(data)
    except (ValueError, UnicodeError):
        raise ValueError('invalid continuation JSON') from None
    if not isinstance(logical, dict) or logical.get('kind') == 'continuation' or 'continuation' in logical:
        raise ValueError('nested or invalid logical continuation record')
    if _canonical(logical) != data:
        raise ValueError('noncanonical logical continuation JSON')
    if _format(logical, len(data), max_logical_bytes) != format_name:
        raise ValueError('continuation format does not match bounded logical structure')
    if format_name == AFFECTED_FORMAT and len(logical['affected']) != descriptor['affected_count']:
        raise ValueError('affected continuation item count mismatch')
    try:
        expected = _stub(logical)
    except KeyError:
        raise ValueError('incomplete logical continuation identity') from None
    expected['continuation'] = descriptor
    if _canonical(expected) != _canonical(parent):
        raise ValueError('logical continuation identity or content hash mismatch')
    return logical


def assemble_records(records: Iterable[dict] | Mapping[str, dict], *,
                     max_record_bytes=MAX_RECORD_BYTES,
                     max_logical_bytes=MAX_LOGICAL_BYTES) -> list[dict]:
    """Reassemble an entire snapshot, rejecting duplicate or orphan fragments."""
    _bounds(max_record_bytes, max_logical_bytes)
    values = records.values() if isinstance(records, Mapping) else records
    by_id = {}
    for record in values:
        identifier = record.get('record_id')
        if not isinstance(identifier, str) or identifier in by_id:
            raise ValueError('invalid or duplicate physical record identity')
        by_id[identifier] = record
    if isinstance(records, Mapping) and set(records) != set(by_id):
        raise ValueError('physical record map key mismatch')
    logical, claimed = [], set()
    for identifier, parent in sorted(by_id.items()):
        if parent.get('kind') == 'continuation':
            continue
        row = join_record(parent, by_id, max_record_bytes=max_record_bytes,
                          max_logical_bytes=max_logical_bytes)
        for part_id in parent.get('continuation', {}).get('parts', []):
            if part_id in claimed:
                raise ValueError('continuation fragment claimed by multiple parents')
            claimed.add(part_id)
        logical.append(row)
    fragments = {key for key, value in by_id.items() if value.get('kind') == 'continuation'}
    if fragments != claimed:
        raise ValueError('orphan or foreign continuation fragment')
    return logical
