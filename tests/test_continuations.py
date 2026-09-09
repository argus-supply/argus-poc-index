"""Lossless large version facts, malicious fragments, and producer/consumer fixture."""
import base64
import copy
import hashlib
import json
from pathlib import Path
import unittest

from sync import continuations
from sync.continuations import (assemble_records, join_record, split_record, AFFECTED_FORMAT,
                                MAX_LOGICAL_BYTES, MAX_AFFECTED_BYTES, MAX_AFFECTED_PARTS)


def encoded(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':')) + '\n').encode()


def record(size=40000):
    return {'schema_version': '1.0', 'record_id': 'cve/CVE-2026-10000', 'source_id': 'cve',
        'native_id': 'CVE-2026-10000', 'kind': 'advisory', 'status': 'active',
        'title': 'Synthetic Unicode range preservation', 'aliases': ['CVE-2026-10000'],
        'published_at': '2026-09-08T00:00:00Z', 'source_modified_at': '2026-09-09T00:00:00Z',
        'first_seen_at': '2026-09-09T01:00:00Z', 'content_hash': 'a' * 64,
        'affected': [{'product': '测试服务', 'original_ranges': [
            {'version': '1.0', 'lessThan': '2.0', 'status': 'affected',
             'original_expression': '原始范围 αβ >=1.0, <2.0; ' * (size // 40)}]}],
        'references': [{'url': 'https://example.com/public-advisory'}],
        'provenance': [{'source_id': 'cve', 'role': 'cna', 'provider': 'synthetic'}]}


def affected_record(count=2712):
    result = record(1)
    result['affected'] = [{'product': f'发行版-{index}', 'provider': {'orgId': 'fixture-adp'},
        'assertion_role': 'adp', 'original_ranges': [{'version': f'{index}.0', 'lessThan': f'{index}.5',
            'status': 'affected', 'original_expression': '原始范围 αβ; ' * 8}]} for index in range(count)]
    result['assertions'] = [{'role': 'adp', 'provider': {'orgId': 'fixture-adp'}, 'affected_indices': list(range(count))}]
    return result


def forged_affected_bundle(logical):
    """Make hash-consistent hostile bytes to exercise consumer semantic validation."""
    data = encoded(logical)
    parent = continuations._stub(logical)
    count = (len(data) + 8191) // 8192
    parts = [continuations._part(parent, data[index * 8192:(index + 1) * 8192], index, count)
             for index in range(count)]
    parent['continuation'] = {'format': AFFECTED_FORMAT, 'parts': [part['record_id'] for part in parts],
        'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest(), 'requires_reassembly': True,
        'affected_count': len(logical['affected'])}
    return [parent, *parts]


class ContinuationTests(unittest.TestCase):
    def test_affected_v2_preserves_every_entry_assertion_index_and_identity(self):
        original = affected_record()
        self.assertGreater(len(encoded(original)), MAX_LOGICAL_BYTES)
        rows = split_record(original)
        descriptor = rows[0]['continuation']
        self.assertEqual(descriptor['format'], AFFECTED_FORMAT)
        self.assertEqual(descriptor['affected_count'], 2712)
        self.assertLessEqual(len(rows) - 1, MAX_AFFECTED_PARTS)
        self.assertTrue(all(len(encoded(row)) <= 16384 for row in rows))
        self.assertEqual(assemble_records(rows), [original])
        self.assertEqual(assemble_records({row['record_id']: row for row in rows}), [original])
        self.assertEqual(split_record(copy.deepcopy(original)), rows)
        self.assertEqual(rows[0]['content_hash'], original['content_hash'])

    def test_affected_v2_does_not_raise_v1_or_non_array_field_limits(self):
        self.assertEqual(MAX_LOGICAL_BYTES, 262144)
        self.assertEqual(continuations.MAX_PARTS, 64)
        for kind in ('resource', 'poc'):
            with self.subTest(kind=kind), self.assertRaisesRegex(ValueError, 'logical record exceeds'):
                split_record({**affected_record(), 'kind': kind})
        for mode in ('huge-base', 'huge-entry', 'non-object-entry', 'total'):
            with self.subTest(mode=mode):
                original = record(1)
                if mode == 'huge-base':
                    original['title'] = 'x' * (MAX_LOGICAL_BYTES + 1)
                elif mode == 'huge-entry':
                    original['affected'] = [{'original_ranges': 'x' * (MAX_LOGICAL_BYTES + 1)}]
                elif mode == 'non-object-entry':
                    original['affected'] = ['x' * 1024] * 300
                else:
                    original = affected_record(8000)
                    self.assertGreater(len(encoded(original)), MAX_AFFECTED_BYTES)
                with self.assertRaisesRegex(ValueError, 'logical record exceeds'):
                    split_record(original)

    def test_affected_v2_consumer_rechecks_semantics_after_valid_hash_reassembly(self):
        bad_base = record(1)
        bad_base['title'] = 'x' * (MAX_LOGICAL_BYTES + 1)
        bad_item = record(1)
        bad_item['affected'] = [{'original_ranges': 'x' * (MAX_LOGICAL_BYTES + 1)}]
        bad_kind = {**affected_record(), 'kind': 'poc'}
        bad_items = {**record(1), 'affected': ['x' * 1024] * 300}
        for original in (bad_base, bad_item, bad_kind, bad_items):
            with self.subTest(kind=original['kind'], bytes=len(encoded(original))):
                with self.assertRaisesRegex(ValueError, 'logical record exceeds'):
                    assemble_records(forged_affected_bundle(original))

    def test_affected_v2_count_missing_order_or_foreign_parts_fail_atomically(self):
        original = affected_record()
        rows = split_record(original)
        for mode in ('count', 'bool-count', 'missing', 'order', 'foreign', 'orphan', 'format'):
            with self.subTest(mode=mode):
                changed = copy.deepcopy(rows)
                if mode == 'count':
                    changed[0]['continuation']['affected_count'] += 1
                elif mode == 'bool-count':
                    changed[0]['continuation']['affected_count'] = True
                elif mode == 'missing':
                    changed.pop()
                elif mode == 'order':
                    changed[0]['continuation']['parts'].reverse()
                elif mode == 'foreign':
                    changed[1]['parent_record_id'] = 'cve/foreign'
                elif mode == 'orphan':
                    extra = copy.deepcopy(changed[-1]); extra['record_id'] = 'cve/orphan'
                    changed.append(extra)
                else:
                    changed[0]['continuation']['format'] = continuations.FORMAT
                    del changed[0]['continuation']['affected_count']
                with self.assertRaises(ValueError):
                    assemble_records(changed)

    def test_affected_v2_declared_total_and_part_bounds_cannot_be_bypassed(self):
        for mode in ('bytes', 'parts', 'extra-key'):
            with self.subTest(mode=mode):
                rows = split_record(affected_record())
                descriptor = rows[0]['continuation']
                if mode == 'bytes':
                    descriptor['bytes'] = MAX_AFFECTED_BYTES + 1
                elif mode == 'parts':
                    descriptor['parts'] = [f'{rows[0]["record_id"]}/part/{index:03d}' for index in range(MAX_AFFECTED_PARTS + 1)]
                else:
                    descriptor['unverified_bypass'] = True
                with self.assertRaises(ValueError):
                    assemble_records(rows)

    def test_affected_v2_cannot_relabel_a_small_v1_payload(self):
        with self.assertRaisesRegex(ValueError, 'format does not match'):
            assemble_records(forged_affected_bundle(record(1)))

    def test_small_record_stays_a_single_independent_copy(self):
        original = record(1)
        rows = split_record(original)
        self.assertEqual(rows, [original])
        rows[0]['title'] = 'changed'
        self.assertNotEqual(rows[0], original)

    def test_two_real_world_size_classes_round_trip_without_range_loss(self):
        for size in (31000, 136000):
            with self.subTest(size=size):
                original = record(size)
                rows = split_record(original)
                self.assertGreater(len(rows), 1)
                self.assertTrue(all(len(encoded(row)) <= 16384 for row in rows))
                self.assertEqual(assemble_records(rows), [original])
                self.assertEqual(assemble_records({r['record_id']: r for r in rows}), [original])
                self.assertTrue(rows[0]['continuation']['requires_reassembly'])
                self.assertEqual(rows[0]['aliases'], [])
                self.assertTrue(all(row['aliases'] == [] for row in rows[1:]))

    def test_deterministic_fragments_and_original_content_hash(self):
        original = record()
        first, second = split_record(original), split_record(copy.deepcopy(original))
        self.assertEqual(encoded(first), encoded(second))
        self.assertEqual(first[0]['content_hash'], original['content_hash'])
        self.assertEqual(first[0]['continuation']['sha256'], hashlib.sha256(encoded(original)).hexdigest())

    def test_byte_budget_is_utf8_and_not_character_count(self):
        original = record(1)
        original['title'] = '界' * 80000
        rows = split_record(original)
        self.assertEqual(assemble_records(rows)[0]['title'], original['title'])
        original['title'] += '界' * 10000
        with self.assertRaisesRegex(ValueError, 'logical record exceeds'):
            split_record(original)

    def test_missing_duplicate_or_orphan_fragment_rejects_entire_snapshot(self):
        rows = split_record(record())
        for changed in (rows[:-1], rows + [rows[1]], rows[1:]):
            with self.subTest(count=len(changed)), self.assertRaises(ValueError):
                assemble_records(changed)

    def test_extra_foreign_or_reordered_parts_are_rejected(self):
        rows = split_record(record())
        for mode in ('foreign', 'order', 'extra'):
            changed = copy.deepcopy(rows)
            if mode == 'foreign':
                changed[1]['parent_record_id'] = 'cve/CVE-2026-99999'
            elif mode == 'order':
                changed[0]['continuation']['parts'].reverse()
            else:
                orphan = copy.deepcopy(changed[1])
                orphan['record_id'] = 'cve/CVE-2026-99999/part/000'
                changed.append(orphan)
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                assemble_records(changed)

    def test_fragment_metadata_size_hash_and_base64_are_checked(self):
        for field, value in (('part_index', 12), ('total_parts', 99), ('source_id', 'ghsa'),
            ('chunk_sha256', '0' * 64), ('content_hash', '0' * 64),
            ('payload_base64', 'not base64!'), ('payload_base64', base64.b64encode(b'changed').decode())):
            rows = split_record(record())
            rows[1][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                assemble_records(rows)
        rows = split_record(record())
        rows[1]['unexpected'] = 'x' * 16384
        with self.assertRaisesRegex(ValueError, 'physical continuation'):
            assemble_records(rows)
        rows = split_record(record())
        rows[1]['part_index'] = False
        with self.assertRaisesRegex(ValueError, 'metadata or hash mismatch'):
            assemble_records(rows)

    def test_parent_descriptor_and_logical_identity_are_checked(self):
        for field, value in (('bytes', 300000), ('bytes', 1), ('sha256', '0' * 64),
                             ('format', 'unknown'), ('requires_reassembly', False)):
            rows = split_record(record())
            rows[0]['continuation'][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                assemble_records(rows)
        rows = split_record(record())
        rows[0]['content_hash'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'identity or content hash'):
            assemble_records(rows)

    def test_nested_bundles_and_unbounded_configuration_are_rejected(self):
        for kwargs in ({'max_record_bytes': 16385}, {'max_logical_bytes': 262145},
                       {'max_record_bytes': 0}, {'max_logical_bytes': True}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                split_record(record(), **kwargs)
        original = record()
        original['continuation'] = {}
        with self.assertRaisesRegex(ValueError, 'nested'):
            split_record(original)
        with self.assertRaises(ValueError):
            join_record(split_record(record())[1], {})

    def test_map_keys_and_huge_identity_cannot_bypass_envelope_limit(self):
        rows = split_record(record())
        mapping = {row['record_id']: row for row in rows}
        mapping['wrong-key'] = mapping.pop(rows[0]['record_id'])
        with self.assertRaisesRegex(ValueError, 'map key mismatch'):
            assemble_records(mapping)
        original = record()
        original['native_id'] = 'x' * 16000
        with self.assertRaises(ValueError):
            split_record(original)

    def test_shared_fixture_matches_producer_and_reassembles_exact_original(self):
        directory = Path(__file__).resolve().parents[1] / 'fixtures' / 'continuations'
        logical = json.loads((directory / 'source-record.json').read_text())
        physical = json.loads((directory / 'physical-records.json').read_text())
        self.assertEqual(split_record(logical), physical)
        self.assertEqual(assemble_records(physical), [logical])


if __name__ == '__main__':
    unittest.main()
