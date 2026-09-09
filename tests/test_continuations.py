"""Lossless large version facts, malicious fragments, and producer/consumer fixture."""
import base64
import copy
import hashlib
import json
from pathlib import Path
import unittest

from sync.continuations import assemble_records, join_record, split_record


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


class ContinuationTests(unittest.TestCase):
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
