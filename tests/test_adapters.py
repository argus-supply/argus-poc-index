"""Source contracts and controlled failure recovery (A02/A05/A06/A07/A11)."""
import copy
import hashlib
import json
import unittest
from urllib.parse import parse_qs, urlsplit

from sync.adapters import (CVE, collect, cve_path, normalize_cve, normalize_ghsa,
                           normalize_kev, normalize_template, raw_url)
from sync.http import FetchError

REV = 'a' * 40
OLDER = 'b' * 40
NOW = '2026-09-09T00:00:00Z'
GHSA_ID = 'GHSA-2345-6789-cfgh'


def cve(identifier='CVE-2020-1234'):
    return {'dataType': 'CVE_RECORD', 'dataVersion': '5.1',
        'cveMetadata': {'cveId': identifier, 'state': 'PUBLISHED',
            'datePublished': '2026-09-08T00:00:00Z', 'dateUpdated': '2026-09-08T00:00:00Z'},
        'containers': {'cna': {'providerMetadata': {'orgId': 'cna-one'}, 'title': 'Test advisory',
            'affected': [{'product': 'widget', 'versions': [{'version': '1.0', 'lessThan': '1.3', 'status': 'affected'}]}],
            'references': [{'url': 'https://example.org/advisory'}]},
        'adp': [{'providerMetadata': {'orgId': 'cve-program'},
                 'references': [{'url': 'https://example.org/advisory', 'tags': ['x_transferred']}]}]}}


def ghsa(identifier=GHSA_ID):
    return {'ghsa_id': identifier, 'type': 'reviewed', 'cve_id': None, 'summary': 'Widget issue',
        'published_at': '2026-09-08T00:00:00Z', 'updated_at': '2026-09-08T00:00:00Z',
        'withdrawn_at': None, 'identifiers': [{'value': identifier, 'type': 'GHSA'}],
        'references': ['https://github.com/advisories/' + identifier],
        'vulnerabilities': [{'package': {'ecosystem': 'npm', 'name': 'widget'},
                            'vulnerable_version_range': '>= 1.0, < 2.0', 'first_patched_version': '2.0'}]}


def dependency(records):
    return {'repository': 'argus-intel-data', 'commit_sha': REV,
            'manifest_sha256': 'c' * 64, 'records': records}


class HTTP:
    def __init__(self, handler):
        self.handler = handler
        self.urls = []

    def get_json(self, url, headers=None):
        self.urls.append(url)
        return self.handler(url)

    def get_bytes(self, url, headers=None):
        self.urls.append(url)
        return self.handler(url)


class SourceContracts(unittest.TestCase):
    def test_cve_preserves_cna_adp_overlap_and_recent_publication_old_number(self):
        row = normalize_cve(cve(), REV)
        self.assertEqual(row['published_at'], '2026-09-08T00:00:00Z')
        self.assertEqual(row['native_id'], 'CVE-2020-1234')
        self.assertEqual([x['assertion_role'] for x in row['references']], ['cna', 'adp'])
        self.assertEqual(row['affected'][0]['original_ranges'][0]['lessThan'], '1.3')
        self.assertEqual(len(row['assertions']), 2)

    def test_cve_rejected_not_unaffected(self):
        raw = cve()
        raw['cveMetadata']['state'] = 'REJECTED'
        self.assertEqual(normalize_cve(raw, REV)['status'], 'rejected')

    def test_unknown_cve_version_is_error(self):
        raw = cve()
        raw['dataVersion'] = '99.0'
        with self.assertRaisesRegex(ValueError, 'unsupported'):
            normalize_cve(raw, REV)

    def test_ghsa_without_cve_original_ranges_and_review_withdrawal(self):
        raw = ghsa()
        row = normalize_ghsa(raw)
        self.assertEqual(row['aliases'], [GHSA_ID])
        self.assertEqual(row['affected'][0]['original_ranges'], '>= 1.0, < 2.0')
        raw['type'] = 'unreviewed'
        self.assertEqual(normalize_ghsa(raw)['status'], 'unreviewed')
        raw['withdrawn_at'] = NOW
        self.assertEqual(normalize_ghsa(raw)['status'], 'withdrawn')

    def test_kev_old_cve_new_risk_time_is_preserved(self):
        row = normalize_kev({'cveID': 'CVE-2000-1234', 'dateAdded': '2026-09-08',
            'vulnerabilityName': 'Old exploited flaw'}, REV)
        self.assertTrue(row['known_exploited'])
        self.assertEqual(row['kev_added_at'], '2026-09-08')
        self.assertIsNone(row['affected'][0]['original_ranges'])

    def test_formatting_is_stable_but_range_and_score_edits_survive(self):
        raw = cve()
        self.assertEqual(normalize_cve(raw, REV), normalize_cve(json.loads(json.dumps(raw, indent=8)), REV))
        changed = copy.deepcopy(raw)
        changed['containers']['cna']['affected'][0]['versions'][0]['lessThan'] = '1.4'
        self.assertNotEqual(normalize_cve(raw, REV)['affected'], normalize_cve(changed, REV)['affected'])
        changed['containers']['cna']['metrics'] = [{'cvssV3_1': {'baseScore': 9.8}}]
        self.assertEqual(normalize_cve(changed, REV)['assertions'][0]['metrics'][0]['cvssV3_1']['baseScore'], 9.8)

    def test_cve_delta_pins_records_and_history_then_resumes(self):
        records = ['CVE-2020-1234', 'CVE-2020-1235']
        def handler(url):
            if '/commits/HEAD' in url:
                return {'sha': REV}
            if '/commits?' in url:
                self.assertEqual(parse_qs(urlsplit(url).query)['sha'], [REV])
                return [{'sha': OLDER}]
            if url.endswith('deltaLog.json'):
                return [{'fetchTime': '2026-09-07T00:00:00Z' if OLDER in url else '2026-09-08T00:00:00Z',
                    'new': [{'cveId': x} for x in records], 'updated': [{'cveId': records[0]}], 'error': []}]
            identifier = url.rsplit('/', 1)[-1][:-5]
            self.assertIn('/' + REV + '/', url)
            return cve(identifier)
        http = HTTP(handler)
        policy = {'retention_days': 2, 'adapter_max_units': 1}
        first = collect('cve', http, {}, now=NOW, policy=policy)
        self.assertEqual(first.status, 'partial')
        self.assertIsNone(first.completed_watermark)
        self.assertEqual(first.continuation['offset'], 1)
        second = collect('cve', http, {'records': first.records, 'state': first.state}, now=NOW,
                         policy={**policy, 'adapter_max_units': 20})
        self.assertEqual(second.status, 'ok')
        self.assertEqual(second.completed_watermark, NOW)
        self.assertEqual(len(second.records), 2)
        self.assertEqual(sum('/commits/HEAD' in u for u in http.urls), 1)

    def test_cve_oversize_keeps_ranges_and_watermark_before_failed_unit(self):
        huge = cve()
        huge['containers']['cna']['affected'][0]['versions'] = [{'version': str(x), 'status': 'affected'} for x in range(10000)]
        def handler(url):
            if '/commits/HEAD' in url:
                return {'sha': REV}
            if url.endswith('deltaLog.json'):
                return [{'fetchTime': '2026-09-08T00:00:00Z', 'new': [{'cveId': 'CVE-2020-1234'}], 'updated': []}]
            return huge
        result = collect('cve', HTTP(handler), {}, now=NOW, policy={})
        self.assertEqual(result.status, 'partial')
        self.assertEqual(result.records, [])
        self.assertEqual(result.continuation['offset'], 0)
        self.assertIsNone(result.completed_watermark)
        self.assertIn('oversize_record', result.errors[0]['message'])

    def test_cve_bootstrap_publishes_recent_seven_days_before_older_backfill(self):
        def handler(url):
            if '/commits/HEAD' in url:
                return {'sha': REV}
            if url.endswith('deltaLog.json'):
                return [{'fetchTime': '2026-09-08T00:00:00Z', 'new': [{'cveId': 'CVE-2000-1234'}]},
                    {'fetchTime': '2026-08-01T00:00:00Z', 'new': [{'cveId': 'CVE-2026-9999'}]}]
            return cve(url.rsplit('/', 1)[-1][:-5])
        first = collect('cve', HTTP(handler), {}, now=NOW, policy={})
        self.assertEqual(first.status, 'partial')
        self.assertEqual([x['native_id'] for x in first.records], ['CVE-2000-1234'])
        self.assertIsNone(first.completed_watermark)
        self.assertEqual(first.continuation['window_upper'], '2026-09-02T00:00:00Z')
        final = collect('cve', HTTP(handler), {'state': first.state, 'records': first.records}, now=NOW, policy={})
        self.assertEqual(final.status, 'ok')
        self.assertEqual(final.completed_watermark, NOW)

    def test_cve_steady_compare_keeps_late_update_without_refetching_delta(self):
        old = normalize_cve(cve(), OLDER)
        raw = cve()
        raw['containers']['cna']['affected'][0]['versions'][0]['lessThan'] = '1.4'
        def handler(url):
            self.assertNotIn('deltaLog', url)
            if '/commits/HEAD' in url:
                return {'sha': REV}
            if '/compare/' in url:
                self.assertIn(OLDER+'...'+REV, url)
                return {'status': 'ahead', 'files': [{'filename': cve_path(old['native_id'])}],
                    'total_commits': 1, 'commits': [{'sha': REV}]}
            return raw
        previous = {'records': [old], 'state': {'status': 'ok', 'revision': OLDER,
            'completed_watermark': '2026-09-08T01:00:00Z'}}
        result = collect('cve', HTTP(handler), previous, now=NOW, policy={})
        self.assertEqual(result.status, 'ok')
        self.assertEqual(result.records[0]['source_modified_at'], '2026-09-08T00:00:00Z')
        self.assertEqual(result.records[0]['affected'][0]['original_ranges'][0]['lessThan'], '1.4')

    def old_bootstrap(self, *, material=False, absent_baseline=False, already_retained=False, rejected_unpublished=False):
        current = cve()
        current['cveMetadata']['datePublished'] = '2000-01-01T00:00:00Z'
        current['containers']['cna']['providerMetadata']['dateUpdated'] = '2026-09-08T00:00:00Z'
        before = copy.deepcopy(current)
        if rejected_unpublished:
            current['cveMetadata'].pop('datePublished')
            current['cveMetadata']['state'] = 'REJECTED'
        before['containers']['cna']['providerMetadata']['dateUpdated'] = '2000-01-01T00:00:00Z'
        before['containers']['cna']['title'] = 'Previous formatting/title'
        if material:
            before['containers']['cna']['affected'][0]['versions'][0]['lessThan'] = '1.2'
        def handler(url):
            if '/commits/HEAD' in url:
                return {'sha': REV}
            if '/commits?' in url:
                return [{'sha': OLDER}]
            if url.endswith('deltaLog.json'):
                return [{'fetchTime': '2026-09-08T00:00:00Z', 'updated': [{'cveId': 'CVE-2020-1234'}]},
                        {'fetchTime': '2026-08-01T00:00:00Z', 'new': []}]
            if OLDER in url:
                if absent_baseline:
                    raise FetchError('upstream HTTP 404', status=404)
                return before
            return current
        previous = {'records': [normalize_cve(before, OLDER)]} if already_retained else {}
        return collect('cve', HTTP(handler), previous, now=NOW, policy={'bootstrap_days': 30})

    def test_old_metadata_only_update_does_not_bootstrap_as_new_disclosure(self):
        result = self.old_bootstrap()
        self.assertEqual(result.status, 'ok')
        self.assertEqual(result.records, [])
        self.assertEqual(result.state['bootstrap_old_records_without_material_change'], 1)

    def test_old_proven_range_change_retains_material_interval_and_baseline(self):
        result = self.old_bootstrap(material=True)
        self.assertEqual(result.status, 'ok')
        self.assertEqual(result.records[0]['bootstrap_material_change']['changed_fields'], ['affected'])
        self.assertEqual(result.records[0]['bootstrap_material_change']['baseline_revision'], OLDER)
        self.assertEqual(result.records[0]['published_at'], '2000-01-01T00:00:00Z')

    def test_unknown_old_baseline_keeps_unit_and_watermark_pending(self):
        result = self.old_bootstrap(absent_baseline=True)
        self.assertEqual(result.status, 'partial')
        self.assertEqual(result.continuation['offset'], 0)
        self.assertIsNone(result.completed_watermark)
        self.assertIn('comparison unknown', result.errors[0]['message'])

    def test_existing_old_record_is_refreshed_without_discovery_reclassification(self):
        result = self.old_bootstrap(already_retained=True)
        self.assertEqual(result.status, 'ok')
        self.assertEqual(len(result.records), 1)
        self.assertNotIn('bootstrap_material_change', result.records[0])

    def test_unpublished_rejected_identifier_retains_proven_rejection(self):
        result = self.old_bootstrap(absent_baseline=True, rejected_unpublished=True)
        self.assertEqual(result.status, 'ok')
        self.assertIsNone(result.records[0]['published_at'])
        self.assertEqual(result.records[0]['status'], 'rejected')
        self.assertEqual(result.records[0]['bootstrap_material_change']['changed_fields'], ['status'])
        self.assertEqual(result.records[0]['bootstrap_material_change']['before_status'], 'absent')

    def test_truncated_cve_compare_resumes_pinned_commit_pages(self):
        def handler(url):
            if '/commits/HEAD' in url:
                return {'sha': REV}
            if '/compare/' in url:
                return {'status': 'ahead', 'files': [{'filename': 'cves/deltaLog.json'}] * 300,
                    'total_commits': 1, 'commits': [{'sha': REV}]}
            if '/commits/'+REV in url:
                return {'files': [{'filename': cve_path('CVE-2020-1234')}, {'filename': cve_path('CVE-2020-1235')}]}
            return cve(url.rsplit('/', 1)[-1][:-5])
        previous = {'records': [], 'state': {'status': 'ok', 'revision': OLDER,
            'completed_watermark': '2026-09-08T01:00:00Z'}}
        first = collect('cve', HTTP(handler), previous, now=NOW, policy={'adapter_max_units': 2})
        self.assertEqual(first.status, 'partial')
        self.assertEqual(first.continuation['file_offset'], 1)
        self.assertEqual(first.completed_watermark, previous['state']['completed_watermark'])
        final = collect('cve', HTTP(handler), {'state': first.state, 'records': first.records}, now=NOW, policy={})
        self.assertEqual(final.status, 'ok')
        self.assertEqual([x['native_id'] for x in final.records], ['CVE-2020-1235'])

    def test_cve_removed_at_fixed_revision_yields_source_tombstone(self):
        row = normalize_cve(cve(), OLDER)
        def handler(url):
            if '/commits/HEAD' in url:
                return {'sha': REV}
            if '/compare/' in url:
                return {'status': 'ahead', 'files': [{'filename': cve_path(row['native_id']), 'status': 'removed'}]}
            raise FetchError('upstream HTTP 404', status=404)
        result = collect('cve', HTTP(handler), {'records': [row], 'state': {'status': 'ok',
            'revision': OLDER, 'completed_watermark': '2026-09-08T01:00:00Z'}}, now=NOW, policy={})
        self.assertEqual(result.status, 'ok')
        self.assertEqual(result.records[0]['status'], 'source_deleted')

    def test_ghsa_full_pagination_equal_timestamps_overlap_and_resume(self):
        def handler(url):
            params = parse_qs(urlsplit(url).query)
            if params:
                self.assertEqual(params['type'], ['reviewed'])
                if params['page'] == ['1']:
                    return [ghsa() for _ in range(100)]
                return [ghsa('GHSA-6789-cfgh-jmpq')]
            return ghsa()
        http = HTTP(handler)
        first = collect('ghsa', http, {}, now=NOW, policy={'adapter_max_units': 50})
        self.assertEqual(first.status, 'partial')
        self.assertIsNone(first.completed_watermark)
        self.assertEqual(first.continuation['offset'], 50)
        second = collect('ghsa', http, {'records': first.records, 'state': first.state}, now=NOW,
                         policy={'adapter_max_units': 300})
        self.assertEqual(second.status, 'ok')
        self.assertEqual({x['native_id'] for x in second.records}, {GHSA_ID, 'GHSA-6789-cfgh-jmpq'})
        self.assertTrue(any('published=' in u for u in http.urls))
        self.assertTrue(any('updated=' in u for u in http.urls))

    def test_ghsa_retained_direct_reconciliation_detects_review_removal(self):
        removed = ghsa()
        removed['type'] = 'unreviewed'
        result = collect('ghsa', HTTP(lambda u: [] if '?' in u else removed),
            {'records': [normalize_ghsa(ghsa())], 'state': {'completed_watermark': NOW}}, now=NOW, policy={})
        self.assertEqual(result.status, 'ok')
        self.assertEqual(result.records[0]['status'], 'unreviewed')

    def test_incomplete_kev_catalog_is_never_authoritative(self):
        def handler(url):
            return {'sha': REV} if '/commits/' in url else {'count': 2, 'vulnerabilities': []}
        result = collect('kev', HTTP(handler), {}, now=NOW, policy={})
        self.assertEqual(result.status, 'partial')
        self.assertIsNone(result.authoritative_ids)

    def test_poc_deduplicates_and_preserves_unknown_verification(self):
        raw = {'id': 123, 'html_url': 'https://github.com/example/poc', 'owner': {'login': 'example'}}
        def handler(url):
            return {'sha': REV} if '/commits/' in url else [raw, raw]
        result = collect('poc-in-github', HTTP(handler), {}, now=NOW, policy={},
            dependency=dependency([normalize_cve(cve(), REV), normalize_cve(cve('CVE-2020-1235'), REV)]))
        self.assertEqual(result.status, 'ok')
        self.assertEqual(len(result.records), 1)
        row = result.records[0]
        self.assertEqual(row['advisory_ids'], ['CVE-2020-1234', 'CVE-2020-1235'])
        self.assertEqual(row['total_known_count'], 1)
        self.assertEqual(row['verification']['status'], 'unverified')
        self.assertIsNone(row['upstream_revision'])

    def test_broken_index_fetch_is_partial_not_deletion(self):
        def handler(url):
            if '/commits/' in url:
                return {'sha': REV}
            raise TimeoutError('temporary upstream outage')
        result = collect('poc-in-github', HTTP(handler), {}, now=NOW, policy={},
            dependency=dependency([normalize_cve(cve(), REV)]))
        self.assertEqual(result.status, 'partial')
        self.assertIsNone(result.authoritative_ids)
        self.assertEqual(result.errors[0]['code'], 'TimeoutError')

    def test_poc_mapping_survives_a_restart_between_two_cve_index_files(self):
        raw = {'id': 123, 'html_url': 'https://github.com/example/poc', 'owner': {'login': 'example'}}
        http = HTTP(lambda u: {'sha': REV} if '/commits/' in u else [raw])
        dep = dependency([normalize_cve(cve(), REV), normalize_cve(cve('CVE-2020-1235'), REV)])
        first = collect('poc-in-github', http, {}, now=NOW, policy={'adapter_max_units': 1}, dependency=dep)
        self.assertEqual(first.status, 'partial')
        last = collect('poc-in-github', http, {'records': first.records, 'state': first.state}, now=NOW,
                       policy={'adapter_max_units': 1}, dependency=dep)
        self.assertEqual(last.status, 'ok')
        self.assertEqual(last.records[0]['advisory_ids'], ['CVE-2020-1234', 'CVE-2020-1235'])

    def test_exploitdb_retains_recent_non_cve_reference_without_invented_link(self):
        csv_data = b'id,description,codes,date_published\n1,Recent reference,,2026-09-08\n2,Old irrelevant,,2000-01-01\n'
        http = HTTP(lambda u: [{'id': REV}] if '/commits?' in u else csv_data)
        result = collect('exploitdb', http, {}, now=NOW, policy={}, dependency=dependency([]))
        self.assertEqual(result.status, 'ok')
        self.assertEqual(len(result.records), 1)
        self.assertEqual(result.records[0]['aliases'], [])
        self.assertEqual(result.records[0]['mapping_confidence'], 'unknown')

    def test_official_references_keep_origin_without_claiming_poc(self):
        result = collect('official-references', HTTP(lambda u: self.fail('unexpected fetch')), {},
            now=NOW, policy={}, dependency=dependency([normalize_cve(cve(), REV)]))
        self.assertEqual(result.status, 'ok')
        self.assertEqual(result.records[0]['verification']['status'], 'reference-only')
        self.assertEqual(result.records[0]['intel_commit_sha'], REV)
        origins = [x['reference']['assertion_role'] for x in result.records[0]['provenance'] if 'reference' in x]
        self.assertEqual(origins, ['cna', 'adp'])

    def template(self, extra=''):
        return ('id: widget-panel\ninfo:\n  name: Widget panel\n  tags: panel,auth\n  metadata:\n    product: widget\n'
                'http:\n  - method: GET\n    path: ["{{BaseURL}}/"]\n' + extra).encode()

    def template_row(self, data, path='http/CVE-2000-1234.yaml'):
        blob = hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
        return normalize_template(data, path, REV, blob)

    def test_non_cve_template_path_is_not_advisory_mapping_and_prerequisites_unknown(self):
        row = self.template_row(self.template())
        self.assertEqual(row['aliases'], [])
        self.assertEqual(row['products'], {'product': 'widget'})
        self.assertEqual(row['requirements']['authentication'], 'required')
        self.assertIsNone(row['engine']['minimum_version'])
        self.assertFalse(row['verification']['executed'])

    def test_unsafe_yaml_duplicate_alias_and_python_tags_rejected(self):
        for data in (b'id: one\nid: two\ninfo: {}', b'id: &a thing\ninfo: *a',
                     b'id: !!python/object/apply:os.system ["touch /tmp/never"]\ninfo: {}'):
            with self.subTest(data=data), self.assertRaises((ValueError, Exception)):
                self.template_row(data)

    def test_unsafe_dependency_path_and_blob_mismatch_rejected(self):
        data = self.template('    payloads:\n      users: ../outside.txt\n')
        with self.assertRaisesRegex(ValueError, 'unsafe'):
            self.template_row(data)
        with self.assertRaisesRegex(ValueError, 'hash mismatch'):
            normalize_template(self.template(), 'http/panel.yaml', REV, '0' * 40)

    def test_template_dependency_missing_or_changed_hash_fails_atomically(self):
        data = self.template('    payloads:\n      users: helpers/users.txt\n')
        blob = hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
        tree = {'truncated': False, 'tree': [{'type': 'blob', 'mode': '100644',
            'path': 'http/panel.yaml', 'sha': blob, 'size': len(data)}]}
        def handler(url):
            if '/commits/' in url:
                return {'sha': REV}
            if '/git/trees/' in url:
                return tree
            return data
        result = collect('nuclei', HTTP(handler), {}, now=NOW, policy={})
        self.assertEqual(result.status, 'partial')
        self.assertEqual(result.records, [])
        self.assertIn('missing template dependency', result.errors[0]['message'])
        self.assertEqual(result.continuation['offset'], 0)

    def test_truncated_tree_and_oversize_tree_cannot_delete(self):
        for tree, policy in [({'truncated': True, 'tree': []}, {}),
            ({'truncated': False, 'tree': [{'type': 'blob', 'mode': '100644',
                'path': 'http/panel.yaml', 'sha': REV, 'size': 10}]}, {'max_tree_bytes': 10})]:
            result = collect('nuclei', HTTP(lambda u: {'sha': REV} if '/commits/' in u else tree), {}, now=NOW, policy=policy)
            self.assertEqual(result.status, 'partial')
            self.assertIsNone(result.authoritative_ids)

    def test_complete_tree_deletion_inventory_is_available_even_when_content_unchanged(self):
        data = self.template()
        row = self.template_row(data, 'http/panel.yaml')
        tree = {'truncated': False, 'tree': [{'type': 'blob', 'mode': '100644',
            'path': row['path'], 'sha': row['blob_sha'], 'size': len(data)}]}
        http = HTTP(lambda u: {'sha': REV} if '/commits/' in u else tree)
        result = collect('nuclei', http, {'records': [row], 'state': {}}, now=NOW, policy={})
        self.assertEqual(result.status, 'ok')
        self.assertEqual(result.records, [])
        self.assertEqual(result.authoritative_ids, ['nuclei/http/panel.yaml'])
        self.assertNotIn('inventory', result.state)

    def test_regular_executable_mode_is_parsed_without_executing_and_unrelated_symlink_ignored(self):
        data = self.template()
        row = self.template_row(data, 'http/panel.yaml')
        tree = {'truncated': False, 'tree': [
            {'type': 'blob', 'mode': '100755', 'path': row['path'], 'sha': row['blob_sha'], 'size': len(data)},
            {'type': 'blob', 'mode': '120000', 'path': 'helpers/unrelated-link', 'sha': OLDER, 'size': 20}]}
        def handler(url):
            if '/commits/' in url:
                return {'sha': REV}
            return tree if '/git/trees/' in url else data
        result = collect('nuclei', HTTP(handler), {}, now=NOW, policy={})
        self.assertEqual(result.status, 'ok')
        self.assertFalse(result.records[0]['verification']['executed'])


if __name__ == '__main__':
    unittest.main()
