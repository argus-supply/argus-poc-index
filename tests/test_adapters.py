"""Source contracts and controlled failure recovery (A02/A05/A06/A07/A11)."""
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlencode, urlsplit

from sync.adapters import (AdapterResult, CVE, Run, collect, cve_path, normalize_cve, normalize_ghsa,
                           normalize_kev, normalize_template, normalize_nuclei_auxiliary, NUCLEI_AUXILIARY, raw_url)
from sync.core import ROOT, apply_result, build_snapshot, canonical as stored_json, load_policy, read_snapshot
from sync.gitstore import GitStore
from sync.http import BudgetExceeded, FetchError, Http
from sync.run import run as run_collector

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
        self.last_headers = {}

    def get_json(self, url, headers=None):
        self.urls.append(url)
        self.last_headers = {}
        return self.handler(url)

    def get_bytes(self, url, headers=None):
        self.urls.append(url)
        self.last_headers = {}
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

    def cve_missing_global_baseline(self, pages, snapshots, *, previous=None, request_limit=1000):
        identifier = 'CVE-2026-19387'
        current = cve(identifier)
        current['cveMetadata']['datePublished'] = '2026-08-09T23:55:00Z'
        cutoff = '2026-08-10T00:00:00Z'
        state = {'revision': REV, 'status': 'partial', 'completed_watermark': None, 'continuation': {
            'revision': REV, 'retention_start': cutoff, 'target_start': cutoff, 'window_end': NOW,
            'snapshot_revision': REV, 'pending': [identifier], 'offset': 0,
            'log_oldest': '2026-08-01T00:00:00Z', 'material_baseline_revision': OLDER}}

        def handler(url):
            if '/commits?' in url:
                query = parse_qs(urlsplit(url).query)
                self.assertEqual(query['sha'], [REV])
                self.assertEqual(query['path'], [cve_path(identifier)])
                self.assertEqual(query['since'], [cutoff])
                self.assertEqual(query['until'], [NOW])
                self.assertEqual(query['per_page'], ['100'])
                return pages[int(query['page'][0])]
            if '/' + OLDER + '/' in url:
                raise FetchError('upstream HTTP 404', status=404)
            if '/' + REV + '/' in url:
                return copy.deepcopy(current)
            revision = url.split('/CVEProject/cvelistV5/', 1)[1].split('/', 1)[0]
            return copy.deepcopy(snapshots[revision])

        class BoundedHTTP(HTTP):
            def get_json(self, url, headers=None):
                if len(self.urls) >= request_limit:
                    raise BudgetExceeded('fixture request budget exhausted')
                return super().get_json(url, headers)

        return BoundedHTTP(handler), previous or {'state': state}, current

    def test_cve_baseline_404_uses_proven_retained_snapshot_without_new_disclosure(self):
        historical = 'c' * 40
        old = cve('CVE-2026-19387')
        old['cveMetadata']['datePublished'] = '2026-08-09T23:55:00Z'
        old['containers']['cna']['affected'][0]['versions'][0]['lessThan'] = '1.1'
        page = [{'sha': historical, 'commit': {'committer': {'date': '2026-08-10T00:10:00Z'}}}]
        http, previous, current = self.cve_missing_global_baseline({1: page}, {historical: old})
        result = collect('cve', http, previous, now=NOW, policy={'bootstrap_days': 30})
        self.assertEqual(result.status, 'ok', result.errors)
        self.assertEqual(result.completed_watermark, NOW)
        row = result.records[0]
        self.assertEqual(row['published_at'], current['cveMetadata']['datePublished'])
        self.assertEqual(row['bootstrap_material_change']['baseline_revision'], historical)
        self.assertEqual(row['bootstrap_material_change']['window_start'], '2026-08-10T00:10:00Z')
        self.assertEqual(row['bootstrap_material_change']['changed_fields'], ['affected'])
        records, events, sources = {}, {}, {}
        apply_result(records, events, sources, 'cve', result, NOW, load_policy(ROOT / 'policy.json'))
        self.assertEqual({event['event_type'] for event in events.values()}, {'affected_corrected'})
        self.assertTrue(all(event['source_occurred_at'] is None for event in events.values()))
        self.assertEqual(records[row['record_id']]['affected'], normalize_cve(current, REV)['affected'])

    def test_cve_baseline_404_history_budget_resumes_exact_uncompared_commit(self):
        same, changed = 'c' * 40, 'd' * 40
        current = cve('CVE-2026-19387')
        current['cveMetadata']['datePublished'] = '2026-08-09T23:55:00Z'
        before = copy.deepcopy(current)
        before['containers']['cna']['metrics'] = [{'cvssV3_1': {'baseScore': 7.5}}]
        page = [{'sha': same, 'commit': {'committer': {'date': '2026-09-08T00:00:00Z'}}},
                {'sha': changed, 'commit': {'committer': {'date': '2026-08-19T00:00:00Z'}}}]
        pages, snapshots = {1: page}, {same: current, changed: before}
        first_http, previous, _ = self.cve_missing_global_baseline(pages, snapshots, request_limit=4)
        first = collect('cve', first_http, previous, now=NOW, policy={'bootstrap_days': 30})
        self.assertEqual(first.status, 'partial')
        self.assertEqual(first.records, [])
        self.assertIsNone(first.completed_watermark)
        self.assertEqual(first.continuation['offset'], 0)
        self.assertEqual(first.continuation['material_history']['offset'], 1)
        second_http, previous, _ = self.cve_missing_global_baseline(pages, snapshots,
            previous={'state': first.state}, request_limit=4)
        second = collect('cve', second_http, previous, now=NOW, policy={'bootstrap_days': 30})
        self.assertEqual(second.status, 'ok', second.errors)
        self.assertFalse(any('/' + same + '/' in url for url in second_http.urls))
        self.assertEqual(second.records[0]['bootstrap_material_change']['changed_fields'], ['scores'])
        self.assertIsNone(second.continuation)

    def test_cve_baseline_404_metadata_only_or_missing_history_never_advances_watermark(self):
        historical = 'c' * 40
        old = cve('CVE-2026-19387')
        old['cveMetadata']['datePublished'] = '2026-08-09T23:55:00Z'
        old['containers']['cna']['title'] = 'Only title changed'
        entry = {'sha': historical, 'commit': {'committer': {'date': '2026-08-10T00:10:00Z'}}}
        for page in ([], [entry]):
            with self.subTest(page=page):
                http, previous, _ = self.cve_missing_global_baseline({1: page}, {historical: old})
                result = collect('cve', http, previous, now=NOW, policy={'bootstrap_days': 30})
                self.assertEqual(result.status, 'partial')
                self.assertEqual(result.records, [])
                self.assertIsNone(result.completed_watermark)
                self.assertEqual(result.continuation['offset'], 0)
                self.assertTrue(result.continuation['material_history']['exhausted'])
                self.assertNotIn('bootstrap_old_records_without_material_change', result.state)
                self.assertIn('no proven material difference', result.errors[0]['message'])

    def test_cve_baseline_404_history_continues_second_page_after_unit_limit(self):
        current = cve('CVE-2026-19387')
        current['cveMetadata']['datePublished'] = '2026-08-09T23:55:00Z'
        identifiers = [f'{index + 1:040x}' for index in range(101)]
        entries = [{'sha': identifier, 'commit': {'committer': {'date': '2026-08-19T00:00:00Z'}}}
                   for identifier in identifiers]
        snapshots = {identifier: copy.deepcopy(current) for identifier in identifiers}
        snapshots[identifiers[-1]]['containers']['cna']['affected'][0]['versions'][0]['lessThan'] = '1.1'
        pages = {1: entries[:100], 2: entries[100:]}
        http, previous, _ = self.cve_missing_global_baseline(pages, snapshots)
        first = collect('cve', http, previous, now=NOW, policy={'bootstrap_days': 30, 'adapter_max_units': 101})
        self.assertEqual(first.status, 'partial')
        self.assertEqual(first.continuation['material_history']['page'], 2)
        self.assertEqual(first.continuation['material_history']['offset'], 0)
        self.assertEqual(first.continuation['offset'], 0)
        resumed_http, previous, _ = self.cve_missing_global_baseline(pages, snapshots, previous={'state': first.state})
        second = collect('cve', resumed_http, previous, now=NOW, policy={'bootstrap_days': 30})
        self.assertEqual(second.status, 'ok', second.errors)
        self.assertEqual(second.records[0]['bootstrap_material_change']['baseline_revision'], identifiers[-1])
        self.assertEqual([parse_qs(urlsplit(url).query)['page'] for url in resumed_http.urls if '/commits?' in url], [['2']])

    def test_cve_baseline_404_rejects_out_of_window_or_wrong_identity_proof(self):
        historical = 'c' * 40
        for date, identifier in (('2026-08-09T23:59:59Z', 'CVE-2026-19387'),
                                 ('2026-08-19T00:00:00Z', 'CVE-2026-9999')):
            with self.subTest(date=date, identifier=identifier):
                old = cve(identifier)
                old['containers']['cna']['affected'][0]['versions'][0]['lessThan'] = '1.1'
                page = [{'sha': historical, 'commit': {'committer': {'date': date}}}]
                http, previous, _ = self.cve_missing_global_baseline({1: page}, {historical: old})
                result = collect('cve', http, previous, now=NOW, policy={'bootstrap_days': 30})
                self.assertEqual(result.status, 'partial')
                self.assertEqual(result.records, [])
                self.assertEqual(result.continuation['offset'], 0)
                self.assertEqual(result.continuation['material_history']['offset'], 0)
                self.assertIsNone(result.completed_watermark)

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
        alphabet = '23456789cfghjmpqrvwx'
        rows = [ghsa('GHSA-2345-6789-22' + alphabet[i // len(alphabet)] + alphabet[i % len(alphabet)]) for i in range(101)]
        def handler(url):
            params = parse_qs(urlsplit(url).query)
            if params:
                self.assertEqual(params['type'], ['reviewed'])
                self.assertNotIn('page', params)
                if 'after' not in params:
                    query = {key: values[0] for key, values in params.items()}
                    query['after'] = 'Y3Vyc29yOm5leHQ='
                    http.last_headers = {'Link': '<https://api.github.com/advisories?' + urlencode(query) + '>; rel="next"'}
                    return rows[:100]
                return rows[100:]
            return next(row for row in rows if url.endswith(row['ghsa_id']))
        http = HTTP(handler)
        first = collect('ghsa', http, {}, now=NOW, policy={'adapter_max_units': 50})
        self.assertEqual(first.status, 'partial')
        self.assertIsNone(first.completed_watermark)
        self.assertEqual(first.continuation['offset'], 50)
        second = collect('ghsa', http, {'records': first.records, 'state': first.state}, now=NOW,
                         policy={'adapter_max_units': 300})
        self.assertEqual(second.status, 'ok')
        self.assertEqual({x['native_id'] for x in second.records}, {row['ghsa_id'] for row in rows})
        self.assertTrue(any('published=' in u for u in http.urls))
        self.assertTrue(any('updated=' in u for u in http.urls))
        self.assertTrue(any('after=' in u for u in http.urls))

    def test_ghsa_link_advances_short_pages_and_finishes_full_terminal_page(self):
        def handler(url):
            params = parse_qs(urlsplit(url).query)
            if 'updated' in params:
                return []
            if 'after' not in params:
                query = {key: values[0] for key, values in params.items()}
                query['after'] = 'opaque-next'
                http.last_headers = {'link': '<https://api.github.com/advisories?' + urlencode(query) + '>; rel="next"'}
                return [ghsa()]
            return [ghsa('GHSA-6789-cfgh-jmpq')] * 100
        http = HTTP(handler)
        result = collect('ghsa', http, {}, now=NOW, policy={})
        self.assertEqual(result.status, 'ok')
        self.assertEqual({r['native_id'] for r in result.records}, {GHSA_ID, 'GHSA-6789-cfgh-jmpq'})
        self.assertEqual(len(http.urls), 3)

    def test_ghsa_legacy_numeric_checkpoint_replays_original_window(self):
        previous = {'state': {'continuation': {'start': '2026-08-10T00:00:00Z',
            'end': NOW, 'phase': 1, 'page': 5, 'offset': 93}}}
        http = HTTP(lambda url: [ghsa()])
        result = collect('ghsa', http, previous, now='2026-09-10T00:00:00Z', policy={})
        self.assertEqual(result.status, 'ok')
        self.assertEqual(result.completed_watermark, NOW)
        self.assertEqual(parse_qs(urlsplit(http.urls[0]).query)['published'], ['2026-08-10T00:00:00Z..' + NOW])
        self.assertIn('legacy numeric', result.state['pagination_recovery'])
        self.assertEqual(len(result.records), 1)

    def test_ghsa_next_links_cannot_change_origin_path_filters_or_add_parameters(self):
        cases = ('foreign', 'path', 'filter', 'duplicate', 'numeric-page', 'two-cursors', 'userinfo', 'empty-cursor')
        for case in cases:
            def handler(url):
                params = {key: values[0] for key, values in parse_qs(urlsplit(url).query).items()}
                params['after'] = 'cursor'
                if case == 'filter':
                    params['type'] = 'unreviewed'
                if case == 'numeric-page':
                    params['page'] = '2'
                if case == 'two-cursors':
                    params['before'] = 'another'
                if case == 'empty-cursor':
                    params['after'] = ''
                target = 'https://api.github.com/advisories?' + urlencode(params)
                if case == 'foreign':
                    target = target.replace('api.github.com', 'example.com')
                if case == 'path':
                    target = target.replace('/advisories?', '/user?')
                if case == 'duplicate':
                    target += '&type=reviewed'
                if case == 'userinfo':
                    target = target.replace('https://', 'https://user@')
                http.last_headers = {'Link': '<' + target + '>; rel="next"'}
                return [ghsa()]
            http = HTTP(handler)
            result = collect('ghsa', http, {}, now=NOW, policy={})
            with self.subTest(case=case):
                self.assertEqual(result.status, 'partial')
                self.assertIsNone(result.completed_watermark)
                self.assertEqual(len(http.urls), 1)
                self.assertTrue(result.errors)

    def test_ghsa_link_cycle_cannot_advance_watermark(self):
        first_url = None
        def handler(url):
            nonlocal first_url
            if first_url is None:
                first_url = url
                next_url = url + '&after=next'
            else:
                next_url = first_url
            http.last_headers = {'Link': '<' + next_url + '>; rel="next"'}
            return [ghsa()]
        http = HTTP(handler)
        result = collect('ghsa', http, {}, now=NOW, policy={})
        self.assertEqual(result.status, 'partial')
        self.assertIsNone(result.completed_watermark)
        self.assertIn('did not advance', result.errors[0]['message'])

    def test_ghsa_changed_page_replays_instead_of_skipping_by_old_offset(self):
        rows = [ghsa(), ghsa('GHSA-6789-cfgh-jmpq')]
        phase = 0
        def handler(url):
            if '/advisories/GHSA-' in url:
                return rows[0]
            params = parse_qs(urlsplit(url).query)
            if 'updated' in params:
                return []
            return rows if phase == 0 else rows[1:]
        http = HTTP(handler)
        first = collect('ghsa', http, {}, now=NOW, policy={'adapter_max_units': 1})
        self.assertEqual(first.continuation['offset'], 1)
        phase = 1
        second = collect('ghsa', http, {'records': first.records, 'state': first.state}, now=NOW, policy={})
        self.assertEqual(second.status, 'ok')
        self.assertIn('GHSA-6789-cfgh-jmpq', {row['native_id'] for row in second.records})

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

    def test_poc_same_completed_source_and_intel_revisions_do_not_rescan_active_files(self):
        dep = dependency([normalize_cve(cve(), REV)])
        http = HTTP(lambda url: {'sha': REV} if '/commits/HEAD' in url else self.fail('unchanged active files refetched'))
        previous = {'state': {'status': 'ok', 'revision': REV, 'intel_commit_sha': REV,
            'completed_watermark': NOW, 'active_ids': ['CVE-2020-1234']}}
        result = collect('poc-in-github', http, previous, now='2026-09-10T00:00:00Z', policy={}, dependency=dep)
        self.assertEqual(result.status, 'ok')
        self.assertEqual(result.records, [])
        self.assertEqual(result.completed_watermark, NOW)
        self.assertEqual(len(http.urls), 1)

    def test_poc_changed_intel_revision_cannot_take_the_no_change_shortcut(self):
        dep = dependency([normalize_cve(cve(), REV)])
        http = HTTP(lambda url: {'sha': REV} if '/commits/HEAD' in url else [])
        previous = {'state': {'status': 'ok', 'revision': REV, 'intel_commit_sha': OLDER,
            'completed_watermark': NOW}}
        result = collect('poc-in-github', http, previous, now=NOW, policy={}, dependency=dep)
        self.assertEqual(result.status, 'ok')
        self.assertEqual(len(http.urls), 2)
        self.assertEqual(result.state['active_ids'], ['CVE-2020-1234'])

    def poc_baseline(self, indexed, *, policy=None):
        dep = dependency([normalize_cve(cve(identifier), REV) for identifier in indexed])
        def handler(url):
            if '/commits/HEAD' in url:
                return {'sha': REV}
            return indexed[url.rsplit('/', 1)[-1][:-5]]
        result = collect('poc-in-github', HTTP(handler), {}, now=NOW, policy=policy or {}, dependency=dep)
        self.assertEqual(result.status, 'ok', result.errors)
        return {'state': result.state, 'records': result.records}, dep

    def poc_reference(self, number=1):
        return {'id': number, 'html_url': f'https://github.com/example/poc-{number}',
                'description': 'Public author claim', 'owner': {'login': 'example'}}

    def test_poc_compare_fetches_only_changed_active_cve_and_preserves_other_records(self):
        indexed = {'CVE-2020-1234': [self.poc_reference(1)], 'CVE-2020-1235': [self.poc_reference(2)],
                   'CVE-2020-1236': [self.poc_reference(3)]}
        previous, dep = self.poc_baseline(indexed)
        def handler(url):
            if '/commits/HEAD' in url:
                return {'sha': OLDER}
            if '/compare/' in url:
                self.assertIn(REV + '...' + OLDER, url)
                return {'status': 'ahead', 'files': [
                    {'filename': '2020/CVE-2020-1235.json'}, {'filename': 'README.md'},
                    {'filename': '2020/CVE-2020-9999.json'}, {'filename': 'unrelated/CVE-2020-1234.json'}]}
            self.assertTrue(url.endswith('/2020/CVE-2020-1235.json'))
            return [{**self.poc_reference(2), 'description': 'Revised public claim'}]
        http = HTTP(handler)
        result = collect('poc-in-github', http, previous, now=NOW, policy={}, dependency=dep)
        self.assertEqual(result.status, 'ok')
        self.assertEqual([row['native_id'] for row in result.records], ['2'])
        self.assertEqual(result.state['last_scan_mode'], 'changed-and-new')
        self.assertEqual(len(http.urls), 3)

    def test_poc_same_source_new_active_id_only_fetches_the_new_file(self):
        previous, dep = self.poc_baseline({'CVE-2020-1234': [self.poc_reference()]})
        dep['commit_sha'] = OLDER
        dep['records'].append(normalize_cve(cve('CVE-2020-1235'), REV))
        def handler(url):
            if '/commits/HEAD' in url:
                return {'sha': REV}
            self.assertTrue(url.endswith('/2020/CVE-2020-1235.json'))
            return [self.poc_reference(2)]
        http = HTTP(handler)
        result = collect('poc-in-github', http, previous, now=NOW, policy={}, dependency=dep)
        self.assertEqual(result.status, 'ok')
        self.assertEqual([row['native_id'] for row in result.records], ['2'])
        self.assertEqual(len(http.urls), 2)

    def test_poc_changed_and_new_union_resumes_without_recomparing_or_changing_pins(self):
        previous, dep = self.poc_baseline({'CVE-2020-1234': [self.poc_reference(1)],
                                          'CVE-2020-1235': [self.poc_reference(2)]})
        dep['commit_sha'] = OLDER
        dep['records'].append(normalize_cve(cve('CVE-2020-1236'), REV))
        def handler(url):
            if '/commits/HEAD' in url:
                return {'sha': OLDER}
            if '/compare/' in url:
                return {'status': 'ahead', 'files': [{'filename': '2020/CVE-2020-1235.json'}]}
            self.assertIn('/' + OLDER + '/', url)
            return [self.poc_reference(2 if url.endswith('1235.json') else 3)]
        http = HTTP(handler)
        first = collect('poc-in-github', http, previous, now=NOW, policy={'adapter_max_units': 1}, dependency=dep)
        self.assertEqual(first.status, 'partial')
        self.assertEqual(first.continuation['scan_ids'], ['CVE-2020-1235', 'CVE-2020-1236'])
        self.assertEqual(first.continuation['offset'], 1)
        merged = {row['record_id']: row for row in previous['records'] + first.records}
        resumed_http = HTTP(lambda url: [self.poc_reference(3)] if url.endswith('/2020/CVE-2020-1236.json')
                            else self.fail('resume resolved a newer source or repeated compare'))
        final = collect('poc-in-github', resumed_http, {'state': first.state, 'records': list(merged.values())},
            now='2026-09-10T00:00:00Z', policy={}, dependency=dep)
        self.assertEqual(final.status, 'ok')
        self.assertEqual(final.completed_watermark, NOW)
        self.assertEqual(final.state['intel_commit_sha'], OLDER)
        self.assertEqual(len(resumed_http.urls), 1)

    def test_poc_removed_file_invalidates_only_its_mapping_and_keeps_reference_provenance(self):
        reference = self.poc_reference()
        previous, dep = self.poc_baseline({'CVE-2020-1234': [reference], 'CVE-2020-1235': [reference]})
        def handler(url):
            if '/commits/HEAD' in url:
                return {'sha': OLDER}
            if '/compare/' in url:
                return {'status': 'ahead', 'files': [{'filename': '2020/CVE-2020-1235.json', 'status': 'removed'}]}
            raise FetchError('upstream HTTP 404', status=404)
        result = collect('poc-in-github', HTTP(handler), previous, now=NOW, policy={}, dependency=dep)
        self.assertEqual(result.status, 'ok')
        row = result.records[0]
        self.assertEqual(row['aliases'], ['CVE-2020-1234'])
        self.assertEqual(row['status'], 'active')
        self.assertEqual(row['url'], reference['html_url'])
        self.assertEqual(row['author'], 'example')
        self.assertEqual(row['provenance'], previous['records'][0]['provenance'])
        self.assertEqual(row['mapping_history']['CVE-2020-1235']['reason'], 'source_file_absent')
        self.assertEqual(row['availability'], 'not-checked')

    def test_poc_successful_empty_file_is_source_removal_not_temporary_link_failure(self):
        previous, dep = self.poc_baseline({'CVE-2020-1234': [self.poc_reference()]})
        def handler(url):
            if '/commits/HEAD' in url:
                return {'sha': OLDER}
            if '/compare/' in url:
                return {'status': 'ahead', 'files': [{'filename': '2020/CVE-2020-1234.json'}]}
            return []
        result = collect('poc-in-github', HTTP(handler), previous, now=NOW, policy={}, dependency=dep)
        row = result.records[0]
        self.assertEqual(row['status'], 'source_deleted')
        self.assertEqual(row['advisory_ids'], [])
        self.assertEqual(row['mapping_history']['CVE-2020-1234']['reason'], 'source_reference_removed')
        self.assertEqual(row['availability'], 'not-checked')

    def test_poc_temporary_fetch_failure_preserves_old_mapping_and_unit_offset(self):
        previous, dep = self.poc_baseline({'CVE-2020-1234': [self.poc_reference()]})
        before = copy.deepcopy(previous)
        def handler(url):
            if '/commits/HEAD' in url:
                return {'sha': OLDER}
            if '/compare/' in url:
                return {'status': 'ahead', 'files': [{'filename': '2020/CVE-2020-1234.json'}]}
            raise FetchError('upstream HTTP 503; retries exhausted', status=503)
        result = collect('poc-in-github', HTTP(handler), previous, now=NOW, policy={}, dependency=dep)
        self.assertEqual(result.status, 'partial')
        self.assertEqual(result.records, [])
        self.assertEqual(result.continuation['offset'], 0)
        self.assertEqual(previous, before)

    def test_truncated_poc_compare_persists_full_scan_then_resumes_until_complete(self):
        indexed = {'CVE-2020-1234': [self.poc_reference(1)], 'CVE-2020-1235': [self.poc_reference(2)]}
        previous, dep = self.poc_baseline(indexed)
        def handler(url):
            if '/commits/HEAD' in url:
                return {'sha': OLDER}
            if '/compare/' in url:
                return {'status': 'ahead', 'files': [{'filename': '2020/CVE-2020-1234.json'}] * 300}
            self.fail('truncated enumeration must first publish a recovery checkpoint')
        first = collect('poc-in-github', HTTP(handler), previous, now=NOW, policy={}, dependency=dep)
        self.assertEqual(first.status, 'partial')
        self.assertEqual(first.records, [])
        self.assertEqual(first.continuation['scan_ids'], sorted(indexed))
        self.assertIn('truncated', first.coverage_gaps[0]['reason'])
        http = HTTP(lambda url: indexed[url.rsplit('/', 1)[-1][:-5]])
        second = collect('poc-in-github', http, {'state': first.state, 'records': previous['records']},
            now=NOW, policy={'adapter_max_units': 1}, dependency=dep)
        self.assertEqual(second.status, 'partial')
        self.assertEqual(second.continuation['offset'], 1)
        self.assertIn('truncated', second.coverage_gaps[0]['reason'])
        merged = {row['record_id']: row for row in previous['records'] + second.records}
        final = collect('poc-in-github', http, {'state': second.state, 'records': list(merged.values())},
            now=NOW, policy={}, dependency=dep)
        self.assertEqual(final.status, 'ok')
        self.assertEqual(final.coverage_gaps, [])
        self.assertEqual(final.state['active_ids'], sorted(indexed))
        self.assertEqual(final.state['last_scan_mode'], 'full-recovery')
        self.assertEqual(len(http.urls), 2)

    def test_poc_inactive_intel_mapping_expires_without_refetching_unchanged_files(self):
        previous, dep = self.poc_baseline({'CVE-2020-1234': [self.poc_reference(1)],
                                          'CVE-2020-1235': [self.poc_reference(2)]})
        dep['commit_sha'] = OLDER
        dep['records'] = dep['records'][1:]
        http = HTTP(lambda url: {'sha': REV} if '/commits/HEAD' in url else self.fail('unchanged file refetched'))
        result = collect('poc-in-github', http, previous, now=NOW, policy={}, dependency=dep)
        self.assertEqual(result.status, 'ok')
        self.assertEqual(len(result.records), 1)
        self.assertEqual(result.records[0]['status'], 'retention_removed')
        self.assertEqual(result.records[0]['mapping_history']['CVE-2020-1234']['reason'], 'outside_active_intel_set')
        self.assertEqual(len(http.urls), 1)

    def test_poc_selection_limit_removal_does_not_claim_upstream_reference_was_deleted(self):
        previous, dep = self.poc_baseline({'CVE-2020-1234': [self.poc_reference(2)]})
        def handler(url):
            if '/commits/HEAD' in url:
                return {'sha': OLDER}
            if '/compare/' in url:
                return {'status': 'ahead', 'files': [{'filename': '2020/CVE-2020-1234.json'}]}
            return [self.poc_reference(1), self.poc_reference(2)]
        result = collect('poc-in-github', HTTP(handler), previous, now=NOW,
                         policy={'max_pocs_per_vulnerability': 1}, dependency=dep)
        rows = {row['native_id']: row for row in result.records}
        self.assertEqual(result.status, 'ok')
        self.assertEqual(rows['1']['selected_count'], 1)
        self.assertEqual(rows['1']['total_known_count'], 2)
        self.assertEqual(rows['2']['status'], 'selection_removed')
        self.assertEqual(rows['2']['mapping_history']['CVE-2020-1234']['reason'], 'selection_limit')

    def test_poc_renamed_index_moves_mapping_without_reviving_the_old_alias(self):
        previous, dep = self.poc_baseline({'CVE-2020-1234': [self.poc_reference()]})
        dep['commit_sha'] = OLDER
        dep['records'].append(normalize_cve(cve('CVE-2020-1235'), REV))
        def handler(url):
            if '/commits/HEAD' in url:
                return {'sha': OLDER}
            if '/compare/' in url:
                return {'status': 'ahead', 'files': [{'filename': '2020/CVE-2020-1235.json',
                    'previous_filename': '2020/CVE-2020-1234.json', 'status': 'renamed'}]}
            if url.endswith('1234.json'):
                raise FetchError('upstream HTTP 404', status=404)
            return [self.poc_reference()]
        result = collect('poc-in-github', HTTP(handler), previous, now=NOW, policy={}, dependency=dep)
        self.assertEqual(result.status, 'ok')
        self.assertEqual(len(result.records), 1)
        self.assertEqual(result.records[0]['status'], 'active')
        self.assertEqual(result.records[0]['aliases'], ['CVE-2020-1235'])
        self.assertEqual(result.records[0]['mapping_history']['CVE-2020-1234']['reason'], 'source_file_absent')

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

    def test_official_completed_same_sha_clears_redundant_partial_cursor_without_units(self):
        previous = {'state': {'status': 'partial', 'revision': REV, 'completed_watermark': NOW,
            'last_success_at': NOW, 'continuation': {'intel_commit_sha': REV, 'offset': 400},
            'coverage_gaps': [{'reason': 'adapter_unit_budget_exhausted'}]}}
        before = copy.deepcopy(previous)
        with patch.object(Run, 'unit', side_effect=AssertionError('completed snapshot rescanned')):
            result = collect('official-references', HTTP(lambda url: self.fail('unexpected fetch')), previous,
                now='2026-09-09T02:00:00Z', policy={}, dependency=dependency([normalize_cve(cve(), REV)]))
        self.assertEqual(result.status, 'ok')
        self.assertEqual(result.records, [])
        self.assertIsNone(result.continuation)
        self.assertEqual(result.coverage_gaps, [])
        self.assertEqual(result.completed_watermark, NOW)
        self.assertEqual(previous, before)

    def test_official_same_sha_without_completion_proof_still_resumes(self):
        previous = {'state': {'status': 'partial', 'revision': REV,
            'continuation': {'intel_commit_sha': REV, 'offset': 0}}}
        result = collect('official-references', HTTP(lambda url: self.fail('unexpected fetch')), previous,
            now=NOW, policy={}, dependency=dependency([normalize_cve(cve(), REV)]))
        self.assertEqual(result.status, 'ok')
        self.assertEqual(len(result.records), 1)

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

    def nuclei_auxiliary_fixture(self, revision=REV, *, mapping=b'node.js: nodejs\n', previous=None, units=400):
        templates = {'http/technologies/a.yaml': self.template(), 'http/technologies/z.yaml': self.template()}
        bodies = {**templates, **({NUCLEI_AUXILIARY: mapping} if mapping is not None else {})}
        tree = {'truncated': False, 'tree': [{'type': 'blob', 'mode': '100644', 'path': path,
            'sha': hashlib.sha1(b'blob ' + str(len(body)).encode() + b'\0' + body).hexdigest(),
            'size': len(body)} for path, body in bodies.items()]}
        def handler(url):
            if '/commits/HEAD' in url:
                return {'sha': revision}
            if '/git/trees/' in url:
                self.assertIn(revision, url)
                return tree
            return bodies[url.split('/' + revision + '/', 1)[1]]
        client = HTTP(handler)
        result = collect('nuclei', client, previous or {}, now=NOW, policy={'adapter_max_units': units})
        return result, client

    def test_nuclei_auxiliary_mapping_preserves_old_offsets_and_next_template(self):
        first_row = self.template_row(self.template(), 'http/technologies/a.yaml')
        previous = {'records': [first_row], 'state': {'status': 'partial', 'revision': REV,
            'completed_watermark': None, 'continuation': {'revision': REV, 'offset': 1}}}
        first, _ = self.nuclei_auxiliary_fixture(previous=previous, units=1)
        self.assertEqual(first.status, 'partial')
        self.assertEqual(first.continuation['offset'], 2)
        self.assertEqual(first.records, [])
        self.assertIsNone(first.completed_watermark)
        auxiliary = first.state['auxiliary_files'][NUCLEI_AUXILIARY]
        self.assertEqual(auxiliary['mapping'], {'node.js': 'nodejs'})
        self.assertEqual(auxiliary['source_commit'], REV)
        self.assertEqual(auxiliary['classification'], 'automatic-scan-technology-tags')
        self.assertFalse(auxiliary['executed'])
        self.assertNotIn('template_id', auxiliary)
        final, client = self.nuclei_auxiliary_fixture(previous={'records': [first_row], 'state': first.state})
        self.assertEqual(final.status, 'ok', final.errors)
        self.assertEqual([row['path'] for row in final.records], ['http/technologies/z.yaml'])
        self.assertEqual(final.authoritative_ids,
            ['nuclei/http/technologies/a.yaml', 'nuclei/http/technologies/z.yaml'])
        self.assertFalse(any(NUCLEI_AUXILIARY in url for url in client.urls))
        repeated, _ = self.nuclei_auxiliary_fixture(previous={'records': [first_row, *final.records], 'state': final.state})
        self.assertEqual(repeated.status, 'ok')
        self.assertEqual(repeated.records, [])
        self.assertEqual(repeated.state['auxiliary_files'], final.state['auxiliary_files'])

    def test_nuclei_auxiliary_change_and_removal_update_metadata_without_template_events(self):
        first, _ = self.nuclei_auxiliary_fixture()
        changed, _ = self.nuclei_auxiliary_fixture(OLDER, mapping=b'node.js: nodejs,javascript\n',
            previous={'records': first.records, 'state': first.state})
        self.assertEqual(changed.status, 'ok', changed.errors)
        self.assertEqual(changed.records, [])
        before, after = first.state['auxiliary_files'][NUCLEI_AUXILIARY], changed.state['auxiliary_files'][NUCLEI_AUXILIARY]
        self.assertNotEqual(before['blob_sha'], after['blob_sha'])
        self.assertNotEqual(before['sha256'], after['sha256'])
        self.assertEqual(after['source_commit'], OLDER)
        self.assertEqual(after['mapping'], {'node.js': 'nodejs,javascript'})
        removed, _ = self.nuclei_auxiliary_fixture('c' * 40, mapping=None,
            previous={'records': first.records, 'state': changed.state})
        self.assertEqual(removed.status, 'ok', removed.errors)
        self.assertEqual(removed.records, [])
        self.assertNotIn('auxiliary_files', removed.state)
        self.assertEqual(removed.authoritative_ids, first.authoritative_ids)

    def test_nuclei_auxiliary_unknown_shape_hash_or_size_stays_unprocessed(self):
        for data in (b'id: actual-template\ninfo: {}\n', b'node.js: [nodejs]\n', b'node.js: null\n',
                     b'node.js: &a nodejs\nother: *a\n'):
            with self.subTest(data=data):
                result, _ = self.nuclei_auxiliary_fixture(mapping=data)
                self.assertEqual(result.status, 'partial')
                self.assertEqual(result.continuation['offset'], 1)
                self.assertIsNone(result.completed_watermark)
                self.assertNotIn('auxiliary_files', result.state)
        with self.assertRaisesRegex(ValueError, 'hash mismatch'):
            normalize_nuclei_auxiliary(b'node.js: nodejs', NUCLEI_AUXILIARY, REV, '0' * 40)
        with self.assertRaisesRegex(ValueError, 'oversized'):
            normalize_nuclei_auxiliary(b'x' * 65537, NUCLEI_AUXILIARY, REV, '0' * 40)
        with self.assertRaisesRegex(ValueError, 'invalid template metadata'):
            self.template_row(b'node.js: nodejs', 'http/technologies/unknown-mapping.yml')

    def test_nuclei_auxiliary_cannot_be_omitted_by_a_cursor_without_classification_evidence(self):
        result, _ = self.nuclei_auxiliary_fixture(previous={'state': {'status': 'partial',
            'revision': REV, 'continuation': {'revision': REV, 'offset': 2}}})
        self.assertEqual(result.status, 'partial')
        self.assertEqual(result.continuation['offset'], 2)
        self.assertIsNone(result.completed_watermark)
        self.assertIn('missing verified Nuclei auxiliary checkpoint', result.errors[0]['message'])

    def test_nuclei_auxiliary_remains_available_to_verified_template_dependencies(self):
        template = self.template('    payloads:\n      technologies: ' + NUCLEI_AUXILIARY + '\n')
        mapping = b'node.js: nodejs\n'
        bodies = {'http/technologies/a.yaml': template, NUCLEI_AUXILIARY: mapping}
        entries = [{'type': 'blob', 'mode': '100644', 'path': path, 'size': len(body),
            'sha': hashlib.sha1(b'blob ' + str(len(body)).encode() + b'\0' + body).hexdigest()}
            for path, body in bodies.items()]
        def handler(url):
            if '/commits/HEAD' in url:
                return {'sha': REV}
            if '/git/trees/' in url:
                return {'truncated': False, 'tree': entries}
            return bodies[url.split('/' + REV + '/', 1)[1]]
        result = collect('nuclei', HTTP(handler), {}, now=NOW, policy={})
        self.assertEqual(result.status, 'ok', result.errors)
        self.assertEqual(len(result.records), 1)
        dependency = result.records[0]['dependencies'][0]
        self.assertEqual(dependency['path'], NUCLEI_AUXILIARY)
        self.assertEqual(dependency['status'], 'verified')
        self.assertEqual(dependency['sha256'], hashlib.sha256(mapping).hexdigest())
        self.assertEqual(dependency['blob_sha'], result.state['auxiliary_files'][NUCLEI_AUXILIARY]['blob_sha'])
        self.assertEqual(result.authoritative_ids, ['nuclei/http/technologies/a.yaml'])

    def test_non_url_template_references_are_inert_text_with_warnings(self):
        references = ['https://example.com/advisory', 'Vendor advisory DOC-123',
                      'javascript:alert(1)', 'file:///etc/passwd', 'https://user:password@example.com/private', 42]
        data = self.template().replace(b'  tags:', ('  reference: ' + json.dumps(references) + '\n  tags:').encode())
        row = self.template_row(data)
        self.assertEqual(row['references'][0], {'url': references[0]})
        self.assertEqual([item['text'] for item in row['references'][1:]], [str(value) for value in references[1:]])
        self.assertTrue(all(item['retrievable'] is False and 'url' not in item for item in row['references'][1:]))
        self.assertEqual([warning['reference_index'] for warning in row['warnings']], [1, 2, 3, 4, 5])

    def test_non_url_reference_does_not_stop_later_templates_or_trigger_fetch(self):
        data = self.template().replace(b'  tags:', b'  reference: ["Vendor DOC-123"]\n  tags:')
        blob = hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
        paths = ['http/one.yaml', 'http/two.yaml']
        tree = {'truncated': False, 'tree': [{'type': 'blob', 'mode': '100644', 'path': path,
            'sha': blob, 'size': len(data)} for path in paths]}
        def handler(url):
            if '/commits/' in url:
                return {'sha': REV}
            if '/git/trees/' in url:
                return tree
            self.assertIn(url, [raw_url('projectdiscovery/nuclei-templates', REV, path) for path in paths])
            return data
        http = HTTP(handler)
        result = collect('nuclei', http, {}, now=NOW, policy={})
        self.assertEqual(result.status, 'ok')
        self.assertEqual(len(result.records), 2)
        self.assertTrue(all(row['warnings'][0]['code'] == 'non_url_reference' for row in result.records))
        self.assertEqual(len(http.urls), 4)

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


class OfficialReferenceRunnerTests(unittest.TestCase):
    def test_fresh_runners_finish_once_then_do_zero_reference_units_and_data_rewrites(self):
        policy = load_policy(ROOT / 'policy.json')
        policy['adapter_max_units'] = 2
        rows = []
        for suffix in ('2222', '2223', '2224', '2225', '2226'):
            row = normalize_ghsa(ghsa('GHSA-2345-6789-' + suffix))
            row['references'] = [{'url': 'https://example.com/advisory/' + suffix,
                                  'relationship': 'upstream-reference'}]
            rows.append(row)
        records, events, sources = {}, {}, {}
        apply_result(records, events, sources, 'ghsa', AdapterResult(records=rows, status='ok', revision=REV,
                     completed_watermark=NOW),
                     NOW, policy)
        # This fixture isolates reference batching against a complete fixed
        # dependency. Missing required intel sources correctly keep a real PoC
        # run partial, so certify the two intentionally empty source catalogs.
        for source in ('cve', 'kev'):
            apply_result(records, events, sources, source, AdapterResult(records=[], status='ok', revision=REV,
                         completed_watermark=NOW), NOW, policy)
        intel_files, _ = build_snapshot('argus-supply/argus-intel-data', records, events, sources,
                                       policy, NOW, 'fixture')

        class PublicFixtureHttp(Http):
            """Substitute external responses only; runner, state and Git are real."""
            def __init__(self, dependency_sha):
                super().__init__(policy)
                self.dependency_sha = dependency_sha

            def fork(self, **kwargs):
                return self

            def get_json(self, url, headers=None):
                self._before()
                if url == 'https://api.github.com/repos/argus-supply/argus-intel-data/git/ref/heads/data':
                    response = {'object': {'sha': self.dependency_sha}}
                elif url == 'https://api.github.com/repos/nomi-sec/PoC-in-GitHub/commits/HEAD':
                    response = {'sha': REV}
                elif url == 'https://gitlab.com/api/v4/projects/exploit-database%2Fexploitdb/repository/commits?per_page=1':
                    response = [{'id': REV}]
                else:
                    raise AssertionError('unexpected fixture URL: ' + url)
                self._charge(len(stored_json(response)))
                return response

            def get_bytes(self, url, headers=None):
                self._before()
                prefix = 'https://raw.githubusercontent.com/argus-supply/argus-intel-data/' + self.dependency_sha + '/'
                if url.startswith(prefix):
                    response = intel_files[url[len(prefix):]]
                elif url == 'https://gitlab.com/api/v4/projects/exploit-database%2Fexploitdb/repository/files/files_exploits.csv/raw?ref=' + REV:
                    response = b'id,description,codes,date_published\n'
                else:
                    raise AssertionError('unexpected fixture URL: ' + url)
                self._charge(len(response))
                return response

        units = []
        original_unit = Run.unit
        def count_unit(adapter):
            if adapter.source == 'official-references':
                units[-1] += 1
            return original_unit(adapter)

        with tempfile.TemporaryDirectory() as directory, patch.object(Run, 'unit', count_unit):
            root = Path(directory)
            remote = root / 'remote.git'
            subprocess.run(['git', 'init', '--bare', str(remote)], check=True, capture_output=True)
            attempts = []
            for index in range(5):
                units.append(0)
                with patch('sync.run.utcnow', return_value=f'2026-09-09T0{index}:00:00Z'):
                    result = run_collector('argus-poc-index', str(remote), root / f'runner-{index}',
                        f'job-{index}', policy=policy, http=PublicFixtureHttp(REV))
                attempts.append(result)
            self.assertEqual([result['status'] for result in attempts], ['partial', 'partial', 'ok', 'ok', 'ok'])
            self.assertEqual(units, [3, 3, 1, 0, 0])
            completed_commit = attempts[2]['data_commit']
            for result in attempts[3:]:
                self.assertEqual(result['data_commit'], completed_commit)
                self.assertFalse(result['published'])
                self.assertEqual(result['changed_bytes'], 0)
            _, files = GitStore(root / 'consumer', str(remote)).read('data')
            final_records, final_events, final_sources, _ = read_snapshot(files)
            self.assertEqual(len(final_records), 5)
            self.assertEqual(len(final_events), 5)
            self.assertEqual(final_sources['official-references']['completed_watermark'], '2026-09-09T02:00:00Z')
            self.assertTrue(all(row['provenance'][-1]['reference']['relationship'] == 'upstream-reference'
                                for row in final_records.values()))

            units.append(0)
            with patch('sync.run.utcnow', return_value='2026-09-09T05:00:00Z'):
                changed = run_collector('argus-poc-index', str(remote), root / 'runner-new-sha',
                    'job-new-sha', policy=policy, http=PublicFixtureHttp(OLDER))
            self.assertEqual(changed['status'], 'partial')
            self.assertEqual(units[-1], 3)
            _, changed_files = GitStore(root / 'changed-consumer', str(remote)).read('data')
            _, _, changed_sources, _ = read_snapshot(changed_files)
            state = changed_sources['official-references']
            self.assertEqual(state['continuation']['intel_commit_sha'], OLDER)
            self.assertEqual(state['continuation']['offset'], 2)
            self.assertEqual(state['completed_watermark'], '2026-09-09T02:00:00Z')


if __name__ == '__main__':
    unittest.main()
