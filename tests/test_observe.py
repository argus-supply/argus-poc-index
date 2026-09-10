"""Offline regression coverage for continuous, explicitly qualified observation."""
import copy
import datetime as dt
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import MagicMock, patch
from urllib.parse import parse_qs, urlsplit

spec = importlib.util.spec_from_file_location('observe', Path(__file__).resolve().parents[1] / 'tools/observe.py')
observe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(observe)
START = dt.datetime(2026, 9, 9, tzinfo=dt.timezone.utc)


def timestamp(seconds=0):
    return (START + dt.timedelta(seconds=seconds)).isoformat()


def run(identifier=1, event='workflow_dispatch', seconds=1, **overrides):
    result = {'id': identifier, 'event': event, 'status': 'completed', 'conclusion': 'success',
              'created_at': timestamp(seconds), 'run_started_at': timestamp(seconds),
              'updated_at': timestamp(seconds)}
    result.update(overrides)
    return result


def healthy(seconds=0, runs=None):
    return {'sampled_at': timestamp(seconds),
        'repositories': {name: {'workflow_state': 'active', 'data_sha': 'a' * 40,
            'window_listing_complete': True, 'runs': copy.deepcopy(runs or [])}
            for name in observe.REPOS},
        'index': {'ready': True, 'freshness': {'stale': False}, 'coverage': {
            'status': 'complete', 'repositories': {'argus-supply/' + name: {
                'status': 'complete', 'sources': {source: {'status': 'ok', 'has_continuation': False}
                    for source in observe.SOURCES[name]}} for name in observe.REPOS}}}}


class QualificationTests(unittest.TestCase):
    def start(self):
        return observe.qualify(healthy(), {}, start_qualified_window=True)

    def full_window(self, runs):
        result = self.start()
        for step in range(1, 97):
            result = observe.qualify(healthy(step * 900, runs), result)
        return result

    def test_diagnostic_does_not_implicitly_start_or_reuse_legacy_elapsed_time(self):
        result = observe.qualify(healthy(86400), {'observation_started_at': timestamp(-86400),
            'elapsed_hours': 0.555, 'status': 'pending_observation'})
        self.assertEqual(result['status'], 'diagnostic_only')
        self.assertIsNone(result['observation_started_at'])
        self.assertEqual(result['qualified_hours'], 0)
        self.assertFalse(result['acceptance_passed'])

    def test_start_rejects_disabled_unready_stale_or_incomplete_sources(self):
        cases = ('disabled', 'unready', 'stale', 'partial', 'missing_source', 'source_partial', 'continuation')
        for case in cases:
            with self.subTest(case=case):
                result = healthy()
                scope = result['index']['coverage']['repositories']['argus-supply/' + observe.REPOS[0]]
                if case == 'disabled':
                    result['repositories'][observe.REPOS[0]]['workflow_state'] = 'disabled_manually'
                elif case == 'unready':
                    result['index']['ready'] = False
                elif case == 'stale':
                    result['index']['freshness']['stale'] = True
                elif case == 'partial':
                    result['index']['coverage']['status'] = 'partial'
                elif case == 'missing_source':
                    del scope['sources']['cve']
                elif case == 'source_partial':
                    scope['sources']['cve']['status'] = 'partial'
                else:
                    scope['sources']['cve']['has_continuation'] = True
                observe.qualify(result, {}, start_qualified_window=True)
                self.assertEqual(result['status'], 'qualified_window_start_rejected')
                self.assertEqual(result['qualified_hours'], 0)
                self.assertFalse(result['acceptance_passed'])

    def test_paused_window_never_resumes_or_counts_paused_time_implicitly(self):
        start = self.start()
        good = observe.qualify(healthy(900), start)
        paused = healthy(1800)
        paused['repositories'][observe.REPOS[1]]['workflow_state'] = 'disabled_manually'
        observe.qualify(paused, good)
        self.assertEqual(paused['qualification']['qualified_seconds_before_invalidation'], 900)
        resumed = observe.qualify(healthy(90000), paused)
        self.assertEqual(resumed['status'], 'qualified_window_invalidated')
        self.assertEqual(resumed['qualified_hours'], 0)
        restarted = observe.qualify(healthy(90000), resumed, start_qualified_window=True)
        self.assertEqual(restarted['status'], 'pending_qualified_observation')
        self.assertNotEqual(restarted['qualification']['window_id'], start['qualification']['window_id'])
        self.assertEqual(restarted['qualification']['qualified_seconds'], 0)

    def test_sampling_gap_invalidates_and_reports_reason_in_checks(self):
        result = observe.qualify(healthy(961), self.start())
        self.assertEqual(result['status'], 'qualified_window_invalidated')
        self.assertIn('sampling_gap_exceeded', result['qualification_checks']['problems'])

    def test_backward_clock_invalidates(self):
        result = observe.qualify(healthy(-1), self.start())
        self.assertEqual(result['status'], 'qualified_window_invalidated')
        self.assertIn('observation_clock_moved_backwards', result['qualification_checks']['problems'])

    def test_prior_successes_and_reruns_created_before_window_do_not_count(self):
        result = self.full_window([run(seconds=-2), run(2, 'schedule', seconds=-2,
            run_started_at=timestamp(1), updated_at=timestamp(1))])
        self.assertEqual(result['qualified_hours'], 24)
        self.assertEqual(result['status'], 'pending_qualified_observation')
        self.assertFalse(result['qualification_checks']['required_in_window_successes'])
        self.assertTrue(all(not repo['window_run_ids'] for repo in result['repositories'].values()))

    def test_in_window_failure_cancellation_or_skipped_job_invalidates(self):
        for conclusion in ('failure', 'cancelled', 'skipped', None):
            with self.subTest(conclusion=conclusion):
                result = observe.qualify(healthy(900, [run(conclusion=conclusion)]), self.start())
                self.assertEqual(result['status'], 'qualified_window_invalidated')
                self.assertEqual(result['qualified_hours'], 0)

    def test_malformed_run_evidence_cannot_hide_failures(self):
        for changes in ({'created_at': None}, {'updated_at': None}, {'run_started_at': timestamp(5000)},
                        {'status': 'unexpected'}, {'id': None}):
            with self.subTest(changes=changes):
                result = observe.qualify(healthy(900, [run(conclusion='failure', **changes)]), self.start())
                self.assertEqual(result['status'], 'qualified_window_invalidated')
                self.assertIn(observe.REPOS[0] + ':invalid_run_evidence', result['qualification_checks']['problems'])

    def test_pending_run_without_update_timestamp_prevents_review(self):
        result = self.full_window([run(), run(2, 'schedule'), run(3, status='queued',
            conclusion=None, updated_at=None, run_started_at=None)])
        self.assertEqual(result['qualified_hours'], 24)
        self.assertEqual(result['status'], 'pending_qualified_observation')
        self.assertEqual(len(result['qualification_checks']['pending_runs']), 3)

    def test_every_repository_needs_both_in_window_manual_and_scheduled_success(self):
        both = [run(), run(2, 'schedule')]
        previous = self.full_window(both)
        for name in observe.REPOS:
            for missing in ('workflow_dispatch', 'schedule'):
                with self.subTest(name=name, missing=missing):
                    result = healthy(86400, both)
                    result['repositories'][name]['runs'] = [row for row in both if row['event'] != missing]
                    observe.qualify(result, previous)
                    self.assertEqual(result['status'], 'pending_qualified_observation')
                    self.assertFalse(result['acceptance_passed'])

    def test_healthy_24_hours_is_review_required_never_acceptance_passed(self):
        result = self.full_window([run(), run(2, 'schedule')])
        self.assertEqual(result['qualification']['sample_count'], 97)
        self.assertEqual(result['qualified_hours'], 24)
        self.assertEqual(result['status'], 'observation_evidence_available_review_required')
        self.assertFalse(result['acceptance_passed'])
        failed = healthy(86400 + 900, [run(), run(2, 'schedule'), run(3, seconds=86401, conclusion='failure')])
        observe.qualify(failed, result)
        self.assertEqual(failed['status'], 'qualified_window_invalidated')

    def test_missing_evidence_or_truncated_listing_invalidates(self):
        for changes in ({'window_listing_complete': False}, {'error': 'unavailable'}, {'data_sha': None},
                        {'runs': None}):
            with self.subTest(changes=changes):
                result = healthy(900)
                result['repositories'][observe.REPOS[2]].update(changes)
                observe.qualify(result, self.start())
                self.assertEqual(result['status'], 'qualified_window_invalidated')

    def test_malformed_coverage_fails_closed(self):
        for index in (None, {'ready': True, 'coverage': None}, {'ready': True,
                'freshness': {'stale': False}, 'coverage': {'status': 'complete', 'repositories': None}}):
            with self.subTest(index=index):
                result = healthy()
                result['index'] = index
                observe.qualify(result, {}, start_qualified_window=True)
                self.assertEqual(result['status'], 'qualified_window_start_rejected')


class SamplingTests(unittest.TestCase):
    def api(self, path):
        if '/runs?' in path:
            return {'workflow_runs': [], 'total_count': 0}
        if path.endswith('/sync.yml'):
            return {'state': 'active'}
        if path.endswith('/git/ref/heads/data'):
            return {'object': {'sha': 'a' * 40}}
        return {'size': 12}

    def test_legacy_summary_and_raw_history_preserved_without_qualification(self):
        legacy = {'sampled_at': timestamp(), 'observation_started_at': timestamp(-1998),
                  'elapsed_hours': 0.555, 'status': 'pending_observation'}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'observation.json').write_text(json.dumps(legacy))
            raw = json.dumps(legacy, sort_keys=True)
            (root / 'observation-samples.jsonl').write_text(raw + '\n')
            with patch.object(observe, 'api', side_effect=self.api), patch.object(observe, 'read_index',
                    return_value=healthy()['index']):
                result = observe.sample(root, now=START + dt.timedelta(days=2))
            self.assertEqual(result['legacy_diagnostic'], legacy)
            self.assertEqual(result['status'], 'diagnostic_only')
            self.assertEqual(result['qualified_hours'], 0)
            self.assertEqual((root / 'observation-samples.jsonl').read_text().splitlines()[0], raw)

    def test_explicit_start_checks_three_workflow_states_and_window_query(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(observe, 'api', side_effect=self.api) as api, \
                patch.object(observe, 'read_index', return_value=healthy()['index']):
            first = observe.sample(directory, start_qualified_window=True, now=START)
            result = observe.sample(directory, now=START + dt.timedelta(seconds=900))
            self.assertEqual(result['qualification']['window_id'], first['qualification']['window_id'])
            self.assertEqual(result['qualified_hours'], 0.25)
            paths = [call.args[0] for call in api.call_args_list]
            for name in observe.REPOS:
                self.assertEqual(paths.count('repos/argus-supply/' + name + '/actions/workflows/sync.yml'), 2)
            queries = [parse_qs(urlsplit(path).query) for path in paths if '/runs?' in path]
            self.assertEqual(len(queries), 6)
            self.assertTrue(all(query['created'][0].startswith(timestamp() + '..') for query in queries))

    def test_truncation_and_null_data_object_fail_closed(self):
        def truncated(path):
            if '/runs?' in path:
                return {'workflow_runs': [run(seconds=0)], 'total_count': 31}
            if path.endswith('/git/ref/heads/data'):
                return {'object': None}
            return self.api(path)
        with tempfile.TemporaryDirectory() as directory, patch.object(observe, 'api', side_effect=truncated), \
                patch.object(observe, 'read_index', return_value=healthy()['index']):
            result = observe.sample(directory, start_qualified_window=True, now=START)
        self.assertEqual(result['status'], 'qualified_window_start_rejected')
        self.assertTrue(all(not repo['window_listing_complete'] for repo in result['repositories'].values()))

    def test_default_cli_is_single_diagnostic_sample(self):
        with patch.object(observe, 'sample', return_value={'sampled_at': timestamp(), 'status': 'diagnostic_only'}) as sample, \
                patch.object(observe.time, 'sleep') as sleep, patch('sys.stdout', new=io.StringIO()):
            observe.main(['--report-directory', '/unused'])
        sample.assert_called_once_with(Path('/unused'), start_qualified_window=False, interval_seconds=900)
        sleep.assert_not_called()

    def test_api_failures_never_copy_secret_stderr_or_exception_text(self):
        secret = 'private-token-marker'
        with patch.object(observe.subprocess, 'run', return_value=subprocess.CompletedProcess(
                ['gh'], 1, stdout=secret, stderr=secret)):
            self.assertNotIn(secret, json.dumps(observe.api('unused')))
        for error in (OSError(secret), subprocess.TimeoutExpired(secret, 45)):
            with patch.object(observe.subprocess, 'run', side_effect=error):
                result = observe.api('unused')
                self.assertIn('error', result)
                self.assertNotIn(secret, json.dumps(result))

    def test_http_headers_expose_only_numeric_rejection_evidence(self):
        for status in (403, 429):
            with self.subTest(status=status):
                output = (f'HTTP/2.0 {status} Forbidden\r\nRetry-After: 60\r\n'
                    'X-Ratelimit-Remaining: 0\r\nX-Ratelimit-Reset: 1788912060\r\n'
                    'Secret-Header: private-token-marker\r\n\r\n{"message":"private-token-marker"}')
                with patch.object(observe.subprocess, 'run', return_value=subprocess.CompletedProcess(
                        ['gh'], 1, stdout=output, stderr='private-token-marker')):
                    result = observe.api('unused')
                self.assertEqual(result['http_status'], status)
                self.assertEqual(result['retry_after_seconds'], 60)
                self.assertEqual(result['rate_limit_remaining'], 0)
                self.assertEqual(result['rate_limit_reset'], 1788912060)
                self.assertNotIn('private-token-marker', json.dumps(result))

    def test_api_parses_success_headers_and_rejects_oversized_or_invalid_envelopes(self):
        for body, valid in (('{"total_count":0,"workflow_runs":[]}', True), ('[]', False), ('secret', False)):
            with self.subTest(body=body), patch.object(observe.subprocess, 'run',
                    return_value=subprocess.CompletedProcess(['gh'], 0, stdout='HTTP/2.0 200 OK\n\n' + body)):
                self.assertEqual('error' not in observe.api('unused'), valid)
        with patch.object(observe, 'API_RESPONSE_BYTES', 20), patch.object(observe.subprocess, 'run',
                return_value=subprocess.CompletedProcess(['gh'], 0, stdout='x' * 21)):
            self.assertIn('safety limit', observe.api('unused')['error'])

    def test_actual_rejection_waits_for_primary_reset_or_secondary_retry_delay(self):
        for headers, expected in (('X-Ratelimit-Remaining: 0\nX-Ratelimit-Reset: 9000', 9000),
                ('Retry-After: 120', 1121), ('', 1061)):
            with self.subTest(headers=headers), patch.object(observe.time, 'time', return_value=1000), \
                    patch.object(observe.subprocess, 'run', return_value=subprocess.CompletedProcess(
                        ['gh'], 1, stdout='HTTP/2.0 429 Too Many Requests\n' + headers + '\n\n{}')):
                self.assertEqual(observe.api('unused')['retry_not_before'], expected)

    def test_later_page_failure_invalidates_the_qualified_window(self):
        rows = [run(identifier, seconds=1, conclusion='failure' if identifier == 150 else 'success')
                for identifier in range(1, 151)]
        with tempfile.TemporaryDirectory() as directory, patch.object(observe, 'read_index', return_value=healthy()['index']):
            with patch.object(observe, 'api', side_effect=self.api):
                observe.sample(directory, start_qualified_window=True, now=START)

            def pages(path):
                return paginated_runs(rows, path) if '/runs?' in path else self.api(path)

            with patch.object(observe, 'api', side_effect=pages):
                result = observe.sample(directory, now=START + dt.timedelta(seconds=900))
        self.assertEqual(result['status'], 'qualified_window_invalidated')
        for name, repository in result['repositories'].items():
            self.assertTrue(repository['window_listing_complete'])
            self.assertEqual(len(repository['runs']), 150)
            self.assertIn(name + ':failed_run:150', result['qualification_checks']['problems'])

    def test_rate_rejection_stops_all_later_github_requests_and_retains_partial_evidence(self):
        rows = [run(identifier, seconds=1) for identifier in range(1, 151)]

        def limited(path):
            page = int(parse_qs(urlsplit(path).query)['page'][0])
            if page == 2:
                return {'error': 'GitHub API request rejected or invalid', 'http_status': 429, 'retry_after_seconds': 60}
            return paginated_runs(rows, path)

        with tempfile.TemporaryDirectory() as directory, patch.object(observe, 'read_index', return_value=healthy()['index']), \
                patch.object(observe, 'api', side_effect=limited) as api:
            result = observe.sample(directory, now=START + dt.timedelta(seconds=900))
        self.assertEqual(api.call_count, 2)
        repositories = list(result['repositories'].values())
        self.assertEqual([len(item['runs']) for item in repositories], [100, 0, 0])
        self.assertTrue(all(not item['window_listing_complete'] for item in repositories))
        self.assertTrue(all(item['github_api_rejection']['retry_after_seconds'] == 60 for item in repositories))

    def test_upstream_retry_time_survives_next_sample_and_requests_resume_afterward(self):
        limited = {'error': 'GitHub API request rejected or invalid', 'http_status': 429,
                   'retry_not_before': int((START + dt.timedelta(seconds=1800)).timestamp())}
        with tempfile.TemporaryDirectory() as directory, patch.object(observe, 'read_index', return_value=healthy()['index']):
            with patch.object(observe, 'api', return_value=limited) as api:
                observe.sample(directory, now=START + dt.timedelta(seconds=900))
                api.assert_called_once()
            with patch.object(observe, 'api') as api:
                result = observe.sample(directory, now=START + dt.timedelta(seconds=1799))
                api.assert_not_called()
            self.assertTrue(all(not repo['window_listing_complete'] for repo in result['repositories'].values()))
            with patch.object(observe, 'api', side_effect=self.api) as api:
                result = observe.sample(directory, now=START + dt.timedelta(seconds=1800))
                self.assertEqual(api.call_count, 12)
            self.assertTrue(all(repo['window_listing_complete'] for repo in result['repositories'].values()))

    def test_index_auth_is_loopback_only_proxy_free_and_not_written_to_evidence(self):
        token = 'private-token-marker'
        opener = MagicMock()
        opener.open.return_value.__enter__.return_value.read.return_value = json.dumps(healthy()['index']).encode()
        with patch.dict(observe.os.environ, {'ARGUS_INTEL_SERVICE_TOKEN': token}), \
                patch.object(observe.urllib.request, 'build_opener', return_value=opener) as build:
            result = observe.read_index()
            self.assertTrue(result['ready'])
            self.assertNotIn(token, json.dumps(result))
            request = opener.open.call_args.args[0]
            self.assertEqual(request.full_url, 'http://127.0.0.1:8091/v1/status')
            self.assertEqual(request.get_header('Authorization'), 'Bearer ' + token)
            self.assertEqual(build.call_args.args[0].proxies, {})
            self.assertIsInstance(build.call_args.args[1], observe.NoRedirect)
            opener.open.side_effect = OSError(token)
            failure = observe.read_index()
            self.assertIn('error', failure)
            self.assertNotIn(token, json.dumps(failure))

    def test_index_rejects_oversized_or_invalid_status_without_echo(self):
        for body in (b'x' * 262145, b'private-token-marker', b'null'):
            with self.subTest(length=len(body)):
                opener = MagicMock()
                opener.open.return_value.__enter__.return_value.read.return_value = body
                with patch.object(observe.urllib.request, 'build_opener', return_value=opener):
                    result = observe.read_index()
                self.assertEqual(result, {'error': 'index status unavailable or invalid'})


def paginated_runs(rows, path):
    query = parse_qs(urlsplit(path).query)
    lower, upper = map(observe.instant, query['created'][0].split('..'))
    selected = [row for row in rows if lower <= observe.instant(row['created_at']) <= upper]
    page, per_page = int(query['page'][0]), int(query['per_page'][0])
    return {'total_count': len(selected), 'workflow_runs': selected[(page - 1) * per_page:page * per_page]}


class WorkflowRunPaginationTests(unittest.TestCase):
    def test_complete_window_larger_than_thirty_runs_uses_all_pages(self):
        rows = [run(identifier, seconds=identifier) for identifier in range(1, 252)]
        with patch.object(observe, 'api', side_effect=lambda path: paginated_runs(rows, path)) as api:
            result = observe.workflow_runs('repos/argus-supply/argus-intel-data', timestamp(), timestamp(900))
        self.assertTrue(result['listing_complete'])
        self.assertEqual(result['workflow_runs'], rows)
        self.assertEqual(api.call_count, 3)
        queries = [parse_qs(urlsplit(call.args[0]).query) for call in api.call_args_list]
        self.assertEqual([query['page'] for query in queries], [['1'], ['2'], ['3']])
        self.assertTrue(all(query['per_page'] == ['100'] for query in queries))

    def test_official_search_limit_splits_adjacent_seconds_without_losing_boundary_runs(self):
        rows = [run(identifier, seconds=identifier % 2) for identifier in range(1, 1102)]
        with patch.object(observe, 'api', side_effect=lambda path: paginated_runs(rows, path)):
            result = observe.workflow_runs('repos/argus-supply/argus-intel-data', timestamp(), timestamp(1))
        self.assertTrue(result['listing_complete'])
        self.assertEqual({row['id'] for row in result['workflow_runs']}, set(range(1, 1102)))
        self.assertEqual(result['listing_windows'], 3)
        self.assertEqual(result['total_count'], 1101)

    def test_unsplittable_official_limit_is_incomplete(self):
        with patch.object(observe, 'api', return_value={'total_count': 1000, 'workflow_runs': []}) as api:
            result = observe.workflow_runs('repos/argus-supply/argus-intel-data', timestamp(), timestamp())
        self.assertFalse(result['listing_complete'])
        self.assertIn('GitHub filtered run limit', result['error'])
        api.assert_called_once()

    def test_malformed_short_duplicate_changing_or_failed_pages_are_incomplete(self):
        first = {'total_count': 101, 'workflow_runs': [run(identifier) for identifier in range(1, 101)]}
        cases = (
            {'total_count': 101, 'workflow_runs': []},
            {'total_count': 101, 'workflow_runs': [run()]},
            {'total_count': 102, 'workflow_runs': [run(101), run(102)]},
            {'total_count': 101, 'workflow_runs': [None]},
            {'total_count': 101, 'workflow_runs': [run(101, seconds=901)]},
            {'total_count': True, 'workflow_runs': [run(101)]},
            {'total_count': 101, 'workflow_runs': None},
            {'error': 'GitHub API unavailable or invalid'},
        )
        for last in cases:
            with self.subTest(last=last), patch.object(observe, 'api', side_effect=[copy.deepcopy(first), last]):
                result = observe.workflow_runs('repos/argus-supply/argus-intel-data', timestamp(), timestamp(900))
            self.assertFalse(result['listing_complete'])
            self.assertEqual(len(result['workflow_runs']), 100)


if __name__ == '__main__':
    unittest.main()
