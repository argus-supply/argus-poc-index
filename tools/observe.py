"""Read-only diagnostics and explicitly started, continuously checked observation."""
import argparse
import copy
import datetime as dt
import json
import os
from pathlib import Path
import re
import subprocess
import time
import urllib.parse
import urllib.request
import uuid

REPOS = ('argus-intel-data', 'argus-poc-index', 'argus-detection-resources')
SOURCES = dict(zip(REPOS, (('cve', 'ghsa', 'kev'),
    ('official-references', 'exploitdb', 'poc-in-github'), ('nuclei',))))
WINDOW_SECONDS = 24 * 3600
# GitHub documents 100 results/page and 1,000 results per filtered search:
# https://docs.github.com/en/rest/actions/workflow-runs#list-workflow-runs-for-a-workflow
RUNS_PER_PAGE = 100
FILTERED_RUN_LIMIT = 1000
API_RESPONSE_BYTES = 16 * 1024 * 1024
REJECTION_FIELDS = ('http_status', 'retry_after_seconds', 'rate_limit_remaining',
    'rate_limit_reset', 'retry_not_before')


def instant(value):
    if not isinstance(value, str):
        raise ValueError('observation timestamp must be text')
    value = dt.datetime.fromisoformat(value.replace('Z', '+00:00'))
    if value.tzinfo is None:
        raise ValueError('observation timestamps require a timezone')
    return value.astimezone(dt.timezone.utc)


def api(path):
    """Read one page; report actual HTTP rejection without echoing upstream text.

    No retry follows a 403/429. The caller defers the sample, including all
    remaining repository requests, instead of spending through upstream limits.
    """
    try:
        result = subprocess.run(['gh', 'api', '--include', path], capture_output=True, text=True, timeout=45)
        if len(result.stdout.encode()) > API_RESPONSE_BYTES:
            return {'error': 'GitHub API response exceeds individual JSON safety limit'}
        head, separator, body = result.stdout.replace('\r\n', '\n').partition('\n\n')
        status = re.match(r'^HTTP/\S+ (\d{3})(?:\s|$)', head)
        metadata = {}
        if status and separator:
            metadata['http_status'] = int(status[1])
            headers = dict(line.lower().split(':', 1) for line in head.splitlines()[1:] if ':' in line)
            for header, key in (('retry-after', 'retry_after_seconds'),
                    ('x-ratelimit-remaining', 'rate_limit_remaining'), ('x-ratelimit-reset', 'rate_limit_reset')):
                value = headers.get(header, '').strip()
                if re.fullmatch(r'\d{1,12}', value):
                    metadata[key] = int(value)
        if result.returncode or not status or not separator or not 200 <= metadata['http_status'] < 300:
            if metadata.get('http_status') in (403, 429):
                # GitHub requires at least a minute after secondary throttling
                # without Retry-After, or waiting for primary quota reset.
                retry_at = int(time.time()) + 1 + max(60, metadata.get('retry_after_seconds', 0))
                if metadata.get('rate_limit_remaining') == 0:
                    retry_at = max(retry_at, metadata.get('rate_limit_reset', 0))
                metadata['retry_not_before'] = retry_at
            return {'error': 'GitHub API request rejected or invalid', 'exit_code': result.returncode, **metadata}
        value = json.loads(body)
        return value if isinstance(value, dict) else {'error': 'invalid GitHub API envelope'}
    except (OSError, subprocess.TimeoutExpired, ValueError):
        return {'error': 'GitHub API unavailable or invalid'}


def workflow_runs(prefix, started, ended):
    """Enumerate fixed creation windows, splitting at GitHub's search limit.

    Inclusive windows use whole seconds, GitHub's run timestamp precision.
    Qualification still checks the original exact observation timestamps.
    Counts must remain stable and every page must be complete and disjoint.
    """
    lower, upper = instant(started).replace(microsecond=0), instant(ended).replace(microsecond=0)
    rows, requests, windows = {}, 0, 0

    def result(error=None, **details):
        return {'workflow_runs': list(rows.values()), 'total_count': len(rows),
            'listing_complete': error is None, 'listing_requests': requests,
            'listing_windows': windows, **({'error': error} if error else {}), **details}

    if lower > upper:
        return result('invalid workflow run observation interval')
    pending = [(lower, upper)]
    while pending:
        lower, upper = pending.pop()
        windows += 1
        page, expected, seen = 1, None, set()
        while True:
            params = {'per_page': RUNS_PER_PAGE, 'page': page, 'exclude_pull_requests': 'true',
                'created': lower.isoformat() + '..' + upper.isoformat()}
            response = api(prefix + '/actions/workflows/sync.yml/runs?' + urllib.parse.urlencode(params))
            requests += 1
            if response.get('error'):
                return result(response['error'], **{key: response[key] for key in REJECTION_FIELDS if key in response})
            total, batch = response.get('total_count'), response.get('workflow_runs')
            if type(total) is not int or total < 0 or not isinstance(batch, list) or len(batch) > RUNS_PER_PAGE:
                return result('invalid workflow run page envelope')
            if expected is not None and total != expected:
                return result('workflow run count changed during pagination')
            if total >= FILTERED_RUN_LIMIT:
                if lower == upper:
                    return result('GitHub filtered run limit reached within one timestamp second')
                middle = lower + dt.timedelta(seconds=int((upper - lower).total_seconds()) // 2)
                pending.extend(((middle + dt.timedelta(seconds=1), upper), (lower, middle)))
                break
            expected = total
            if len(batch) != min(RUNS_PER_PAGE, expected - len(seen)):
                return result('incomplete workflow run page')
            for row in batch:
                try:
                    identifier = row['id']
                    created = instant(row['created_at'])
                    if type(identifier) is not int or identifier <= 0 or not lower <= created <= upper:
                        raise ValueError()
                except (KeyError, TypeError, ValueError):
                    return result('invalid or out-of-window workflow run')
                if identifier in rows:
                    return result('duplicate workflow run across pages or windows')
                rows[identifier] = row
                seen.add(identifier)
            if len(seen) == expected:
                break
            page += 1
    return result()


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        return None


def read_index():
    try:
        headers = {}
        token = os.environ.get('ARGUS_INTEL_SERVICE_TOKEN')
        if token:
            headers['Authorization'] = 'Bearer ' + token
        request = urllib.request.Request('http://127.0.0.1:8091/v1/status', headers=headers)
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        with opener.open(request, timeout=10) as response:
            body = response.read(262145)
        if len(body) > 262144:
            raise ValueError('status response exceeds limit')
        status = json.loads(body)
        return {key: status.get(key) for key in ('ready', 'coverage', 'freshness',
            'warnings', 'repository_revisions', 'collector_revisions', 'consumer_budget', 'disk')}
    except (OSError, ValueError, TypeError, AttributeError):
        return {'error': 'index status unavailable or invalid'}


def run_in_window(run, started, sampled_at):
    """Reject malformed evidence; old successes and reruns do not count."""
    if not isinstance(run, dict) or not run.get('id') or run.get('status') not in (
            'completed', 'queued', 'in_progress', 'waiting', 'requested', 'pending'):
        raise ValueError('invalid workflow run evidence')
    created = instant(run['created_at'])
    began = instant(run.get('run_started_at') or run['created_at'])
    if run['status'] == 'completed' and not run.get('updated_at'):
        raise ValueError('completed workflow run requires update timestamp')
    updated = instant(run['updated_at']) if run.get('updated_at') else began
    if not created <= began <= updated <= sampled_at:
        raise ValueError('invalid workflow run chronology')
    return started <= created


def mapping(value):
    return value if isinstance(value, dict) else {}


def qualify(result, previous, *, start_qualified_window=False, interval_seconds=900):
    """Fail closed on interrupted observation; completion always needs review."""
    now = instant(result['sampled_at'])
    old = mapping(mapping(previous).get('qualification'))
    if start_qualified_window:
        state = {'version': 1, 'window_id': uuid.uuid4().hex, 'started_at': now.isoformat(),
            'last_sample_at': now.isoformat(), 'status': 'observing', 'qualified_seconds': 0,
            'sample_count': 0, 'interval_seconds': interval_seconds,
            'max_sample_gap_seconds': interval_seconds + 60, 'reasons': []}
    elif old.get('version') == 1:
        state = copy.deepcopy(old)
    else:
        state = {'version': 1, 'status': 'not_started', 'qualified_seconds': 0,
                 'reasons': ['explicit --start-qualified-window required']}
    started = instant(state['started_at']) if state.get('started_at') else None
    reasons, pending = [], []
    index = mapping(result.get('index'))
    coverage = mapping(index.get('coverage'))
    if index.get('ready') is not True:
        reasons.append('index_not_ready')
    if coverage.get('status') != 'complete':
        reasons.append('index_coverage_incomplete')
    if mapping(index.get('freshness')).get('stale') is not False:
        reasons.append('index_not_fresh')
    all_success = True
    for name in REPOS:
        repo = mapping(mapping(result.get('repositories')).get(name))
        if repo.get('workflow_state') != 'active':
            reasons.append(name + ':workflow_not_active')
        if repo.get('error') or not repo.get('data_sha'):
            reasons.append(name + ':repository_evidence_unavailable')
        if started and not repo.get('window_listing_complete'):
            reasons.append(name + ':window_run_listing_incomplete')
        scope = mapping(mapping(coverage.get('repositories')).get('argus-supply/' + name))
        sources = mapping(scope.get('sources'))
        if scope.get('status') != 'complete' or not set(SOURCES[name]) <= sources.keys() or any(
                mapping(source).get('status') != 'ok' or mapping(source).get('has_continuation')
                for source in sources.values()):
            reasons.append(name + ':source_coverage_incomplete')
        runs = []
        raw_runs = repo.get('runs')
        if started:
            if not isinstance(raw_runs, list):
                reasons.append(name + ':invalid_run_evidence')
            else:
                for run in raw_runs:
                    try:
                        if run_in_window(run, started, now):
                            runs.append(run)
                    except (KeyError, TypeError, ValueError):
                        reasons.append(name + ':invalid_run_evidence')
        repo['window_run_ids'] = [run['id'] for run in runs]
        for run in runs:
            if run.get('status') == 'completed' and run.get('conclusion') != 'success':
                reasons.append(name + ':failed_run:' + str(run['id']))
            elif run.get('status') != 'completed':
                pending.append(name + ':' + str(run['id']))
        for event, key in (('workflow_dispatch', 'manual_success'), ('schedule', 'scheduled_success')):
            repo[key] = any(run.get('event') == event and run.get('status') == 'completed'
                            and run.get('conclusion') == 'success' for run in runs)
        all_success = all_success and repo['manual_success'] and repo['scheduled_success']
    if state['status'] in ('observing', 'review_required'):
        gap = (now - instant(state['last_sample_at'])).total_seconds()
        if gap < 0:
            reasons.append('observation_clock_moved_backwards')
        elif gap > state['max_sample_gap_seconds']:
            reasons.append('sampling_gap_exceeded')
        if reasons:
            state.update(status='start_rejected' if start_qualified_window else 'invalidated',
                qualified_seconds_before_invalidation=state['qualified_seconds'], qualified_seconds=0,
                invalidated_at=now.isoformat(), reasons=sorted(set(reasons)))
        else:
            state['qualified_seconds'] += gap
            state['status'] = ('review_required' if state['qualified_seconds'] >= WINDOW_SECONDS
                               and all_success and not pending else 'observing')
            state['sample_count'] += 1
        state['last_sample_at'] = now.isoformat()
    # Invalid/rejected windows never resume implicitly when a later sample is healthy.
    result['qualification_checks'] = {'problems': sorted(set(reasons)),
        'pending_runs': pending, 'required_in_window_successes': bool(all_success)}
    result['qualification'] = state
    result['qualified_hours'] = state['qualified_seconds'] / 3600
    result['observation_started_at'] = state.get('started_at')
    result['elapsed_hours'] = max(0, (now - started).total_seconds() / 3600) if started else 0
    result['status'] = {'not_started': 'diagnostic_only', 'start_rejected': 'qualified_window_start_rejected',
        'invalidated': 'qualified_window_invalidated', 'observing': 'pending_qualified_observation',
        'review_required': 'observation_evidence_available_review_required'}[state['status']]
    result['acceptance_passed'] = False
    return result


def sample(directory, *, start_qualified_window=False, interval_seconds=900, now=None):
    directory = Path(directory)
    path = directory / 'observation.json'
    previous = json.loads(path.read_text()) if path.exists() else {}
    now = now or dt.datetime.now(dt.timezone.utc)
    window_start = now.isoformat() if start_qualified_window else (previous.get('qualification') or {}).get('started_at')
    result = {'sampled_at': now.isoformat(), 'repositories': {}}
    legacy = previous.get('legacy_diagnostic')
    if not legacy and previous and not previous.get('qualification'):
        legacy = {key: previous.get(key) for key in ('sampled_at', 'observation_started_at', 'elapsed_hours', 'status')}
    if legacy:
        result['legacy_diagnostic'] = legacy
    # Diagnostics also use a fixed interval; they never imply qualification.
    listing_start = window_start or (now - dt.timedelta(seconds=WINDOW_SECONDS)).isoformat()
    blocked = None
    for repository in mapping(previous.get('repositories')).values():
        rejection = mapping(mapping(repository).get('github_api_rejection'))
        retry_at = rejection.get('retry_not_before')
        if type(retry_at) is int and retry_at > now.timestamp():
            blocked = {'error': 'GitHub API deferred until upstream retry time',
                **{key: rejection[key] for key in REJECTION_FIELDS if key in rejection}}
            break
    for name in REPOS:
        prefix = 'repos/argus-supply/' + name
        response = blocked or workflow_runs(prefix, listing_start, now.isoformat())
        raw_runs = response.get('workflow_runs', [])
        if not isinstance(raw_runs, list):
            raw_runs = []
            response['error'] = 'invalid workflow runs'
        runs = [{key: run.get(key) for key in ('id', 'html_url', 'event', 'status', 'conclusion',
                    'created_at', 'updated_at', 'run_started_at', 'head_sha', 'run_attempt')}
                for run in raw_runs if isinstance(run, dict)]
        if response.get('http_status') in (403, 429):
            blocked = {key: response[key] for key in ('error', *REJECTION_FIELDS) if key in response}
        metadata = []
        for route in ('/actions/workflows/sync.yml', '/git/ref/heads/data', ''):
            item = blocked or api(prefix + route)
            metadata.append(item)
            if item.get('http_status') in (403, 429):
                blocked = {key: item[key] for key in ('error', *REJECTION_FIELDS) if key in item}
        workflow, data, repo = metadata
        errors = [item['error'] for item in (response, workflow, data, repo) if item.get('error')]
        total = response.get('total_count')
        result['repositories'][name] = {'runs': runs, 'data_sha': mapping(data.get('object')).get('sha'),
            'workflow_state': workflow.get('state'), 'workflow_url': workflow.get('html_url'),
            'window_listing_complete': not errors and response.get('listing_complete') is True and total == len(runs),
            'run_listing': {'created': listing_start + '..' + now.isoformat(),
                'requests': response.get('listing_requests', 0), 'windows': response.get('listing_windows', 0)},
            'github_api_rejection': {key: blocked[key] for key in REJECTION_FIELDS if blocked and key in blocked},
            'reported_repository_kib_all_branches': repo.get('size'),
            'storage_measurement_limit': 'GitHub repository size is a provider estimate, not an exact object inventory',
            'error': '; '.join(errors) if errors else None}
    result['index'] = read_index()
    qualify(result, previous, start_qualified_window=start_qualified_window, interval_seconds=interval_seconds)
    directory.mkdir(parents=True, exist_ok=True)
    history = directory / 'observation-samples.jsonl'
    lines = history.read_text().splitlines() if history.exists() else []
    lines.append(json.dumps(result, separators=(',', ':')))
    # Retain bounded metadata (seven days at the default interval), including legacy lines.
    temporary = directory / 'observation-samples.jsonl.tmp'
    temporary.write_text('\n'.join(lines[-672:]) + '\n')
    temporary.replace(history)
    temporary = directory / 'observation.json.tmp'
    temporary.write_text(json.dumps(result, indent=2) + '\n')
    temporary.replace(path)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('--report-directory', type=Path, required=True)
    parser.add_argument('--hours', type=float, default=0)
    parser.add_argument('--interval-seconds', type=int, default=900)
    parser.add_argument('--start-qualified-window', action='store_true',
                        help='Start a new window only if all workflows and the complete fresh index are healthy')
    args = parser.parse_args(argv)
    if not 0 <= args.hours <= 168 or not 60 <= args.interval_seconds <= 3600:
        parser.error('invalid observation duration or interval')
    deadline = time.monotonic() + args.hours * 3600
    first = True
    while True:
        began = time.monotonic()
        result = sample(args.report_directory, start_qualified_window=first and args.start_qualified_window,
                        interval_seconds=args.interval_seconds)
        first = False
        print(result['sampled_at'], result['status'], flush=True)
        if time.monotonic() >= deadline:
            break
        until = min(deadline, began + args.interval_seconds)
        while time.monotonic() < until:
            time.sleep(max(0, min(60, until - time.monotonic())))


if __name__ == '__main__':
    main()
