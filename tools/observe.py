"""Read-only diagnostics and explicitly started, continuously checked observation."""
import argparse
import copy
import datetime as dt
import json
import os
from pathlib import Path
import subprocess
import time
import urllib.parse
import urllib.request
import uuid

REPOS = ('argus-intel-data', 'argus-poc-index', 'argus-detection-resources')
SOURCES = dict(zip(REPOS, (('cve', 'ghsa', 'kev'),
    ('official-references', 'exploitdb', 'poc-in-github'), ('nuclei',))))
WINDOW_SECONDS = 24 * 3600


def instant(value):
    if not isinstance(value, str):
        raise ValueError('observation timestamp must be text')
    value = dt.datetime.fromisoformat(value.replace('Z', '+00:00'))
    if value.tzinfo is None:
        raise ValueError('observation timestamps require a timezone')
    return value.astimezone(dt.timezone.utc)


def api(path):
    try:
        result = subprocess.run(['gh', 'api', path], capture_output=True, text=True, timeout=45)
        if result.returncode:
            return {'error': 'GitHub API request failed', 'exit_code': result.returncode}
        value = json.loads(result.stdout)
        return value if isinstance(value, dict) else {'error': 'invalid GitHub API envelope'}
    except (OSError, subprocess.TimeoutExpired, ValueError):
        return {'error': 'GitHub API unavailable or invalid'}


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
    for name in REPOS:
        prefix = 'repos/argus-supply/' + name
        params = {'per_page': 30}
        if window_start:
            params['created'] = window_start + '..' + now.isoformat()
        response = api(prefix + '/actions/workflows/sync.yml/runs?' + urllib.parse.urlencode(params))
        raw_runs = response.get('workflow_runs', [])
        if not isinstance(raw_runs, list):
            raw_runs = []
            response['error'] = 'invalid workflow runs'
        runs = [{key: run.get(key) for key in ('id', 'html_url', 'event', 'status', 'conclusion',
                    'created_at', 'updated_at', 'run_started_at', 'head_sha', 'run_attempt')}
                for run in raw_runs if isinstance(run, dict)]
        workflow = api(prefix + '/actions/workflows/sync.yml')
        data = api(prefix + '/git/ref/heads/data')
        repo = api(prefix)
        errors = [item['error'] for item in (response, workflow, data, repo) if item.get('error')]
        total = response.get('total_count')
        result['repositories'][name] = {'runs': runs, 'data_sha': mapping(data.get('object')).get('sha'),
            'workflow_state': workflow.get('state'), 'workflow_url': workflow.get('html_url'),
            'window_listing_complete': not errors and type(total) is int and total == len(runs),
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
