"""Bounded, derived HEAD observations; never mutate source facts or watermarks."""
from __future__ import annotations

import copy
import datetime as dt

from .core import canonical, digest, instant
from .http import BudgetExceeded, FetchError, reference_allowed


def validate_policy(policy):
    """Validate opt-in limits without increasing the existing job reservation."""
    bounds = {'reference_probe_requests': (0, 4), 'reference_probe_retries': (0, 1),
        'reference_probe_timeout_seconds': (1, 10), 'reference_probe_bytes': (1, 65536),
        'reference_probe_entries': (1, 256), 'reference_probe_state_bytes': (1024, 65536),
        'reference_recheck_hours': (24, 168)}
    for key, (lower, upper) in bounds.items():
        if type(policy.get(key)) is not int or not lower <= policy[key] <= upper:
            raise ValueError('invalid reference policy setting: ' + key)


def refresh(records, previous, http, now, policy):
    """Resume a fair cursor across retained refs using at most four requests/job.

    Only a bounded observation window is persisted. Evicted, unsupported and
    budget-deferred references remain explicitly unchecked. URL changes discard
    the old observation. Due checks keep their previous result if quota expires.
    """
    validate_policy(policy)
    eligible, unsupported = {}, 0
    for row in records.values():
        if row.get('kind') != 'poc' or row.get('status') != 'active':
            continue
        try:
            url = reference_allowed(row.get('url'))
        except FetchError:
            unsupported += 1
            continue
        eligible[digest(row['record_id'].encode())] = url
    state = {'schema_version': '1.0', 'method': 'HEAD', 'scope': 'github-repository-and-exploitdb-id',
        'cursor': (previous or {}).get('cursor'), 'eligible_count': len(eligible),
        'unsupported_count': unsupported, 'entries': {}}
    for key, entry in (previous or {}).get('entries', {}).items():
        if key in eligible and entry['url_sha256'] == digest(eligible[key].encode()):
            state['entries'][key] = copy.deepcopy(entry)
    entries = state['entries']
    local = http.fork(max_bytes=policy['reference_probe_bytes'], max_requests=policy['reference_probe_requests'])
    ordered = sorted(eligible)
    cursor = state['cursor'] or ''
    ordered = [key for key in ordered if key > cursor] + [key for key in ordered if key <= cursor]
    deferred, observed = False, 0
    for key in ordered:
        if key in entries and instant(entries[key]['next_check_at']) > instant(now):
            continue
        try:
            status = local.head_reference(eligible[key])
            availability, reason = 'available', 'HEAD returned success; content and exploit effectiveness unverified'
        except BudgetExceeded:
            deferred = True
            break
        except FetchError as error:
            status = error.status
            if status in (301, 302, 303, 307, 308, 405, 501):
                availability, reason = 'unknown', 'redirect refused or HEAD unsupported; no GET fallback'
            else:
                availability, reason = 'temporarily-unavailable', str(error)[:120]
        next_check = instant(now) + dt.timedelta(hours=policy['reference_recheck_hours'])
        entries[key] = {'url_sha256': digest(eligible[key].encode()), 'availability': availability,
            'checked_at': now, 'next_check_at': next_check.isoformat(timespec='seconds').replace('+00:00', 'Z'),
            'http_status': status, 'reason': reason}
        state['cursor'] = key
        observed += 1
    # Retain the most recent bounded observations. These derived facts never
    # change source content hashes, source checkpoints, or material event feeds.
    oldest = sorted(entries, key=lambda key: (entries[key]['checked_at'], key))
    while len(entries) > policy['reference_probe_entries'] or len(canonical(state)) > policy['reference_probe_state_bytes']:
        if not oldest:
            raise ValueError('reference checkpoint exceeds configured bound')
        del entries[oldest.pop(0)]
    fresh = sum(instant(item['next_check_at']) > instant(now) for item in entries.values())
    metrics = {'eligible_count': len(eligible), 'unsupported_count': unsupported,
        'retained_checks': len(entries), 'fresh_checks': fresh, 'pending_or_due': len(eligible) - fresh,
        'observed': observed, 'requests': local.requests, 'bytes': local.bytes,
        'deferred_by_budget': deferred, 'checkpoint_bytes': len(canonical(state)),
        'coverage': 'complete' if fresh == len(eligible) and not unsupported else 'partial'}
    return state, metrics
