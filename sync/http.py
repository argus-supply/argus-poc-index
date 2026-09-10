"""Allowlisted, byte-counted transport; every retry consumes the same reservation."""
from __future__ import annotations

import json
import math
import re
import time
import zlib
import urllib.error
import urllib.parse
import urllib.request

from .observations import threshold_observation


class BudgetExceeded(RuntimeError):
    """The current durable reservation cannot fund another complete unit."""


class FetchError(RuntimeError):
    """Sanitized upstream failure; never includes response bodies or credentials."""
    def __init__(self, message, status=None):
        super().__init__(message)
        self.status = status


HOSTS = frozenset(('api.github.com', 'raw.githubusercontent.com', 'gitlab.com',
    'www.cve.org', 'www.cisa.gov'))


def reference_allowed(url):
    """Only canonical public repository roots and numeric Exploit-DB references."""
    if not isinstance(url, str) or len(url) > 512:
        raise FetchError('reference URL is outside checked scope')
    # Match the complete URL before parsing: ports, userinfo, encoded paths,
    # whitespace, query strings, fragments and navigation paths are all refused.
    github = re.fullmatch(r'https://github\.com/([A-Za-z0-9](?:[A-Za-z0-9-]{0,38}))/'
                         r'([A-Za-z0-9_][A-Za-z0-9_.-]{0,99})', url)
    exploitdb = re.fullmatch(r'https://www\.exploit-db\.com/exploits/[1-9][0-9]{0,9}', url)
    if not github and not exploitdb:
        raise FetchError('reference URL is outside checked scope')
    if github and (github[1].endswith('-') or '..' in github[2] or github[2].endswith('.git')):
        raise FetchError('reference URL is not canonical')
    reserved = {'about', 'account', 'accounts', 'advisories', 'apps', 'blog', 'collections',
        'contact', 'customer-stories', 'enterprise', 'events', 'explore', 'features', 'gist',
        'issues', 'join', 'login', 'logout', 'marketplace', 'new', 'notifications', 'orgs',
        'organizations', 'pricing', 'pulls', 'search', 'security', 'sessions', 'settings',
        'site', 'sponsors', 'stars', 'topics', 'trending', 'users'}
    if github and github[1].lower() in reserved:
        raise FetchError('GitHub navigation route is outside checked scope')
    return url


def allowed(url):
    parsed = urllib.parse.urlsplit(url)
    if (parsed.scheme != 'https' or parsed.hostname not in HOSTS or parsed.username
            or parsed.password or parsed.port not in (None, 443)):
        raise FetchError('upstream origin is not allowed')
    return parsed


class Redirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if req.get_method() == 'HEAD':
            if fp is not None:
                fp.close()
            raise FetchError('reference redirect refused', status=code)
        origin, destination = allowed(req.full_url), allowed(newurl)
        if origin.hostname != destination.hostname:
            raise FetchError('cross-origin redirect refused')
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class Http:
    """Allowlisted transport with advisory aggregate cost measurements.

    Project byte and request targets never stop synchronization. The time
    boundary still yields a durable continuation before the Actions job is
    killed, and each response remains bounded as a transport-safety rule.
    """
    def __init__(self, policy, *, token=None, max_bytes=None, max_requests=None,
                 parent=None, opener=None, sleep=time.sleep, clock=time.monotonic):
        self.policy = policy
        self.token = token
        self.max_bytes = policy['job_bytes'] if max_bytes is None else max_bytes
        self.max_requests = policy['job_requests'] if max_requests is None else max_requests
        self.bytes = self.requests = 0
        self.decompressed_bytes = 0
        self.parent = parent
        self.clock, self.sleep = clock, sleep
        self.started = parent.started if parent else clock()
        self.opener = opener or urllib.request.build_opener(Redirects())
        self.last_headers = {}
        self.capacity_observations = [] if parent is None else parent.capacity_observations
        self._reported_thresholds = set() if parent is None else parent._reported_thresholds

    def fork(self, *, max_bytes, max_requests):
        return Http(self.policy, token=self.token, parent=self, max_bytes=max_bytes,
                    max_requests=max_requests, opener=self.opener, sleep=self.sleep, clock=self.clock)

    def _before(self):
        if self.clock() - self.started >= self.policy['job_seconds']:
            raise BudgetExceeded('job time budget exhausted')
        if self.parent:
            self.parent._before()
        self.requests += 1
        self._observe_capacity()

    def _charge(self, size):
        self.bytes += size
        if self.parent:
            self.parent._charge(size)

    def _observe_capacity(self):
        root = self
        while root.parent:
            root = root.parent
        for name, observed, threshold in (
                ('http_job_bytes', root.bytes, root.max_bytes),
                ('http_job_requests', root.requests, root.max_requests)):
            if observed > threshold and name not in root._reported_thresholds:
                observation = threshold_observation(name, observed, threshold)
                root._reported_thresholds.add(name)
            else:
                observation = {'metric': name, 'observed': observed, 'threshold': threshold,
                               'exceeded': observed > threshold, 'enforcement': 'advisory'}
            current = {item['metric']: item for item in root.capacity_observations}
            current[name] = observation
            root.capacity_observations[:] = current.values()

    def _read(self, response):
        chunks = []
        received = 0
        limit = self.policy.get('max_response_bytes', self.policy['job_bytes'])
        while True:
            data = response.read(min(65536, limit + 1 - received))
            self._charge(len(data))
            if not data:
                self._observe_capacity()
                return b''.join(chunks)
            chunks.append(data)
            received += len(data)
            if received > limit:
                raise FetchError('individual upstream response exceeds safety bound')
            if self.clock() - self.started >= self.policy['job_seconds']:
                raise BudgetExceeded('job time budget exhausted')

    def get_bytes(self, url, headers=None):
        parsed = allowed(url)
        hdr = {'User-Agent': 'ARGUS-data-sync/1.0', 'Accept': 'application/vnd.github+json',
               'Accept-Encoding': 'gzip', **(headers or {})}
        if self.token and parsed.hostname == 'api.github.com':
            hdr['Authorization'] = 'Bearer ' + self.token
        request = urllib.request.Request(url, headers=hdr)
        for attempt in range(self.policy['http_retries'] + 1):
            self._before()
            retry_after = 0
            try:
                with self.opener.open(request, timeout=self.policy['http_timeout_seconds']) as response:
                    self.last_headers = dict(response.headers)
                    body = self._read(response)
                    if response.headers.get('Content-Encoding', '').lower() == 'gzip':
                        decode_limit = self.policy.get(
                            'max_decompressed_response_bytes', self.policy['job_bytes'])
                        decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
                        try:
                            body = decoder.decompress(body, decode_limit + 1)
                        except zlib.error:
                            raise FetchError('invalid compressed upstream response') from None
                        if len(body) > decode_limit or not decoder.eof or decoder.unused_data:
                            raise FetchError('decompressed response exceeds bound or is incomplete')
                    self.decompressed_bytes += len(body)
                    if self.parent:
                        self.parent.decompressed_bytes += len(body)
                    return body
            except urllib.error.HTTPError as error:
                self.last_headers = dict(error.headers)
                self._read(error)
                if error.code not in (429, 500, 502, 503, 504):
                    raise FetchError(f'upstream HTTP {error.code}', status=error.code) from None
                try:
                    retry_after = float(error.headers.get('Retry-After', 0))
                except ValueError:
                    retry_after = self.policy['http_retry_after_max_seconds']
                reason = f'upstream HTTP {error.code}'
            except (urllib.error.URLError, TimeoutError, ConnectionError, OSError):
                reason = 'upstream transport failure'
            if attempt == self.policy['http_retries']:
                raise FetchError(reason + '; retries exhausted') from None
            delay = max(retry_after, self.policy['http_backoff_seconds'] * 2 ** attempt)
            if delay > self.policy['http_retry_after_max_seconds']:
                raise FetchError(reason + '; retry deferred')
            self.sleep(delay)
        raise AssertionError('unreachable retry exhaustion')

    def get_json(self, url, headers=None):
        try:
            return json.loads(self.get_bytes(url, headers))
        except (ValueError, UnicodeError):
            raise FetchError('invalid upstream JSON') from None

    def head_reference(self, url):
        """Anonymous HEAD only; retries share the caller's durable reservation."""
        reference_allowed(url)
        request = urllib.request.Request(url, method='HEAD', headers={
            'User-Agent': 'ARGUS-reference-check/1.0', 'Accept-Encoding': 'identity'})
        for attempt in range(self.policy['reference_probe_retries'] + 1):
            self._before()
            status, retry_after = None, 0
            try:
                remaining = self.policy['job_seconds'] - (self.clock() - self.started)
                if remaining <= 0:
                    raise BudgetExceeded('job time budget exhausted')
                timeout = min(self.policy['reference_probe_timeout_seconds'], remaining)
                with self.opener.open(request, timeout=timeout) as response:
                    status = response.status
                    if 200 <= status < 300:
                        return status
                    raise FetchError('reference HTTP ' + str(status), status=status)
            except urllib.error.HTTPError as error:
                status = error.code
                # HEAD has no response body; never fall back to GET or consume
                # content. Close even an error response immediately.
                error.close()
                if status not in (429, 500, 502, 503, 504):
                    raise FetchError('reference HTTP ' + str(status), status=status) from None
                try:
                    retry_after = float(error.headers.get('Retry-After', 0))
                    if not math.isfinite(retry_after):
                        retry_after = self.policy['http_retry_after_max_seconds'] + 1
                except (TypeError, ValueError):
                    retry_after = self.policy['http_retry_after_max_seconds'] + 1
            except (urllib.error.URLError, TimeoutError, ConnectionError, OSError):
                pass
            reason = 'reference HTTP ' + str(status) if status else 'reference transport failure'
            if attempt == self.policy['reference_probe_retries']:
                raise FetchError(reason + '; retries exhausted', status=status) from None
            delay = max(retry_after, self.policy['http_backoff_seconds'] * 2 ** attempt)
            if delay > self.policy['http_retry_after_max_seconds'] or delay >= self.policy['job_seconds'] - (self.clock() - self.started):
                raise FetchError(reason + '; retry deferred', status=status)
            self.sleep(delay)
        raise AssertionError('unreachable reference retry exhaustion')
