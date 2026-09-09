"""Allowlisted, byte-counted transport; every retry consumes the same reservation."""
from __future__ import annotations

import json
import time
import zlib
import urllib.error
import urllib.parse
import urllib.request


class BudgetExceeded(RuntimeError):
    """The current durable reservation cannot fund another complete unit."""


class FetchError(RuntimeError):
    """Sanitized upstream failure; never includes response bodies or credentials."""
    def __init__(self, message, status=None):
        super().__init__(message)
        self.status = status


HOSTS = frozenset(('api.github.com', 'raw.githubusercontent.com', 'gitlab.com',
    'www.cve.org', 'www.cisa.gov'))


def allowed(url):
    parsed = urllib.parse.urlsplit(url)
    if (parsed.scheme != 'https' or parsed.hostname not in HOSTS or parsed.username
            or parsed.password or parsed.port not in (None, 443)):
        raise FetchError('upstream origin is not allowed')
    return parsed


class Redirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        origin, destination = allowed(req.full_url), allowed(newurl)
        if origin.hostname != destination.hostname:
            raise FetchError('cross-origin redirect refused')
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class Http:
    """A source-local allocation shares its parent's actual-byte/job counters."""
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

    def fork(self, *, max_bytes, max_requests):
        return Http(self.policy, token=self.token, parent=self, max_bytes=max_bytes,
                    max_requests=max_requests, opener=self.opener, sleep=self.sleep, clock=self.clock)

    def _before(self):
        if self.clock() - self.started >= self.policy['job_seconds']:
            raise BudgetExceeded('job time budget exhausted')
        if self.bytes >= self.max_bytes or self.requests >= self.max_requests:
            raise BudgetExceeded('request or byte budget exhausted')
        if self.parent:
            self.parent._before()
        self.requests += 1

    def _charge(self, size):
        self.bytes += size
        if self.parent:
            self.parent._charge(size)

    def _remaining(self):
        local = self.max_bytes - self.bytes
        return min(local, self.parent._remaining()) if self.parent else local

    def _read(self, response):
        chunks = []
        while True:
            remaining = self._remaining()
            if remaining <= 0:
                raise BudgetExceeded('response byte budget exhausted')
            data = response.read(min(65536, remaining))
            self._charge(len(data))
            if not data:
                return b''.join(chunks)
            chunks.append(data)
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
                        decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
                        try:
                            body = decoder.decompress(body, self.policy['job_bytes'] + 1)
                        except zlib.error:
                            raise FetchError('invalid compressed upstream response') from None
                        if len(body) > self.policy['job_bytes'] or not decoder.eof or decoder.unused_data:
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
