"""Bounded public-source adapters. Upstream content is parsed, never executed.

The caller atomically persists returned records and state. A partial result never
advances the completed watermark or supplies an authoritative deletion inventory.
HTTP transport owns origin/redirect validation, retries and persisted budgets.
"""
from __future__ import annotations

import copy
import csv
import hashlib
import io
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import PurePosixPath
from urllib.parse import parse_qsl, quote, urlencode, urlsplit

import yaml

from .http import BudgetExceeded, FetchError
from .continuations import split_record


CVE = re.compile(r'CVE-\d{4}-\d{4,}')
GHSA = re.compile(r'GHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}', re.I)
SHA = re.compile(r'[0-9a-f]{40}')
REPOS = {'cve': 'CVEProject/cvelistV5', 'ghsa': 'github/advisory-database',
         'kev': 'cisagov/kev-data', 'poc-in-github': 'nomi-sec/PoC-in-GitHub',
         'nuclei': 'projectdiscovery/nuclei-templates'}


@dataclass
class AdapterResult:
    """Completed units and a restartable checkpoint, including honest gaps."""
    records: list[dict] = field(default_factory=list)
    state: dict = field(default_factory=dict)
    status: str = 'partial'
    revision: str | None = None
    completed_watermark: str | None = None
    continuation: dict | None = None
    coverage_gaps: list = field(default_factory=list)
    errors: list = field(default_factory=list)
    authoritative_ids: list[str] | None = None


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode()


def timestamp(value):
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc)
    parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)


def iso(value):
    return timestamp(value).isoformat(timespec='seconds').replace('+00:00', 'Z')


def checked_path(path):
    if not isinstance(path, str) or not path or '\\' in path or '%' in path:
        raise ValueError('unsafe upstream path')
    parsed = PurePosixPath(path)
    if parsed.is_absolute() or any(part in ('..', '.') for part in path.split('/')) or ':' in path:
        raise ValueError('unsafe upstream path')
    return path


def public_url(value):
    if not isinstance(value, str):
        raise ValueError('reference URL must be a string')
    parsed = urlsplit(value)
    if parsed.scheme not in ('https', 'http') or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError('invalid public reference URL')
    return value


def advisory_page_url(url, filters):
    """Accept only the original advisory query plus one opaque GitHub cursor."""
    if not isinstance(url, str) or len(url) > 8192 or any(ord(char) < 33 or ord(char) == 127 for char in url):
        raise ValueError('invalid GHSA pagination URL')
    parsed = urlsplit(url)
    if (parsed.scheme != 'https' or parsed.netloc != 'api.github.com' or
            parsed.path != '/advisories' or parsed.fragment):
        raise ValueError('GHSA pagination origin or path changed')
    pairs = parse_qsl(parsed.query, keep_blank_values=True, strict_parsing=True)
    query = dict(pairs)
    if len(query) != len(pairs):
        raise ValueError('duplicate GHSA pagination parameter')
    cursors = set(query) - set(filters)
    if cursors not in (set(), {'after'}, {'before'}) or any(query.get(key) != value for key, value in filters.items()):
        raise ValueError('GHSA pagination filters changed')
    if cursors and not query[next(iter(cursors))]:
        raise ValueError('empty GHSA pagination cursor')
    return 'https://api.github.com/advisories?' + urlencode(sorted(query.items()))


def advisory_next_url(headers, filters):
    """Read the documented Link next relation without following untrusted URLs."""
    link = next((value for key, value in headers.items() if key.lower() == 'link'), '')
    if not isinstance(link, str) or len(link) > 16384:
        raise ValueError('invalid GHSA pagination Link header')
    next_url = None
    for entry in re.split(r',(?=\s*<)', link) if link else []:
        match = re.fullmatch(r'\s*<([^<>]+)>\s*(.*)', entry)
        if not match:
            raise ValueError('malformed GHSA pagination Link entry')
        relations = re.findall(r'(?:^|;)\s*rel\s*=\s*(?:"([^"]*)"|([^;\s]+))', match[2])
        if len(relations) != 1:
            raise ValueError('ambiguous GHSA pagination Link relation')
        if 'next' not in (relations[0][0] or relations[0][1]).split():
            continue
        if next_url is not None:
            raise ValueError('multiple GHSA pagination next links')
        next_url = advisory_page_url(match[1], filters)
    return next_url


def raw_url(repo, revision, path):
    if not SHA.fullmatch(revision):
        raise ValueError('upstream revision must be immutable')
    return f'https://raw.githubusercontent.com/{repo}/{revision}/{quote(checked_path(path), safe="/")}'


def pin(http, repo, ref='HEAD'):
    value = http.get_json(f'https://api.github.com/repos/{repo}/commits/{quote(ref, safe="")}')
    revision = value.get('sha', '')
    if not SHA.fullmatch(revision):
        raise ValueError('invalid upstream commit response')
    return revision


def base_record(source, native_id, kind, *, title=None, aliases=(), published=None,
                modified=None, status='active', revision=None, url=None):
    return {'schema_version': '1.0', 'record_id': f'{source}/{native_id}',
            'source_id': source, 'native_id': native_id, 'kind': kind,
            'aliases': sorted(set(aliases)), 'status': status, 'title': title or native_id,
            'published_at': iso(published) if published else None,
            'source_modified_at': iso(modified) if modified else None,
            'first_seen_at': None, 'affected': [], 'references': [],
            'provenance': [{'source_id': source, 'revision': revision, 'url': url}],
            'content_hash': '', 'assessment': {'relevance': 'unknown', 'confidence': 'unknown',
                'product_class': None, 'entry_protocol': None, 'authentication': None,
                'configuration': None, 'reasons': [], 'classifier_version': '1.0'}}


def normalize_cve(raw, revision):
    """Preserve distinct CNA/ADP assertions and unshortened affected facts."""
    if raw.get('dataType') != 'CVE_RECORD' or raw.get('dataVersion') not in ('5.0', '5.1', '5.1.1', '5.2'):
        raise ValueError('unsupported CVE record schema')
    meta = raw['cveMetadata']
    identifier = meta['cveId']
    if not CVE.fullmatch(identifier):
        raise ValueError('invalid CVE ID')
    if meta.get('state') not in ('PUBLISHED', 'REJECTED'):
        raise ValueError('unsupported CVE state')
    containers = raw.get('containers', {})
    cna = containers.get('cna', {})
    row = base_record('cve', identifier, 'advisory', aliases=[identifier],
        title=cna.get('title'), published=meta.get('datePublished'), modified=meta.get('dateUpdated'),
        status='rejected' if meta['state'] == 'REJECTED' else 'active', revision=revision,
        url=f'https://www.cve.org/CVERecord?id={identifier}')
    row['data_version'] = raw['dataVersion']
    row['descriptions'] = cna.get('descriptions', cna.get('rejectedReasons', []))
    row['assertions'] = []
    for role, container in [('cna', cna)] + [('adp', x) for x in containers.get('adp', [])]:
        provider = container.get('providerMetadata', {})
        assertion = {key: copy.deepcopy(container[key]) for key in
            ('metrics', 'problemTypes', 'descriptions', 'configurations',
             'rejectedReasons', 'replacedBy', 'datePublic', 'title') if key in container}
        assertion.update({'role': role, 'provider': provider, 'affected_indices': []})
        row['assertions'].append(assertion)
        for affected in container.get('affected', []):
            assertion['affected_indices'].append(len(row['affected']))
            fields = {key: copy.deepcopy(value) for key, value in affected.items() if key != 'versions'}
            row['affected'].append({**fields, 'assertion_role': role,
                'provider': {key: value for key, value in provider.items() if key != 'dateUpdated'},
                'original_ranges': copy.deepcopy(affected.get('versions', []))})
        for ref in container.get('references', []):
            row['references'].append({**ref, 'assertion_role': role, 'provider': provider})
        row['provenance'].append({'source_id': 'cve', 'role': role, 'provider': provider,
                                  'independent_evidence': role == 'cna'})
    return row


def normalize_ghsa(raw, revision=None):
    """Normalize reviewed API records, preserving native ranges and review changes."""
    identifier = raw['ghsa_id']
    if not GHSA.fullmatch(identifier):
        raise ValueError('invalid GHSA ID')
    aliases = [x['value'] for x in raw.get('identifiers', []) if x.get('value')]
    aliases.append(identifier)
    if raw.get('cve_id'):
        aliases.append(raw['cve_id'])
    row = base_record('ghsa', identifier, 'advisory', aliases=aliases, title=raw.get('summary'),
        published=raw.get('published_at'), modified=raw.get('updated_at'),
        status='withdrawn' if raw.get('withdrawn_at') else ('unreviewed' if raw.get('type') != 'reviewed' else 'active'),
        revision=revision or raw.get('updated_at'), url=raw.get('html_url'))
    row['review_state'] = raw.get('type')
    row['withdrawn_at'] = raw.get('withdrawn_at')
    row['github_reviewed_at'] = raw.get('github_reviewed_at')
    row['severity'] = raw.get('severity')
    row['metrics'] = raw.get('cvss_severities', raw.get('cvss'))
    for item in raw.get('vulnerabilities', []):
        package = item.get('package', {})
        row['affected'].append({'package': package, 'ecosystem': package.get('ecosystem'),
            'name': package.get('name'), 'original_ranges': item.get('vulnerable_version_range'),
            'first_patched_version': item.get('first_patched_version'),
            'vulnerable_functions': item.get('vulnerable_functions', [])})
    row['references'] = [{'url': public_url(x), 'relationship': 'upstream-reference'} for x in raw.get('references', [])]
    row['provenance'][0]['independent_evidence_group'] = f'github-advisory/{identifier}'
    return row


def normalize_kev(raw, revision):
    identifier = raw['cveID']
    if not CVE.fullmatch(identifier):
        raise ValueError('invalid KEV CVE')
    row = base_record('kev', identifier, 'advisory', aliases=[identifier],
        title=raw.get('vulnerabilityName'), published=raw.get('dateAdded'), modified=raw.get('dateAdded'),
        revision=revision, url='https://www.cisa.gov/known-exploited-vulnerabilities-catalog')
    row.update({'known_exploited': True, 'kev_added_at': raw.get('dateAdded'),
                'kev': True, 'kev_metadata': copy.deepcopy(raw)})
    row['affected'] = [{'vendor': raw.get('vendorProject'), 'product': raw.get('product'),
                         'original_ranges': None}]
    return row


def normalize_poc(raw, cve, revision, intel_sha):
    url = public_url(raw['html_url'])
    native = str(raw.get('id') or hashlib.sha256(url.encode()).hexdigest())
    row = base_record('poc-in-github', native, 'poc', title=raw.get('description') or raw.get('full_name'),
        aliases=[cve], published=raw.get('created_at'), modified=raw.get('updated_at'),
        revision=revision, url=url)
    row.update({'url': url, 'author': raw.get('owner', {}).get('login'),
        'advisory_ids': [cve], 'mapping_confidence': 'source-asserted',
        'upstream_revision': None, 'index_revision': revision, 'intel_commit_sha': intel_sha,
        'prerequisites': None, 'availability': 'not-checked',
        'verification': {'author_claim': 'proof-of-concept', 'static_analysis': 'not-performed',
                         'executed': False, 'status': 'unverified'}})
    return row


class MetadataLoader(yaml.SafeLoader):
    """Safe loader rejects alias expansion and duplicate keys before construction."""
    def compose_node(self, parent, index):
        if self.check_event(yaml.AliasEvent):
            raise ValueError('YAML aliases are not allowed')
        return super().compose_node(parent, index)

    def construct_mapping(self, node, deep=False):
        keys = [self.construct_object(k, deep=deep) for k, _ in node.value]
        if len(set(keys)) != len(keys):
            raise ValueError('duplicate YAML mapping key')
        return super().construct_mapping(node, deep=deep)


def normalize_template(data, path, revision, blob_sha, *, max_bytes=2 * 1024 * 1024):
    """Read only safe YAML metadata; path names never assert CVE association."""
    checked_path(path)
    if len(data) > max_bytes:
        raise ValueError('oversize template')
    actual_blob = hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
    if actual_blob != blob_sha:
        raise ValueError('template blob hash mismatch')
    raw = yaml.load(data, Loader=MetadataLoader)
    if not isinstance(raw, dict) or not isinstance(raw.get('id'), str) or not isinstance(raw.get('info'), dict):
        raise ValueError('invalid template metadata')
    info = raw['info']
    tags = info.get('tags', [])
    tags = [x.strip() for x in tags.split(',')] if isinstance(tags, str) else tags
    if not isinstance(tags, list):
        raise ValueError('invalid template tags')
    classification = info.get('classification') or {}
    identifiers = classification.get('cve-id', [])
    identifiers = [identifiers] if isinstance(identifiers, str) else identifiers
    refs = info.get('reference', [])
    refs = refs if isinstance(refs, list) else [refs]
    aliases = set(x.upper() for x in identifiers if isinstance(x, str) and CVE.fullmatch(x.upper()))
    for value in tags:
        if isinstance(value, str) and CVE.fullmatch(value.upper()):
            aliases.add(value.upper())
    for value in refs:
        if isinstance(value, str):
            aliases.update(GHSA.findall(value))
    protocols = [x for x in ('http', 'requests', 'tcp', 'network', 'headless', 'code', 'file', 'dns', 'ssl', 'javascript') if x in raw]
    metadata = info.get('metadata') or {}
    text = data.decode('utf-8')
    dependency_paths = set()
    for protocol in ('http', 'requests', 'tcp', 'network'):
        for request in raw.get(protocol, []):
            if not isinstance(request, dict):
                raise ValueError('invalid template request')
            for payload in (request.get('payloads') or {}).values():
                if isinstance(payload, str):
                    dependency_paths.add(checked_path(payload))
    if len(dependency_paths) > 32:
        raise ValueError('too many template dependencies')
    row = base_record('nuclei', path, 'resource', title=info.get('name'), aliases=aliases,
        revision=revision, url=f'https://github.com/{REPOS["nuclei"]}/blob/{revision}/{path}')
    row.update({'template_id': raw['id'], 'resource_id': f'nuclei/{path}', 'path': path,
        'source_commit': revision, 'blob_sha': blob_sha, 'sha256': hashlib.sha256(data).hexdigest(),
        'bytes': len(data), 'protocols': protocols, 'tags': sorted(set(tags)),
        'advisory_ids': sorted(aliases), 'mapping_confidence': 'explicit-metadata' if aliases else 'unknown',
        'products': {k: metadata[k] for k in ('vendor', 'product', 'cpe') if k in metadata},
        'engine': {'name': 'nuclei', 'minimum_version': metadata.get('min-version') or raw.get('minimum-version')},
        'dependencies': [{'path': p, 'revision': revision, 'status': 'unresolved'} for p in sorted(dependency_paths)],
        'requirements': {'authentication': 'required' if any(x in tags for x in ('auth', 'authenticated')) else None,
            'browser': 'headless' in raw, 'out_of_band': '{{interactsh-url}}' in text,
            'code': 'code' in raw or 'javascript' in raw, 'configuration': None},
        'verification': {'status': 'metadata-only', 'executed': False}})
    row['references'] = []
    for value in refs:
        try:
            url = public_url(value)
        except ValueError:
            text_value = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
            row['references'].append({'text': text_value, 'relationship': 'upstream-reference', 'retrievable': False})
            row.setdefault('warnings', []).append({'code': 'non_url_reference',
                'message': 'Upstream reference retained as inert text; not a download URL.',
                'reference_index': len(row['references']) - 1})
        else:
            row['references'].append({'url': url})
    return row


def delta_ids(raw, lower, upper):
    if not isinstance(raw, list) or not raw:
        raise ValueError('empty or invalid CVE delta log')
    times, ids = [], {}
    for batch in raw:
        fetched = timestamp(batch['fetchTime'])
        times.append(fetched)
        if fetched < lower or fetched > upper:
            continue
        if batch.get('error'):
            raise ValueError('CVE delta contains upstream errors')
        for kind in ('new', 'updated'):
            for item in batch.get(kind, []):
                identifier = item['cveId']
                if not CVE.fullmatch(identifier):
                    raise ValueError('invalid CVE delta ID')
                ids[identifier] = max(ids.get(identifier, fetched), fetched)
    # Prioritize actual recent changes, never the CVE numbering year.
    return sorted(ids, key=lambda identifier: (-ids[identifier].timestamp(), identifier)), min(times), max(times)


def cve_path(identifier):
    _, year, number = identifier.split('-')
    bucket = number[:-3] + 'xxx' if len(number) > 3 else '0xxx'
    return f'cves/{year}/{bucket}/{identifier}.json'


class Run:
    def __init__(self, source, http, previous, now, policy, dependency):
        self.source, self.http, self.policy, self.dependency = source, http, policy, dependency
        self.now = iso(now)
        self.previous = previous.get('records', [])
        self.previous_by_id = {row['record_id']: row for row in self.previous}
        self.previous_ids = {row['record_id'] for row in self.previous}
        self.old = copy.deepcopy(previous.get('state', {}))
        self.state = copy.deepcopy(self.old)
        self.result = AdapterResult(state=self.state, revision=self.old.get('revision'),
            completed_watermark=self.old.get('completed_watermark'))
        self.cursor = copy.deepcopy(self.old.get('continuation') or {})
        self.units = 0
        self.limit = policy.get('adapter_max_units', 400)

    def add(self, row):
        self.check_record(row)
        self.result.records.append(row)

    def check_record(self, row):
        # Prove the finalized record can fit a lossless bounded physical bundle
        # before advancing its source unit. Core repeats this after final events.
        logical_limit = self.policy.get('max_logical_record_bytes', 262144)
        if len(canonical(row)) + 512 > logical_limit:
            raise ValueError(f'oversize_record:{row["record_id"]}')
        trial = {**row, 'content_hash': '0' * 64, 'first_seen_at': row.get('first_seen_at') or self.now}
        split_record(trial, max_record_bytes=self.policy.get('max_record_bytes', 16384),
                     max_logical_bytes=logical_limit)

    def unit(self):
        self.units += 1
        if self.units > self.limit:
            raise ValueError('adapter_unit_budget_exhausted')

    def finish(self, revision, *, authoritative=None, watermark=None):
        self.result.status = 'ok'
        self.result.revision = revision
        self.result.completed_watermark = watermark or self.now
        self.result.authoritative_ids = authoritative
        if self.source == 'cve':
            history = self.state.get('revision_history', [])
            if not history or history[-1]['revision'] != revision:
                history.append({'revision': revision, 'at': self.result.completed_watermark})
            cutoff = timestamp(self.now) - timedelta(hours=self.policy.get('overlap_hours', 48))
            # Retain one boundary revision older than the overlap as its base.
            while len(history) > 1 and timestamp(history[1]['at']) < cutoff:
                history.pop(0)
            self.state['revision_history'] = history
        self.cursor = {}

    def pinned(self, repo, ref='HEAD'):
        if not self.cursor.get('revision'):
            self.cursor['revision'] = pin(self.http, repo, ref)
        self.result.revision = self.cursor['revision']
        return self.cursor['revision']

    def cve(self):
        repo = REPOS['cve']
        revision = self.pinned(repo)
        if revision == self.old.get('revision') and self.old.get('status') == 'ok':
            self.finish(revision, watermark=self.old.get('completed_watermark'))
            return
        if self.old.get('completed_watermark') and not self.cursor.get('target_start'):
            self.cve_changes(revision)
            return
        if 'target_start' not in self.cursor:
            desired = timestamp(self.now) - timedelta(days=self.policy.get('retention_days', 30))
            self.cursor['retention_start'] = iso(desired)
            if self.old.get('completed_watermark'):
                desired = max(desired, timestamp(self.old['completed_watermark']) - timedelta(hours=self.policy.get('overlap_hours', 48)))
            else:
                initial = timestamp(self.now) - timedelta(days=self.policy.get('bootstrap_days', 7))
                if initial > desired:
                    self.cursor['backfill_start'] = iso(desired)
                    desired = initial
            self.cursor.update(target_start=iso(desired), window_end=self.now, snapshot_revision=revision)
        lower = timestamp(self.cursor['target_start'])
        upper = timestamp(self.cursor.get('window_upper', self.cursor['window_end']))
        while True:
            if 'pending' not in self.cursor:
                raw = self.http.get_json(raw_url(repo, self.cursor['snapshot_revision'], 'cves/deltaLog.json'))
                ids, oldest, newest = delta_ids(raw, lower, upper)
                self.cursor.update(pending=ids, offset=0, log_oldest=iso(oldest), log_newest=iso(newest))
            pending = self.cursor['pending']
            while self.cursor['offset'] < len(pending):
                self.unit()
                identifier = pending[self.cursor['offset']]
                data = self.http.get_json(raw_url(repo, revision, cve_path(identifier)))
                self.admit_cve(normalize_cve(data, revision), revision)
                self.cursor['offset'] += 1
            oldest = timestamp(self.cursor['log_oldest'])
            self.state['coverage_start'] = iso(oldest)
            if oldest <= lower:
                if self.cursor.get('backfill_start'):
                    self.state['coverage_start'] = self.cursor['target_start']
                    self.cursor['window_upper'] = self.cursor['target_start']
                    self.cursor['target_start'] = self.cursor.pop('backfill_start')
                    self.cursor['snapshot_revision'] = revision
                    self.cursor.pop('pending')
                    self.result.coverage_gaps = [{'reason': 'recent bootstrap complete; retained-window backfill pending',
                                                  'source_id': 'cve', 'from': self.cursor['target_start'],
                                                  'to': self.cursor['window_upper']}]
                    return
                self.finish(revision, watermark=self.cursor['window_end'])
                return
            # Query only ancestors of the fixed revision, one older log snapshot.
            before = iso(oldest - timedelta(seconds=1))
            params = urlencode({'sha': revision, 'path': 'cves/deltaLog.json', 'until': before, 'per_page': 1})
            commits = self.http.get_json(f'https://api.github.com/repos/{repo}/commits?{params}')
            if not isinstance(commits, list) or not commits:
                raise ValueError('CVE history coverage gap: no older delta snapshot')
            next_revision = commits[0]['sha']
            if not SHA.fullmatch(next_revision) or next_revision == self.cursor['snapshot_revision']:
                raise ValueError('CVE history did not advance')
            self.cursor['snapshot_revision'] = next_revision
            self.cursor.pop('pending')

    def admit_cve(self, row, revision):
        """Bootstrap old disclosures only with a provable retained-window change."""
        if self.old.get('completed_watermark') or row['record_id'] in self.previous_ids:
            self.add(row)
            return
        published = row.get('published_at')
        cutoff = self.cursor.get('retention_start', self.cursor['target_start'])
        if not published and row['status'] != 'rejected':
            raise ValueError(f'bootstrap publication time unknown:{row["native_id"]}')
        if published and timestamp(published) >= timestamp(cutoff):
            self.add(row)
            return
        baseline = self.cursor.get('material_baseline_revision')
        if not baseline:
            params = urlencode({'sha': revision, 'until': cutoff, 'per_page': 1})
            commits = self.http.get_json(f'https://api.github.com/repos/{REPOS["cve"]}/commits?{params}')
            if not isinstance(commits, list) or not commits or not SHA.fullmatch(commits[0].get('sha', '')):
                raise ValueError('bootstrap material-change baseline is unavailable')
            baseline = self.cursor['material_baseline_revision'] = commits[0]['sha']
        try:
            old = normalize_cve(self.http.get_json(raw_url(REPOS['cve'], baseline, cve_path(row['native_id']))), baseline)
        except FetchError as exc:
            if exc.status == 404:
                if row['status'] != 'rejected':
                    raise ValueError(f'bootstrap old-record comparison unknown:{row["native_id"]}') from None
                # A rejected identifier need never have had a publication date.
                # Confirmed absence at the pinned baseline proves this explicit
                # rejection was added within the interval, without a disclosure.
                old = {'status': 'absent', 'affected': row['affected'], 'assertions': row['assertions']}
            else:
                raise
        changed = [key for key in ('affected', 'status') if old[key] != row[key]]
        if [x['metrics'] for x in old['assertions'] if x.get('metrics')] != [x['metrics'] for x in row['assertions'] if x.get('metrics')]:
            changed.append('scores')
        if not changed:
            self.state['bootstrap_old_records_without_material_change'] = self.state.get('bootstrap_old_records_without_material_change', 0) + 1
            return
        row['bootstrap_material_change'] = {'baseline_revision': baseline,
            'window_start': cutoff, 'window_end': self.cursor['window_end'],
            'changed_fields': changed, 'before_status': old['status'],
            'timing': 'observed-state-difference-within-interval'}
        self.add(row)

    def cve_changes(self, revision):
        """Complete Git changes capture late source timestamps; overlap uses old heads."""
        repo = REPOS['cve']
        if 'base_revision' not in self.cursor:
            history = self.old.get('revision_history', [])
            base = history[0]['revision'] if history else self.old['revision']
            self.cursor.update(base_revision=base, window_end=self.now, change_offset=0)
        base = self.cursor['base_revision']
        if not SHA.fullmatch(base):
            raise ValueError('invalid CVE comparison base')
        url = f'https://api.github.com/repos/{repo}/compare/{base}...{revision}'
        comparison = self.http.get_json(url + '?per_page=100&page=1')
        if comparison.get('status') not in ('ahead', 'identical'):
            raise ValueError('CVE upstream history diverged; bounded delta rebootstrap required')
        if not isinstance(comparison.get('files'), list):
            raise ValueError('missing CVE comparison file inventory')
        if len(comparison['files']) < 300 and not self.cursor.get('enumerate_commits'):
            self.cve_changed_files(comparison['files'], revision, 'change_offset')
            self.finish(revision, watermark=self.cursor['window_end'])
            return
        # GitHub compare's file list is capped at 300. Enumerate the pinned
        # comparison's commits, then every page of each commit's file list.
        self.cursor['enumerate_commits'] = True
        page_number = self.cursor.setdefault('commit_page', 1)
        while True:
            page = comparison if page_number == 1 else self.http.get_json(url + f'?per_page=100&page={page_number}')
            commits = page.get('commits')
            if not isinstance(commits, list):
                raise ValueError('invalid CVE commit page')
            index = self.cursor.setdefault('commit_index', 0)
            while index < len(commits):
                commit = commits[index]['sha']
                if not SHA.fullmatch(commit):
                    raise ValueError('invalid CVE changed commit')
                file_page = self.cursor.setdefault('file_page', 1)
                while True:
                    self.unit()
                    detail = self.http.get_json(f'https://api.github.com/repos/{repo}/commits/{commit}?per_page=100&page={file_page}')
                    files = detail.get('files')
                    if not isinstance(files, list):
                        raise ValueError('missing CVE changed files')
                    self.cve_changed_files(files, revision, 'file_offset')
                    self.cursor['file_offset'] = 0
                    if len(files) < 100:
                        break
                    # GitHub commit endpoint limits the complete list to 3000.
                    if file_page >= 30:
                        raise ValueError('CVE single commit file inventory truncated at 3000')
                    file_page += 1
                    self.cursor['file_page'] = file_page
                index += 1
                self.cursor.update(commit_index=index, file_page=1)
            if len(commits) < 100:
                if (page_number - 1) * 100 + len(commits) != comparison.get('total_commits'):
                    raise ValueError('incomplete CVE comparison commit enumeration')
                break
            page_number += 1
            self.cursor.update(commit_page=page_number, commit_index=0)
        self.finish(revision, watermark=self.cursor['window_end'])

    def cve_changed_files(self, files, revision, offset_key):
        previous = {x['native_id']: x for x in self.previous}
        for index in range(self.cursor.get(offset_key, 0), len(files)):
            changed = files[index]
            path = checked_path(changed['filename'])
            identifier = PurePosixPath(path).stem
            if path.startswith('cves/') and path.endswith('.json') and CVE.fullmatch(identifier):
                self.unit()
                try:
                    raw = self.http.get_json(raw_url(REPOS['cve'], revision, cve_path(identifier)))
                    self.add(normalize_cve(raw, revision))
                except FetchError as exc:
                    if exc.status != 404:
                        raise
                    # A historical commit may remove then re-add the record.
                    # Only absence at the final fixed revision is a deletion.
                    if identifier in previous:
                        row = copy.deepcopy(previous[identifier])
                        row.update(status='source_deleted', source_modified_at=None)
                        self.add(row)
            self.cursor[offset_key] = index + 1

    def ghsa(self):
        if not self.cursor:
            start = timestamp(self.now) - timedelta(days=self.policy.get('retention_days', 30))
            if self.old.get('completed_watermark'):
                start = max(start, timestamp(self.old['completed_watermark']) - timedelta(hours=self.policy.get('overlap_hours', 48)))
            self.cursor = {'start': iso(start), 'end': self.now, 'phase': 0, 'offset': 0,
                           'pagination': 'github-link-v1'}
        elif self.cursor.get('pagination') != 'github-link-v1':
            # Numeric page was never a supported global-advisory API cursor.
            # Replay the same complete window; already stored records deduplicate.
            self.cursor = {'start': self.cursor['start'], 'end': self.cursor['end'],
                           'phase': 0, 'offset': 0, 'pagination': 'github-link-v1'}
            self.state['pagination_recovery'] = 'legacy numeric page checkpoint replayed within its original window'
        self.result.revision = self.cursor['end']
        phases = ('published', 'updated')
        while self.cursor['phase'] < 2:
            field = phases[self.cursor['phase']]
            filters = {'type': 'reviewed', field: f'{self.cursor["start"]}..{self.cursor["end"]}',
                       'sort': field, 'direction': 'asc', 'per_page': '100'}
            url = advisory_page_url(self.cursor.get('current_url') or
                                    'https://api.github.com/advisories?' + urlencode(filters), filters)
            self.cursor['current_url'] = url
            page = self.http.get_json(url)
            if not isinstance(page, list):
                raise ValueError('invalid GHSA page')
            next_url = advisory_next_url(getattr(self.http, 'last_headers', {}), filters)
            visited = self.cursor.setdefault('visited_pages', [])
            current_hash = hashlib.sha256(url.encode()).hexdigest()
            if next_url and (not page or hashlib.sha256(next_url.encode()).hexdigest() in visited + [current_hash]):
                raise ValueError('GHSA pagination next cursor did not advance')
            page_hash = hashlib.sha256(canonical(page)).hexdigest()
            if self.cursor.get('page_hash') != page_hash:
                self.cursor['offset'] = 0
            self.cursor['page_hash'] = page_hash
            for raw in page[self.cursor['offset']:]:
                self.unit()
                self.add(normalize_ghsa(raw))
                self.cursor['offset'] += 1
            self.cursor['offset'] = 0
            self.cursor.pop('page_hash')
            if next_url is None:
                self.cursor['phase'] += 1
                self.cursor.pop('current_url')
                self.cursor['visited_pages'] = []
            else:
                visited.append(current_hash)
                self.cursor['current_url'] = next_url
        # A review-state change can remove an entry from reviewed listings.
        if self.old.get('reconciled_on') != self.now[:10]:
            retained = sorted({row['native_id'] for row in self.previous})
            while self.cursor.get('reconcile_offset', 0) < len(retained):
                self.unit()
                index = self.cursor.get('reconcile_offset', 0)
                identifier = retained[index]
                raw = self.http.get_json(f'https://api.github.com/advisories/{identifier}')
                self.add(normalize_ghsa(raw))
                self.cursor['reconcile_offset'] = index + 1
            self.state['reconciled_on'] = self.now[:10]
        previous_start = self.old.get('coverage_start')
        self.state['coverage_start'] = min(previous_start, self.cursor['start']) if previous_start else self.cursor['start']
        self.finish(self.cursor['end'], watermark=self.cursor['end'])

    def kev(self):
        revision = self.pinned(REPOS['kev'])
        if revision == self.old.get('revision') and self.old.get('status') == 'ok':
            self.finish(revision)
            return
        raw = self.http.get_json(raw_url(REPOS['kev'], revision, 'known_exploited_vulnerabilities.json'))
        entries = raw['vulnerabilities']
        if not isinstance(entries, list) or raw.get('count') != len(entries):
            raise ValueError('incomplete KEV catalog')
        rows = [normalize_kev(x, revision) for x in entries]
        for row in rows:
            self.add(row)
        self.state['coverage'] = 'full-catalog'
        self.finish(revision, authoritative=[x['record_id'] for x in rows])

    def intel(self):
        dep = self.dependency
        if not dep or dep.get('repository') not in ('argus-intel-data', 'argus-supply/argus-intel-data') or not SHA.fullmatch(dep.get('commit_sha', '')):
            raise ValueError('missing immutable intel dependency')
        if not re.fullmatch(r'[0-9a-f]{64}', dep.get('manifest_sha256', '')):
            raise ValueError('invalid intel manifest hash')
        sha = dep['commit_sha']
        if self.cursor.get('intel_commit_sha') not in (None, sha):
            raise ValueError('resume requires the original intel dependency revision')
        self.cursor['intel_commit_sha'] = sha
        records = [x for x in dep['records'] if x.get('status') == 'active']
        return sha, records

    def poc(self):
        intel_sha, intel = self.intel()
        revision = self.pinned(REPOS['poc-in-github'])
        if (not self.old.get('continuation') and self.old.get('status') == 'ok' and
                revision == self.old.get('revision') and intel_sha == self.old.get('intel_commit_sha')):
            self.finish(revision, watermark=self.old.get('completed_watermark'))
            return
        active = sorted({a for x in intel for a in x.get('aliases', []) if CVE.fullmatch(a)})
        if self.poc_plan(active, revision):
            # A truncated compare is not a deletion inventory. Publish the
            # recovery checkpoint before spending a later job on its full scan.
            return
        self.poc_working = copy.deepcopy(self.previous_by_id)
        self.poc_by_alias = {}
        for key, row in self.poc_working.items():
            for alias in row['aliases']:
                self.poc_by_alias.setdefault(alias, set()).add(key)
        if not self.cursor.get('active_reconciled'):
            updates = {}
            for key, old in self.poc_working.items():
                removed = set(old['aliases']) - set(active)
                if removed:
                    row = copy.deepcopy(old)
                    for alias in sorted(removed):
                        self.poc_remove_mapping(row, alias, 'outside_active_intel_set', revision, intel_sha)
                    updates[key] = row
            self.poc_store(updates)
            self.cursor['active_reconciled'] = True
        if self.cursor.get('recovery_reason'):
            self.result.coverage_gaps = [{'source_id': self.source, 'reason': self.cursor['recovery_reason'],
                'recovery': 'complete pinned active-set scan pending'}]
        selected_ids = self.cursor['scan_ids']
        for index in range(self.cursor.get('offset', 0), len(selected_ids)):
            self.unit()
            cve = selected_ids[index]
            missing = False
            try:
                raw = self.http.get_json(raw_url(REPOS['poc-in-github'], revision, f'{cve.split("-")[1]}/{cve}.json'))
            except FetchError as exc:
                if exc.status != 404:
                    raise
                raw = []
                missing = True
            if not isinstance(raw, list):
                raise ValueError('invalid per-CVE PoC index')
            unique = {public_url(x['html_url']): x for x in raw}
            selected = sorted(unique)[:self.policy.get('max_pocs_per_vulnerability', 100)]
            updates = {}
            for url in selected:
                row = normalize_poc(unique[url], cve, revision, intel_sha)
                old = self.poc_working.get(row['record_id'])
                aliases = set(old['aliases']) if old else set()
                row['aliases'] = row['advisory_ids'] = sorted(aliases | {cve})
                if old:
                    if old.get('mapping_history'):
                        row['mapping_history'] = copy.deepcopy(old['mapping_history'])
                    # Preserve earlier URL attribution if the indexed repository
                    # was renamed; revision-only polls are not new evidence.
                    row['provenance'] = [item for item in old['provenance'] if item.get('url') != url] + row['provenance']
                selections = self.poc_selections(old) if old else {}
                selections[cve] = {'selected_count': len(selected), 'total_known_count': len(unique)}
                row['selection_by_advisory'] = selections
                self.poc_counts(row)
                updates[row['record_id']] = row
            for key in self.poc_by_alias.get(cve, set()) - set(updates):
                row = copy.deepcopy(self.poc_working[key])
                reason = ('source_file_absent' if missing else 'selection_limit' if row['url'] in unique
                          else 'source_reference_removed')
                self.poc_remove_mapping(row, cve, reason, revision, intel_sha)
                updates[key] = row
            # Validate the entire successful file's reconciliation before any
            # mapping from that unit is staged or its offset is advanced.
            self.poc_store(updates)
            self.cursor['offset'] = index + 1
        self.state['intel_commit_sha'] = intel_sha
        self.state['active_ids'] = active
        self.state['last_scan_mode'] = self.cursor['scan_mode']
        self.result.coverage_gaps = []
        self.finish(revision, watermark=self.cursor['window_end'])

    def poc_plan(self, active, revision):
        """Plan only changed/new active CVEs, or a restartable bounded recovery."""
        if 'scan_ids' in self.cursor:
            if not isinstance(self.cursor['scan_ids'], list) or not set(self.cursor['scan_ids']).issubset(active):
                raise ValueError('PoC continuation active-set mismatch')
            return False
        self.cursor.setdefault('window_end', self.now)
        if self.old.get('continuation'):
            # Previously published offset-only checkpoints enumerated all active
            # CVEs in this same immutable intel snapshot and sorted order.
            self.cursor.update(scan_ids=active, scan_mode='full-legacy-resume')
            return False
        previous_active = self.old.get('active_ids')
        if self.old.get('status') != 'ok' or not isinstance(previous_active, list):
            self.cursor.update(scan_ids=active, scan_mode='full-bootstrap', offset=0)
            return False
        if any(not isinstance(identifier, str) or not CVE.fullmatch(identifier) for identifier in previous_active):
            raise ValueError('invalid saved PoC active inventory')
        selected = set(active) - set(previous_active)
        base = self.old.get('revision', '')
        recovery = None
        if revision != base:
            if not SHA.fullmatch(base):
                recovery = 'previous PoC revision unavailable'
            else:
                try:
                    comparison = self.http.get_json(f'https://api.github.com/repos/{REPOS["poc-in-github"]}/compare/{base}...{revision}?per_page=1')
                except FetchError as exc:
                    if exc.status != 404:
                        raise
                    comparison = {'status': 'unavailable', 'files': []}
                if comparison.get('status') not in ('ahead', 'identical'):
                    recovery = 'PoC upstream comparison history diverged or is unavailable'
                elif not isinstance(comparison.get('files'), list):
                    raise ValueError('missing PoC compare file inventory')
                elif comparison.get('truncated') or len(comparison['files']) >= 300:
                    recovery = 'PoC compare file inventory truncated at 300'
                else:
                    for item in comparison['files']:
                        for field in ('filename', 'previous_filename'):
                            if field not in item:
                                continue
                            path = checked_path(item[field])
                            parts = PurePosixPath(path).parts
                            identifier = PurePosixPath(path).stem
                            if (len(parts) == 2 and path.endswith('.json') and CVE.fullmatch(identifier)
                                    and parts[0] == identifier.split('-')[1] and identifier in active):
                                selected.add(identifier)
        self.cursor.update(scan_ids=active if recovery else sorted(selected), offset=0,
            scan_mode='full-recovery' if recovery else 'changed-and-new', base_revision=base)
        if recovery:
            self.cursor['recovery_reason'] = recovery
            self.result.coverage_gaps = [{'source_id': self.source, 'reason': recovery,
                'recovery': 'complete pinned active-set scan pending'}]
            return True
        return False

    def poc_store(self, updates):
        for row in updates.values():
            self.check_record(row)
        for key, row in updates.items():
            old = self.poc_working.get(key)
            if old:
                for alias in old['aliases']:
                    self.poc_by_alias.get(alias, set()).discard(key)
            for alias in row['aliases']:
                self.poc_by_alias.setdefault(alias, set()).add(key)
            self.poc_working[key] = row
            self.result.records.append(row)

    @staticmethod
    def poc_selections(row):
        if 'selection_by_advisory' in row:
            return copy.deepcopy(row['selection_by_advisory'])
        # Legacy multi-CVE records did not retain distinct per-CVE counts.
        return {alias: {key: row.get(key) if len(row['aliases']) == 1 else None
                       for key in ('selected_count', 'total_known_count')} for alias in row['aliases']}

    @staticmethod
    def poc_counts(row):
        for key in ('selected_count', 'total_known_count'):
            values = {entry[key] for entry in row['selection_by_advisory'].values()}
            row[key] = next(iter(values)) if len(values) == 1 else None

    def poc_remove_mapping(self, row, alias, reason, revision, intel_sha):
        selections = self.poc_selections(row)
        selections.pop(alias, None)
        row['selection_by_advisory'] = selections
        row['aliases'] = row['advisory_ids'] = sorted(set(row['aliases']) - {alias})
        row.setdefault('mapping_history', {})[alias] = {'reason': reason,
            'source_revision': revision, 'intel_commit_sha': intel_sha,
            'source_index_url': raw_url(REPOS['poc-in-github'], revision, f'{alias.split("-")[1]}/{alias}.json')}
        row.update(index_revision=revision, intel_commit_sha=intel_sha, source_modified_at=None)
        if not row['aliases']:
            row['status'] = ('retention_removed' if reason == 'outside_active_intel_set' else
                             'selection_removed' if reason == 'selection_limit' else 'source_deleted')
        self.poc_counts(row)

    def exploitdb(self):
        intel_sha, intel = self.intel()
        active = {a for x in intel for a in x.get('aliases', []) if CVE.fullmatch(a)}
        if self.old.get('checked_on') == self.now[:10] and not self.policy.get('manual', False):
            self.finish(self.old.get('revision'))
            return
        project = 'https://gitlab.com/api/v4/projects/exploit-database%2Fexploitdb'
        if not self.cursor.get('revision'):
            rows = self.http.get_json(f'{project}/repository/commits?per_page=1')
            self.cursor['revision'] = rows[0]['id']
        revision = self.cursor['revision']
        if not SHA.fullmatch(revision):
            raise ValueError('invalid Exploit-DB revision')
        self.result.revision = revision
        if revision == self.old.get('revision') and self.old.get('status') == 'ok':
            self.state['checked_on'] = self.now[:10]
            self.finish(revision, watermark=self.old.get('completed_watermark'))
            return
        data = self.http.get_bytes(f'{project}/repository/files/files_exploits.csv/raw?ref={revision}')
        if len(data) > self.policy.get('exploitdb_max_bytes', 10 * 1024 * 1024):
            raise ValueError('oversize Exploit-DB CSV')
        reader = csv.DictReader(io.StringIO(data.decode('utf-8-sig')))
        if not {'id', 'description', 'codes', 'date_published'}.issubset(reader.fieldnames or []):
            raise ValueError('unsupported Exploit-DB CSV schema')
        cutoff = (timestamp(self.now) - timedelta(days=self.policy.get('retention_days', 30))).date().isoformat()
        for index, entry in enumerate(reader):
            if index < self.cursor.get('offset', 0):
                continue
            aliases = sorted(set(CVE.findall(entry['codes'])))
            if not active.intersection(aliases) and entry['date_published'] < cutoff:
                self.cursor['offset'] = index + 1
                continue
            self.unit()
            if not entry['id'].isdigit():
                raise ValueError('invalid Exploit-DB ID')
            url = f'https://www.exploit-db.com/exploits/{entry["id"]}'
            row = base_record('exploitdb', entry['id'], 'poc', title=entry['description'],
                aliases=aliases, published=entry['date_published'], modified=entry.get('date_updated'),
                revision=revision, url=url)
            row.update({'url': url, 'author': entry.get('author'), 'advisory_ids': aliases,
                'mapping_confidence': 'source-asserted' if aliases else 'unknown',
                'upstream_revision': revision, 'intel_commit_sha': intel_sha,
                'prerequisites': {'platform': entry.get('platform'), 'type': entry.get('type'), 'port': entry.get('port')},
                'availability': 'not-checked', 'verification': {'author_claim': 'proof-of-concept',
                    'upstream_verified': entry.get('verified') == '1', 'static_analysis': 'not-performed',
                    'executed': False, 'status': 'unverified'}, 'selected_count': None, 'total_known_count': None})
            self.add(row)
            self.cursor['offset'] = index + 1
        self.state.update(checked_on=self.now[:10], intel_commit_sha=intel_sha)
        self.finish(revision)

    def official(self):
        intel_sha, intel = self.intel()
        if self.old.get('revision') == intel_sha and self.old.get('completed_watermark'):
            # A completed immutable snapshot also proves that any later cursor
            # scanning this same SHA is redundant, even if it reports partial.
            self.finish(intel_sha, watermark=self.old['completed_watermark'])
            return
        for index in range(self.cursor.get('offset', 0), len(intel)):
            self.unit()
            advisory = intel[index]
            for ref in advisory.get('references', []):
                url = public_url(ref['url'])
                # These are explicitly attributed references, never an invented
                # claim that the site hosts a working PoC or vendor endorsement.
                native = hashlib.sha256((advisory['record_id'] + '\0' + url).encode()).hexdigest()
                row = base_record('official-references', native, 'poc', title=ref.get('name') or url,
                    aliases=advisory.get('aliases', []), published=advisory.get('published_at'),
                    modified=advisory.get('source_modified_at'), revision=intel_sha, url=url)
                row.update(url=url, author=None, advisory_ids=advisory.get('aliases', []),
                    mapping_confidence='explicit-advisory-reference', reference_type='advisory-reference',
                    upstream_revision=None, intel_commit_sha=intel_sha, prerequisites=None,
                    availability='not-checked', verification={'status': 'reference-only', 'executed': False},
                    selected_count=None, total_known_count=None)
                row['provenance'].append({'source_record_id': advisory['record_id'], 'reference': ref})
                self.add(row)
            self.cursor['offset'] = index + 1
        self.finish(intel_sha)

    def nuclei(self):
        repo = REPOS['nuclei']
        revision = self.pinned(repo)
        if revision == self.old.get('revision') and self.old.get('status') == 'ok':
            self.finish(revision)
            return
        # The fixed revision makes re-enumeration safe. Keep the multi-MiB tree
        # transient rather than publishing a duplicate raw inventory in state.
        tree = self.http.get_json(f'https://api.github.com/repos/{repo}/git/trees/{revision}?recursive=1')
        if tree.get('truncated'):
            raise ValueError('truncated Nuclei upstream tree; bounded subtree recovery required')
        if not isinstance(tree.get('tree'), list):
            raise ValueError('invalid Nuclei tree')
        inventory = {}
        for entry in tree['tree']:
            if entry.get('type') != 'blob':
                continue
            path = checked_path(entry['path'])
            if path.split('/')[0] in ('http', 'network', 'helpers'):
                inventory[path] = {'sha': entry['sha'], 'size': entry.get('size'), 'mode': entry.get('mode')}
        if len(canonical(inventory)) > self.policy.get('max_tree_bytes', 32 * 1024 * 1024):
            raise ValueError('oversize Nuclei inventory')
        self.cursor.setdefault('offset', 0)
        paths = sorted(p for p in inventory if p.split('/')[0] in ('http', 'network') and p.endswith(('.yaml', '.yml')))
        old = {x.get('path'): x for x in self.previous}
        for index in range(self.cursor['offset'], len(paths)):
            path = paths[index]
            if path in old and old[path].get('blob_sha') == inventory[path]['sha']:
                # Dependency-only changes are material even when YAML is stable.
                if all(inventory.get(d['path'], {}).get('sha') == d.get('blob_sha') for d in old[path].get('dependencies', [])):
                    self.cursor['offset'] = index + 1
                    continue
            self.unit()
            if inventory[path]['mode'] not in ('100644', '100755'):
                raise ValueError(f'unsupported template symlink:{path}')
            size_limit = self.policy.get('resource_max_bytes', 2 * 1024 * 1024)
            if (inventory[path]['size'] or 0) > size_limit:
                raise ValueError(f'oversize template:{path}')
            data = self.http.get_bytes(raw_url(repo, revision, path))
            row = normalize_template(data, path, revision, inventory[path]['sha'], max_bytes=size_limit)
            total = len(data)
            for dependency in row['dependencies']:
                dep_path = dependency['path']
                if dep_path not in inventory:
                    raise ValueError(f'missing template dependency:{dep_path}')
                blob = inventory[dep_path]
                if blob['mode'] not in ('100644', '100755'):
                    raise ValueError('template dependency symlink is not allowed')
                if blob['size'] is None or total + blob['size'] > size_limit:
                    raise ValueError('oversize template dependency bundle')
                content = self.http.get_bytes(raw_url(repo, revision, dep_path))
                total += len(content)
                actual = hashlib.sha1(b'blob ' + str(len(content)).encode() + b'\0' + content).hexdigest()
                if total > size_limit or actual != blob['sha']:
                    raise ValueError('template dependency size/hash mismatch')
                dependency.update(status='verified', blob_sha=actual,
                    sha256=hashlib.sha256(content).hexdigest(), bytes=len(content))
            self.add(row)
            self.cursor['offset'] = index + 1
        self.state['coverage'] = 'current-http-network-catalog'
        self.finish(revision, authoritative=[f'nuclei/{p}' for p in paths])


def collect(source_id, http, previous, *, now, policy, dependency=None):
    """Collect completed units; all failures retain a resumable source checkpoint."""
    run = Run(source_id, http, previous, now, policy, dependency)
    method = {'cve': run.cve, 'ghsa': run.ghsa, 'kev': run.kev,
        'poc-in-github': run.poc, 'exploitdb': run.exploitdb,
        'official-references': run.official, 'nuclei': run.nuclei}.get(source_id)
    if method is None:
        raise ValueError('unknown registered source')
    try:
        method()
    except Exception as exc:
        # Transport errors contain bounded redacted reasons; never store response
        # bodies, secrets, or arbitrary exception representations in public state.
        code = type(exc).__name__
        detail = str(exc)[:300] if isinstance(exc, (ValueError, FetchError, BudgetExceeded)) else code
        run.result.errors = [{'code': code, 'message': detail, 'http_status': getattr(exc, 'status', None)}]
        run.result.coverage_gaps.append({'reason': detail, 'source_id': source_id})
        run.result.status = 'partial' if run.result.records or run.previous or run.cursor else 'failed'
    unique = {}
    for row in run.result.records:
        key = row['record_id']
        if key in unique and row['kind'] == 'poc' and row['source_id'] != 'poc-in-github':
            row['aliases'] = sorted(set(row['aliases'] + unique[key]['aliases']))
            row['advisory_ids'] = sorted(set(row['advisory_ids'] + unique[key]['advisory_ids']))
            row['provenance'] = list({canonical(item): item for item in
                unique[key]['provenance'] + row['provenance']}.values())
        unique[key] = row
    run.result.records = list(unique.values())
    run.result.continuation = run.cursor or None
    run.state.update(status=run.result.status, revision=run.result.revision,
        completed_watermark=run.result.completed_watermark, continuation=run.result.continuation,
        coverage_gaps=run.result.coverage_gaps, errors=run.result.errors)
    return run.result
