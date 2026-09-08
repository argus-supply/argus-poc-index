"""Source-specific collectors. No upstream PoC, template or script is executed."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import csv
from datetime import datetime, timedelta, timezone
import fnmatch
import io
import json
import os
from pathlib import PurePosixPath
import re
import time
from urllib.parse import quote, urlencode
import xml.etree.ElementTree as ET

import yaml

from runtime import GitTree, canonical, digest, get_json, request

CVE = re.compile(r'CVE-\d{4}-\d{4,}')


def cves(value):
    return sorted(set(CVE.findall(canonical(value))))


def advisory(identifier, raw, *, aliases=(), title='', published=None, modified=None, **extra):
    return {'id': identifier, 'kind': 'advisory', 'aliases': sorted(set(aliases)),
            'title': title, 'published': published, 'modified': modified, 'raw': raw, **extra}


def parse_nvd(path, data):
    raw = json.loads(data)
    raw = raw.get('cve', raw)
    identifier = raw['id']
    if not CVE.fullmatch(identifier):
        raise ValueError('invalid NVD id')
    # Rejections remain explicit records, allowing consumers to remove prior findings.
    title = next((d['value'] for d in raw.get('descriptions', []) if d.get('lang') == 'en'), '')
    return [advisory(identifier, raw, title=title, published=raw.get('published'),
                     modified=raw.get('lastModified'), withdrawn=raw.get('vulnStatus') == 'Rejected')], None


def parse_kev(path, data):
    raw = json.loads(data)
    entries = raw['vulnerabilities']
    if not isinstance(entries, list) or not entries:
        raise ValueError('empty KEV catalog')
    return [advisory(r['cveID'], r, title=r.get('vulnerabilityName', ''),
                     published=r.get('dateAdded'), known_exploited=True) for r in entries], None


def poc(identifier, cve, title, url, raw, **extra):
    return {'id': f'{cve}:{identifier}', 'upstream_id': str(identifier), 'kind': 'poc',
            'cve': cve, 'title': title, 'url': url, 'raw': raw, **extra}


def parse_github_poc(path, data):
    cve = PurePosixPath(path).stem
    raw = json.loads(data)
    if not isinstance(raw, list):
        raise ValueError('invalid PoC-in-GitHub index')
    rows = {}
    for entry in raw:
        url = entry.get('html_url')
        if not url:
            continue
        row = poc(entry.get('id', url), cve, entry.get('full_name', url), url, entry,
                  published=entry.get('created_at'), modified=entry.get('updated_at'))
        rows[row['id']] = row
    return list(rows.values()), None


def parse_exploitdb(path, data):
    reader = csv.DictReader(io.StringIO(data.decode('utf-8-sig')))
    if not {'id', 'codes', 'description'}.issubset(reader.fieldnames or []):
        raise ValueError('invalid Exploit-DB CSV header')
    rows = {}
    for entry in reader:
        aliases = [x.strip() for x in entry['codes'].split(';') if x.strip()]
        for cve in sorted(set(x for x in aliases if CVE.fullmatch(x))):
            row = poc(entry['id'], cve, entry['description'],
                      f"https://www.exploit-db.com/exploits/{entry['id']}", entry,
                      aliases=[x for x in aliases if x != cve],
                      published=entry.get('date_published'), modified=entry.get('date_updated'))
            prior = rows.get(row['id'])
            if prior:
                row['aliases'] = sorted(set(prior['aliases'] + row['aliases']))
                variants = prior.get('raw_variants', [prior['raw']])
                if entry not in variants:
                    variants.append(entry)
                row['raw_variants'] = variants
            rows[row['id']] = row
    return list(rows.values()), None


def parse_resource(path, data):
    if path.endswith(('.yaml', '.yml')):
        try:
            doc = yaml.safe_load(data)
        except yaml.YAMLError:
            # Preserve coverage metadata, but exclude malformed files from the bundle.
            return [{'id': path, 'kind': 'coverage', 'path': path, 'cves': cves(path),
                     'validation': 'invalid-yaml', 'sha256': digest(data)}], None
        if not isinstance(doc, dict) or not isinstance(doc.get('info'), dict) or not isinstance(doc.get('id'), str):
            return [{'id': path, 'kind': 'coverage', 'path': path, 'cves': cves(path),
                     'validation': 'not-a-nuclei-template', 'sha256': digest(data)}], None
        return [{'id': path, 'kind': 'template', 'template_id': doc['id'], 'path': path,
                 'title': doc['info'].get('name', ''), 'cves': cves([path, doc['info'].get('classification', {})]),
                 'validation': 'yaml-structure-only', 'runtime_validated': False,
                 'sha256': digest(data)}], data
    if path.endswith('.json'):
        raw = json.loads(data)
        components = []
        for entry in raw if isinstance(raw, list) else []:
            if isinstance(entry, dict):
                metadata = entry.get('info', {}).get('metadata', {})
                product = metadata.get('product') or entry.get('id')
                if isinstance(product, str):
                    components.append(product)
        return [{'id': path, 'kind': 'fingerprint', 'path': path, 'sha256': digest(data),
                 'components': sorted(set(components)),
                 'validation': 'json-syntax-only', 'runtime_validated': False,
                 'entry_count': len(raw) if isinstance(raw, (list, dict)) else None}], data
    return [], None


def parse_missing(path, data):
    entries = json.loads(data)
    if not isinstance(entries, list) or not entries:
        raise ValueError('invalid missing-template dataset')
    rows = {}
    for raw in entries:
        identifier = raw['cve']
        if not CVE.fullmatch(identifier):
            raise ValueError('invalid coverage CVE id')
        rows[identifier] = {'id': identifier, 'kind': 'coverage-gap', 'cves': [identifier],
                            'upstream_reports_missing_template': True, 'raw': raw}
    return list(rows.values()), None


PARSERS = {'nvd': parse_nvd, 'kev': parse_kev, 'github-poc': parse_github_poc,
           'exploitdb': parse_exploitdb, 'resources': parse_resource, 'missing': parse_missing}


def license_path(path):
    parts = PurePosixPath(path).parts
    return any(part.upper() == 'LICENSES' for part in parts) or parts[-1].upper().startswith(('LICENSE', 'COPYING', 'NOTICE'))


def selected(source, path):
    if license_path(path):
        return True
    if source['parser'] == 'nvd':
        match = re.search(r'CVE-(\d{4})-\d+\.json$', path)
        return bool(match and int(match[1]) >= source.get('min_year', 2018))
    if source['parser'] == 'github-poc':
        return bool(CVE.fullmatch(PurePosixPath(path).stem) and path.endswith('.json'))
    return any(fnmatch.fnmatch(path, pattern) for pattern in source['include'])


def git_feed(store, source, previous, cache, limit):
    tree = GitTree(source, cache)
    sid = source['id']
    inventory = {path: sha for path, sha in tree.files() if selected(source, path)}
    if not inventory:
        raise ValueError('upstream selected inventory unexpectedly empty')
    known = dict(store.db.execute('SELECT name,version FROM units WHERE source=?', (sid,)))
    for path in known.keys() - inventory.keys():
        store.remove(sid, path)
    changed = [path for path, sha in inventory.items() if known.get(path) != sha]
    licenses = [path for path in changed if license_path(path)]
    pending = [path for path in changed if path not in licenses]
    # Recent CVEs become available immediately during an initial bounded backfill.
    pending.sort(reverse=True)
    for path in licenses + pending[:limit]:
        data = tree.read(path)
        if license_path(path):
            rows, blob = [{'id': 'license:' + path, 'kind': 'license', 'path': path,
                           'sha256': digest(data)}], data
        else:
            rows, blob = PARSERS[source['parser']](path, data)
        store.replace(sid, path, inventory[path], rows, blob)
    remaining = max(0, len(pending) - limit)
    return {'status': 'partial' if remaining else 'ok', 'revision': tree.revision,
            'complete_revision': previous.get('complete_revision') if remaining else tree.revision,
            'ref': tree.ref, 'remaining_files': remaining, 'total_files': len(inventory)}


def osv_feed(store, source, previous, cache, limit):
    sid = source['id']
    ecosystems = source['ecosystems']
    eco_index = previous.get('ecosystem_index', 0)
    token = previous.get('token', '')
    offset = previous.get('offset', 0)
    used = 0
    listed = 0
    namespace = {'s': 'http://doc.s3.amazonaws.com/2006-03-01'}
    while eco_index < len(ecosystems) and used < limit and listed < source.get('max_list_pages', 40):
        params = {'list-type': '2', 'prefix': ecosystems[eco_index] + '/', 'max-keys': 500}
        if token:
            params['continuation-token'] = token
        page = ET.fromstring(request(source['url'] + '?' + urlencode(params)))
        listed += 1
        # GCS XML responses use the S3 namespace; reject error/unknown envelopes.
        if not page.tag.endswith('ListBucketResult'):
            raise ValueError('invalid OSV listing')
        if page.tag.startswith('{'):
            namespace['s'] = page.tag[1:].split('}')[0]
        entries = page.findall('s:Contents', namespace)
        batch = []
        index = offset
        while index < len(entries) and used < limit:
            entry = entries[index]
            key = entry.findtext('s:Key', namespaces=namespace)
            etag = entry.findtext('s:ETag', namespaces=namespace)
            index += 1
            if not key or not etag or not key.endswith('.json'):
                continue
            if store.version(sid, key) != etag:
                batch.append((key, etag))
                used += 1
        def fetch(item):
            key, etag = item
            return key, etag, get_json(source['url'] + '/' + quote(key, safe='/'))
        with ThreadPoolExecutor(max_workers=8) as pool:
            for key, etag, raw in pool.map(fetch, batch):
                row = advisory(raw['id'], raw, aliases=raw.get('aliases', []),
                               title=raw.get('summary', ''), published=raw.get('published'),
                               modified=raw.get('modified'), withdrawn=bool(raw.get('withdrawn')))
                # Include ecosystem in the internal key: the same OSV id may be
                # exported under several ecosystem prefixes. Aliases retain its id.
                row['upstream_id'] = row['id']
                row['id'] = key
                store.replace(sid, key, etag, [row])
        if index < len(entries):
            offset = index
            break
        offset = 0
        token = page.findtext('s:NextContinuationToken', default='', namespaces=namespace)
        if not token:
            eco_index += 1
    complete = eco_index == len(ecosystems)
    return {'status': 'ok' if complete else 'partial', 'ecosystem_index': 0 if complete else eco_index,
            'token': '' if complete else token, 'offset': 0 if complete else offset,
            'completed_loops': previous.get('completed_loops', 0) + int(complete),
            'last_complete': time.time() if complete else previous.get('last_complete'),
            'deletion_policy': 'withdrawn field retained; missing objects are not inferred as withdrawn'}


def chaitin_feed(store, source, previous, cache, limit):
    sid = source['id']
    used = 0
    done = set()
    def save_detail(key):
        raw = get_json(f"{source['url']}/detail/?id={quote(key)}")['data']
        aliases = [raw[k] for k in ('cve_id', 'ct_id', 'cnvd_id', 'cnnvd_id') if raw.get(k)]
        row = advisory(key, raw, aliases=aliases, title=raw.get('title', raw.get('title_en', '')),
                       published=raw.get('disclosure_date', raw.get('created_at')),
                       modified=raw.get('updated_at'))
        store.replace(sid, key, digest(canonical(raw).encode()), [row])
    # Refreshes get a separate budget so old records cannot starve historical discovery.
    due = store.db.execute('SELECT name FROM units WHERE source=? AND checked<? '
                           'ORDER BY checked LIMIT ?',
                           (sid, time.time() - source.get('reprobe_days', 7) * 86400, limit // 4)).fetchall()
    for (key,) in due:
        save_detail(key)
        used += 1
    # Always inspect recent pages first, then resume historical traversal.
    historical = previous.get('offset', 0)
    offsets = [0] + ([historical] if historical else [])
    next_offset = historical
    exhausted = False
    for start in offsets:
        offset = start
        pages = 0
        while used < limit and pages < source.get('max_list_pages', 20):
            envelope = get_json(f"{source['url']}/list/?limit=100&offset={offset}")
            data = envelope['data']
            if not isinstance(data.get('list'), list) or not isinstance(data.get('count'), int):
                raise ValueError('invalid Chaitin listing')
            entries = data['list']
            for entry in entries:
                key = str(entry['id'])
                if key in done:
                    continue
                done.add(key)
                if store.version(sid, key) is not None:
                    continue
                if used >= limit:
                    break
                save_detail(key)
                used += 1
            # Revisit a partially processed page. Its checked records will be skipped.
            if used >= limit:
                next_offset = offset
                break
            offset += len(entries)
            pages += 1
            if not entries or offset >= data['count']:
                exhausted = True
                next_offset = 0
                break
            next_offset = offset
            if start == 0 and historical:
                break
        if used >= limit or exhausted:
            break
    return {'status': 'ok' if exhausted else 'partial', 'offset': next_offset,
            'last_complete': time.time() if exhausted else previous.get('last_complete')}


def day(timestamp):
    return datetime.fromtimestamp(timestamp, timezone.utc).strftime('%Y-%m-%d')


def api_window(previous, lookback):
    if previous.get('window'):
        return previous['window']
    end = time.time()
    start = previous.get('last_complete', end - lookback * 86400) - 2 * 86400
    return {'from': day(start), 'to': day(end), 'end': end}


def vulncheck_feed(store, source, previous, cache, limit):
    sid = source['id']
    key = os.environ.get(source['secret'])
    if not key:
        return {**previous, 'status': 'skipped', 'reason': 'missing API secret'}
    window = api_window(previous, source.get('lookback_days', 30))
    cursor = previous.get('cursor', '')
    pages = max(1, limit // 100)
    complete = False
    for _ in range(pages):
        params = {'lastModStartDate': window['from'], 'lastModEndDate': window['to'],
                  'sort': '_timestamp', 'order': 'asc', 'limit': 100}
        if cursor:
            params['cursor'] = cursor
        body = get_json(source['url'] + '?' + urlencode(params), headers={'Authorization': 'Bearer ' + key})
        if not isinstance(body.get('data'), list):
            raise ValueError('invalid VulnCheck data envelope')
        for raw in body['data']:
            cve = raw.get('id')
            if not isinstance(cve, str) or not CVE.fullmatch(cve):
                continue
            rows = {}
            for entry in raw.get('exploits', []):
                url = entry.get('url')
                if url:
                    row = poc(url, cve, entry.get('name', url), url, entry,
                              published=entry.get('date_added', raw.get('date_added')))
                    rows[row['id']] = row
            store.replace(sid, cve, digest(canonical(raw).encode()), list(rows.values()))
        next_cursor = body.get('_meta', {}).get('next_cursor') or ''
        if not next_cursor or not body['data']:
            complete = True
            cursor = ''
            break
        if next_cursor == cursor:
            raise ValueError('VulnCheck cursor did not advance')
        cursor = next_cursor
    return {'status': 'ok' if complete else 'partial', 'cursor': cursor,
            'window': None if complete else window,
            'last_complete': window['end'] if complete else previous.get('last_complete')}


def vulners_data(url, key, payload):
    body = get_json(url, headers={'X-Api-Key': key}, body=payload)
    if body.get('result') != 'OK':
        raise ValueError('Vulners rejected request')
    return body['data']


def vulners_poc_feed(store, source, previous, cache, limit):
    key = os.environ.get(source['secret'])
    if not key:
        return {**previous, 'status': 'skipped', 'reason': 'missing API secret'}
    window = api_window(previous, source.get('lookback_days', 30))
    offset = previous.get('offset', 0)
    complete = False
    for _ in range(max(1, limit // 100)):
        query = f"bulletinFamily:exploit AND published:[{window['from']} TO {window['to']}] order:published"
        data = vulners_data(source['url'] + '/api/v3/search/lucene', key,
                            {'query': query, 'skip': offset, 'size': 100,
                             'fields': ['id', 'title', 'href', 'published', 'modified', 'cvelist']})
        hits = data['search']
        if not isinstance(hits, list):
            raise ValueError('invalid Vulners search envelope')
        for hit in hits:
            raw = hit['_source']
            identifier = raw['id']
            rows = [poc(identifier, cve, raw.get('title', identifier), raw['href'], raw,
                        published=raw.get('published'), modified=raw.get('modified'))
                    for cve in sorted(set(raw.get('cvelist', []))) if CVE.fullmatch(cve)]
            store.replace(source['id'], identifier, digest(canonical(raw).encode()), rows)
        offset += len(hits)
        if len(hits) < 100:
            complete = True
            break
    return {'status': 'ok' if complete else 'partial', 'offset': 0 if complete else offset,
            'window': None if complete else window,
            'last_complete': window['end'] if complete else previous.get('last_complete')}


def vulners_enrichment_feed(store, source, previous, cache, limit):
    key = os.environ.get(source['secret'])
    if not key:
        return {**previous, 'status': 'skipped', 'reason': 'missing API secret'}
    sid = source['id']
    candidates = store.db.execute('''SELECT d.id FROM docs d
        LEFT JOIN units u ON u.source=? AND u.name=d.id
        WHERE d.source='nvd' AND (u.checked IS NULL OR u.checked<?)
        ORDER BY COALESCE(u.checked,0), d.id DESC LIMIT ?''',
        (sid, time.time() - source.get('reprobe_days', 7) * 86400, limit)).fetchall()
    ids = [row[0] for row in candidates]
    for index in range(0, len(ids), 100):
        batch = ids[index:index + 100]
        data = vulners_data(source['url'] + '/api/v3/search/id', key,
                            {'id': batch, 'references': True, 'fields': ['*'], 'referenceFields': ['*']})
        docs = data['documents']
        if not isinstance(docs, dict):
            raise ValueError('invalid Vulners documents envelope')
        found = {}
        for raw_key, raw in docs.items():
            identifier = raw.get('id', raw.get('cve', raw_key.split(':')[-1]))
            if identifier in batch:
                found[identifier] = raw
        for identifier in batch:
            raw = found.get(identifier)
            if raw is not None:
                aliases = []
                for reference in raw.get('enchantments', {}).get('dependencies', {}).get('references', []):
                    if reference.get('type') in ('cnvd', 'cnnvd'):
                        aliases.extend(x for x in reference.get('idList', []) if isinstance(x, str))
                rows = [advisory(identifier, raw, aliases=aliases,
                                 known_exploited=raw.get('wildExploited') is True,
                                 epss=raw.get('epss'), ai_score=raw.get('ai_score'))]
                store.replace(sid, identifier, digest(canonical(raw).encode()), rows)
            else:
                # A successful lookup with no result must not erase an older enrichment.
                store.db.execute('INSERT INTO units VALUES (?,?,?,?) ON CONFLICT(source,name) '
                                 'DO UPDATE SET checked=excluded.checked', (sid, identifier, 'absent', time.time()))
    return {'status': 'ok', 'last_batch_at': time.time() if ids else previous.get('last_batch_at'),
            'daily_budget': limit}


COLLECTORS = {'git': git_feed, 'osv': osv_feed, 'chaitin': chaitin_feed,
              'vulncheck': vulncheck_feed, 'vulners-poc': vulners_poc_feed,
              'vulners-enrichment': vulners_enrichment_feed}
