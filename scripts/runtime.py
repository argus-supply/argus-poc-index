"""Durable source transactions, HTTP/Git transport and versioned release packaging."""
from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import tarfile
import time
import urllib.error
import urllib.request

SCHEMA = 1


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'))


def digest(value):
    return hashlib.sha256(value).hexdigest()


def run(args, **kwargs):
    return subprocess.check_output(args, stderr=subprocess.PIPE, timeout=900, **kwargs)


def request(url, *, headers=None, body=None, output=None):
    """Retry transient transport failures without logging credentials or response bodies."""
    hdr = {'User-Agent': 'ARGUS-data-sync/1', **(headers or {})}
    if body is not None:
        hdr['Content-Type'] = 'application/json'
    req = urllib.request.Request(url, data=None if body is None else canonical(body).encode(), headers=hdr)
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=60) as response:
                if output is not None:
                    with Path(output).open('wb') as dest:
                        shutil.copyfileobj(response, dest)
                    return None
                return response.read()
        except urllib.error.HTTPError as error:
            if error.code not in (408, 429, 500, 502, 503, 504) or attempt == 2:
                raise RuntimeError(f'upstream HTTP {error.code}') from None
        except (urllib.error.URLError, TimeoutError, ConnectionError):
            if attempt == 2:
                raise RuntimeError('upstream transport failed after 3 attempts') from None
        time.sleep(2 ** (attempt + 1))


def get_json(url, **kwargs):
    return json.loads(request(url, **kwargs))


def github_json(path):
    headers = {'Accept': 'application/vnd.github+json'}
    if os.environ.get('GH_TOKEN'):
        headers['Authorization'] = 'Bearer ' + os.environ['GH_TOKEN']
    return get_json('https://api.github.com/' + path, headers=headers)


class Store:
    """Keep records, source ownership and cursors in the same atomic database."""

    def __init__(self, path):
        self.db = sqlite3.connect(path)
        self.db.executescript('''
          CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS docs (
            source TEXT, id TEXT, unit TEXT, payload TEXT NOT NULL,
            PRIMARY KEY(source,id));
          CREATE INDEX IF NOT EXISTS docs_unit ON docs(source,unit);
          CREATE TABLE IF NOT EXISTS units (
            source TEXT, name TEXT, version TEXT NOT NULL, checked REAL NOT NULL,
            PRIMARY KEY(source,name));
          CREATE TABLE IF NOT EXISTS state (source TEXT PRIMARY KEY, payload TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS blobs (source TEXT, path TEXT, data BLOB NOT NULL,
            PRIMARY KEY(source,path));
          CREATE TEMP TABLE changes (source TEXT, id TEXT, operation TEXT, payload TEXT,
            PRIMARY KEY(source,id));
        ''')
        version = self.db.execute("SELECT value FROM meta WHERE key='schema'").fetchone()
        if version is not None and int(version[0]) != SCHEMA:
            raise ValueError('unsupported snapshot schema')
        self.db.execute("INSERT OR IGNORE INTO meta VALUES ('schema',?)", (str(SCHEMA),))
        self.db.commit()

    def state(self, source):
        row = self.db.execute('SELECT payload FROM state WHERE source=?', (source,)).fetchone()
        return json.loads(row[0]) if row else {}

    def set_state(self, source, value):
        self.db.execute('INSERT OR REPLACE INTO state VALUES (?,?)', (source, canonical(value)))

    def version(self, source, name):
        row = self.db.execute('SELECT version FROM units WHERE source=? AND name=?', (source, name)).fetchone()
        return row[0] if row else None

    def checked(self, source, name):
        row = self.db.execute('SELECT checked FROM units WHERE source=? AND name=?', (source, name)).fetchone()
        return row[0] if row else 0

    def replace(self, source, unit, version, rows, blob=None):
        """Replace one upstream document; emit deletions as well as changed records."""
        old = dict(self.db.execute('SELECT id,payload FROM docs WHERE source=? AND unit=?', (source, unit)))
        incoming = {}
        for row in rows:
            key = row['id']
            if not isinstance(key, str) or not key:
                raise ValueError('empty upstream record id')
            if key in incoming:
                raise ValueError('duplicate record id within upstream document')
            row = {'source': source, **row}
            prior = json.loads(old[key]) if key in old else {}
            prior_content = {k: v for k, v in prior.items() if k not in ('first_seen_at', 'last_changed_at')}
            unchanged = prior_content == row
            row['first_seen_at'] = prior.get('first_seen_at', time.time())
            row['last_changed_at'] = prior['last_changed_at'] if unchanged else time.time()
            incoming[key] = canonical(row)
        for key, payload in incoming.items():
            owner = self.db.execute('SELECT unit FROM docs WHERE source=? AND id=?', (source, key)).fetchone()
            if owner and owner[0] != unit:
                raise ValueError('upstream id belongs to multiple documents')
            if old.get(key) != payload:
                self.db.execute('INSERT OR REPLACE INTO docs VALUES (?,?,?,?)', (source, key, unit, payload))
                self.db.execute('INSERT OR REPLACE INTO changes VALUES (?,?,?,?)', (source, key, 'upsert', payload))
        for key in old.keys() - incoming.keys():
            self.db.execute('DELETE FROM docs WHERE source=? AND id=?', (source, key))
            self.db.execute('INSERT OR REPLACE INTO changes VALUES (?,?,?,NULL)', (source, key, 'delete'))
        self.db.execute('INSERT OR REPLACE INTO units VALUES (?,?,?,?)', (source, unit, version, time.time()))
        if blob is None:
            self.db.execute('DELETE FROM blobs WHERE source=? AND path=?', (source, unit))
        else:
            self.db.execute('INSERT OR REPLACE INTO blobs VALUES (?,?,?)', (source, unit, blob))

    def remove(self, source, unit):
        self.replace(source, unit, '', [])
        self.db.execute('DELETE FROM units WHERE source=? AND name=?', (source, unit))

    def transaction(self, source, action):
        """A failed feed cannot publish half a document or advance its checkpoint."""
        self.db.execute('SAVEPOINT feed')
        previous = self.state(source)
        try:
            result = action(previous.copy())
            success = previous.get('last_success') if result.get('status') == 'skipped' else time.time()
            self.set_state(source, {**result, 'last_success': success, 'error': None})
            self.db.execute('RELEASE feed')
            status = self.state(source)
        except Exception as error:
            self.db.execute('ROLLBACK TO feed')
            self.db.execute('RELEASE feed')
            # Exception bodies from providers can contain secrets; only known local
            # messages or exception classes are retained.
            message = str(error) if isinstance(error, RuntimeError) and str(error).startswith('upstream ') else type(error).__name__
            status = {**previous, 'status': 'failed', 'error': message, 'last_attempt': time.time()}
            self.set_state(source, status)
        self.db.commit()
        return status

    def signature(self):
        """State progress and source revisions matter; polling timestamps do not."""
        h = hashlib.sha256()
        for query in [
            'SELECT source,id,payload FROM docs ORDER BY source,id',
            'SELECT source,name,version FROM units ORDER BY source,name',
        ]:
            for row in self.db.execute(query):
                h.update(canonical(row).encode())
        for source, payload in self.db.execute('SELECT source,payload FROM state ORDER BY source'):
            state = json.loads(payload)
            for key in ('last_success', 'last_attempt'):
                state.pop(key, None)
            h.update(canonical([source, state]).encode())
        return h.hexdigest()


class GitTree:
    """Read tracked upstream files without running anything from the upstream tree."""

    def __init__(self, source, cache):
        self.path = Path(cache) / source['id']
        url = source['url']
        ref = source.get('ref')
        if source.get('latest_release'):
            ref = github_json(f"repos/{source['github']}/releases/latest")['tag_name']
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not (self.path / '.git').exists():
            # Blob filtering plus sparse checkout avoids fetching Exploit-DB code.
            run(['git', 'clone', '--filter=blob:none', '--no-checkout', '--depth=1', url, str(self.path)])
        run(['git', '-C', str(self.path), 'fetch', '--depth=1', 'origin', ref or 'HEAD'])
        if source.get('sparse') or source.get('parser') == 'nvd':
            patterns = source.get('sparse', []) + ['LICENSE*', 'COPYING*', 'NOTICE*']
            if source.get('parser') == 'nvd':
                import datetime
                patterns = [f'/CVE-{year}/' for year in range(source.get('min_year', 2018), datetime.date.today().year + 1)] + ['/LICENSES/']
            run(['git', '-C', str(self.path), 'sparse-checkout', 'set', '--no-cone', *patterns])
        run(['git', '-C', str(self.path), '-c', 'advice.detachedHead=false', 'checkout', '--force', '--detach', 'FETCH_HEAD'])
        self.revision = run(['git', '-C', str(self.path), 'rev-parse', 'HEAD']).decode().strip()
        self.ref = ref

    def files(self):
        out = run(['git', '-C', str(self.path), 'ls-tree', '-rz', 'HEAD'])
        for entry in out.split(b'\0'):
            if not entry:
                continue
            meta, path = entry.split(b'\t', 1)
            mode, kind, sha = meta.decode().split()
            # No symlinks, submodules or executables in a data resource.
            if kind == 'blob' and mode == '100644':
                yield path.decode(), sha

    def read(self, path):
        candidate = self.path / path
        if candidate.is_symlink() or not candidate.resolve().is_relative_to(self.path.resolve()):
            raise ValueError('unsafe upstream path')
        if not candidate.is_file():
            raise ValueError('selected file missing from sparse checkout')
        if candidate.stat().st_size > 64 * 1024 * 1024:
            raise ValueError('upstream file exceeds 64 MiB limit')
        return candidate.read_bytes()


def restore(destination, repository):
    """Only an absent release means bootstrap; network/auth/corruption aborts restore."""
    pages = json.loads(run(['gh', 'api', f'repos/{repository}/releases?per_page=100', '--paginate', '--slurp']))
    releases = [release for page in pages for release in page]
    releases = [r for r in releases if not r['draft'] and not r['prerelease'] and r['tag_name'].startswith('data-')]
    if not releases:
        return None
    release = max(releases, key=lambda r: r['published_at'])
    dest = Path(destination)
    dest.mkdir(parents=True, exist_ok=True)
    tag = release['tag_name']
    run(['gh', 'release', 'download', tag, '--repo', repository, '--dir', str(dest), '--clobber',
         '--pattern', 'manifest.json', '--pattern', 'state.sqlite.gz'])
    manifest = json.loads((dest / 'manifest.json').read_text())
    if manifest['schema_version'] != SCHEMA or manifest['repository'] != repository:
        raise ValueError('snapshot repository/schema mismatch')
    if manifest['version'] != tag:
        raise ValueError('snapshot version mismatch')
    info = manifest['assets']['state.sqlite.gz']
    data = dest / 'state.sqlite.gz'
    if data.stat().st_size != info['size'] or file_digest(data) != info['sha256']:
        raise ValueError('snapshot checksum mismatch')
    with gzip.open(data, 'rb') as src, (dest / 'state.sqlite').open('wb') as dst:
        shutil.copyfileobj(src, dst)
    db = sqlite3.connect(dest / 'state.sqlite')
    try:
        if db.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
            raise ValueError('snapshot database integrity failure')
    finally:
        db.close()
    return tag


def file_digest(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for part in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(part)
    return h.hexdigest()


def package(store, output, repository, version, base, config):
    """Publishable full snapshot, metadata delta, resource archive and checksum manifest."""
    out = Path(output)
    out.mkdir(parents=True, exist_ok=True)
    for name in ('state.sqlite', 'state.sqlite.gz', 'records.jsonl.gz', 'delta.jsonl.gz',
                 'resources.tar.gz', 'indexes.json.gz', 'manifest.json'):
        (out / name).unlink(missing_ok=True)
    db_path = out / 'state.sqlite'
    dest = sqlite3.connect(db_path)
    store.db.backup(dest)
    dest.close()
    with db_path.open('rb') as src, gzip.open(out / 'state.sqlite.gz', 'wb', compresslevel=6) as dst:
        shutil.copyfileobj(src, dst)
    db_path.unlink()
    with gzip.open(out / 'records.jsonl.gz', 'wt', encoding='utf-8') as stream:
        for (payload,) in store.db.execute('SELECT payload FROM docs ORDER BY source,id'):
            stream.write(payload + '\n')
    with gzip.open(out / 'delta.jsonl.gz', 'wt', encoding='utf-8') as stream:
        for source, key, op, payload in store.db.execute('SELECT * FROM changes ORDER BY source,id'):
            stream.write(canonical({'source': source, 'id': key, 'operation': op,
                                    'record': json.loads(payload) if payload else None}) + '\n')
    if store.db.execute('SELECT count(*) FROM blobs').fetchone()[0]:
        with tarfile.open(out / 'resources.tar.gz', 'w:gz') as archive:
            for source, path, data in store.db.execute('SELECT * FROM blobs ORDER BY source,path'):
                item = tarfile.TarInfo(f'{source}/{path}')
                item.size = len(data)
                item.mode = 0o644
                item.mtime = 0
                archive.addfile(item, io.BytesIO(data))
    indexes = {'cve_to_resources': {}, 'template_ids': {}, 'components': {}}
    for (payload,) in store.db.execute('SELECT payload FROM docs ORDER BY source,id'):
        row = json.loads(payload)
        if row.get('kind') not in ('template', 'fingerprint', 'coverage', 'coverage-gap'):
            continue
        target = {'source': row['source'], 'id': row['id'], 'kind': row['kind'], 'path': row.get('path')}
        for cve in row.get('cves', []):
            indexes['cve_to_resources'].setdefault(cve, []).append(target)
        if row.get('template_id'):
            indexes['template_ids'].setdefault(row['template_id'], []).append(target)
        for component in row.get('components', []):
            indexes['components'].setdefault(component, []).append(target)
    if any(indexes.values()):
        with gzip.open(out / 'indexes.json.gz', 'wt', encoding='utf-8') as stream:
            stream.write(canonical(indexes))
    assets = {}
    for path in sorted(out.iterdir()):
        if path.name == 'manifest.json':
            continue
        if path.stat().st_size >= 1_900_000_000:
            raise ValueError('release asset exceeds configured size limit; shard before publishing')
        assets[path.name] = {'size': path.stat().st_size, 'sha256': file_digest(path)}
    states = {source: json.loads(payload) for source, payload in store.db.execute('SELECT * FROM state')}
    manifest = {'schema_version': SCHEMA, 'repository': repository, 'version': version,
                'base_version': base, 'created_at': time.time(), 'content_signature': store.signature(),
                'record_count': store.db.execute('SELECT count(*) FROM docs').fetchone()[0],
                'sources': states, 'source_config': config['sources'], 'assets': assets,
                'delta_scope': 'metadata; resource consumers use the complete resource archive',
                'consumer_policy': 'data supply only; does not grant runtime activation'}
    (out / 'manifest.json').write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + '\n')
    return manifest
