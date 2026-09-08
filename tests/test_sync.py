"""Regression coverage for release continuity and source normalization."""
import gzip
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from runtime import Store, canonical, file_digest, package, restore
from sources import (git_feed, osv_feed, parse_exploitdb, parse_github_poc, parse_kev,
                     parse_missing, parse_nvd, parse_resource, vulncheck_feed, vulners_poc_feed)


class PersistenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.store = Store(self.root / 'state.sqlite')
        self.addCleanup(self.store.db.close)

    def test_failed_feed_rolls_back_rows_blobs_and_cursor(self):
        def first(state):
            self.store.replace('a', 'file', 'one', [{'id': 'old'}], b'old')
            return {'status': 'partial', 'cursor': 'one'}
        self.store.transaction('a', first)
        def broken(state):
            self.store.replace('a', 'file', 'two', [{'id': 'new'}], b'new')
            self.store.set_state('a', {'cursor': 'two'})
            raise ValueError('private upstream payload must not leak')
        result = self.store.transaction('a', broken)
        self.assertEqual(result['cursor'], 'one')
        self.assertEqual(result['error'], 'ValueError')
        self.assertEqual(self.store.db.execute('SELECT id FROM docs').fetchone()[0], 'old')
        self.assertEqual(self.store.db.execute('SELECT data FROM blobs').fetchone()[0], b'old')
        self.store.transaction('b', lambda state: {'status': 'ok'})
        self.assertEqual(self.store.state('b')['status'], 'ok')

    def test_unchanged_poll_does_not_generate_delta_or_new_content_signature(self):
        self.store.replace('a', 'file', 'one', [{'id': 'old'}])
        self.store.set_state('a', {'status': 'ok', 'last_success': 1})
        signature = self.store.signature()
        self.store.db.execute('DELETE FROM changes')
        self.store.replace('a', 'file', 'one', [{'id': 'old'}])
        self.store.set_state('a', {'status': 'ok', 'last_success': 2})
        self.assertEqual(signature, self.store.signature())
        self.assertEqual(self.store.db.execute('SELECT count(*) FROM changes').fetchone()[0], 0)

    def test_snapshot_restores_and_delta_reconstructs_consumer_state(self):
        self.store.replace('a', 'file', 'one', [{'id': 'old'}, {'id': 'changed', 'value': 1}])
        self.store.db.commit()
        base = {key: json.loads(payload) for key, payload in self.store.db.execute('SELECT id,payload FROM docs')}
        self.store.db.execute('DELETE FROM changes')
        self.store.replace('a', 'file', 'two', [{'id': 'changed', 'value': 2}, {'id': 'new'}])
        self.store.set_state('a', {'status': 'ok', 'cursor': 'two'})
        self.store.db.commit()
        out = self.root / 'dist'
        manifest = package(self.store, out, 'org/repo', 'data-next', 'data-before', {'sources': []})
        for name, info in manifest['assets'].items():
            self.assertEqual(file_digest(out / name), info['sha256'])
        with gzip.open(out / 'delta.jsonl.gz', 'rt') as stream:
            for line in stream:
                change = json.loads(line)
                if change['operation'] == 'delete':
                    base.pop(change['id'], None)
                else:
                    base[change['id']] = change['record']
        with gzip.open(out / 'records.jsonl.gz', 'rt') as stream:
            records = {row['id']: row for row in map(json.loads, stream)}
        self.assertEqual(base, records)
        def gh(args, **kwargs):
            if args[1] == 'api':
                return json.dumps([[{'tag_name': 'data-next', 'published_at': '2026-01-01',
                                     'draft': False, 'prerelease': False}]]).encode()
            return b''
        with patch('runtime.run', side_effect=gh):
            self.assertEqual(restore(out, 'org/repo'), 'data-next')
        restored = Store(out / 'state.sqlite')
        self.addCleanup(restored.db.close)
        self.assertEqual(restored.state('a')['cursor'], 'two')
        (out / 'state.sqlite.gz').write_bytes(b'corrupt')
        with patch('runtime.run', side_effect=gh), self.assertRaises(ValueError):
            restore(out, 'org/repo')

    def test_restore_network_failure_never_becomes_empty_bootstrap(self):
        with patch('runtime.run', side_effect=subprocess.CalledProcessError(1, ['gh'])):
            with self.assertRaises(subprocess.CalledProcessError):
                restore(self.root, 'org/repo')

    def test_git_backfill_resumes_and_propagates_removals(self):
        upstream = self.root / 'upstream'
        upstream.mkdir()
        def git(*args):
            subprocess.run(['git', '-C', str(upstream), *args], check=True, capture_output=True)
        git('init', '-b', 'main')
        git('config', 'user.email', 'test@example.invalid')
        git('config', 'user.name', 'Test')
        (upstream / 'CVE-2026').mkdir()
        for number in [1000, 2000]:
            (upstream / 'CVE-2026' / f'CVE-2026-{number}.json').write_text(canonical({'id': f'CVE-2026-{number}', 'descriptions': []}))
        git('add', '.')
        git('commit', '-m', 'fixture')
        source = {'id': 'nvd', 'type': 'git', 'parser': 'nvd', 'url': upstream.as_uri()}
        def collect(previous):
            return git_feed(self.store, source, previous, self.root / 'cache', 1)
        self.assertEqual(self.store.transaction('nvd', collect)['remaining_files'], 1)
        self.assertEqual(self.store.transaction('nvd', collect)['status'], 'ok')
        (upstream / 'CVE-2026' / 'CVE-2026-1000.json').unlink()
        git('add', '.')
        git('commit', '-m', 'remove')
        self.store.transaction('nvd', collect)
        self.assertEqual(self.store.db.execute('SELECT id FROM docs').fetchall(), [('CVE-2026-2000',)])

    def test_osv_continues_mid_page_without_losing_alias_records(self):
        listing = b'''<ListBucketResult xmlns="http://doc.s3.amazonaws.com/2006-03-01">
          <Contents><Key>npm/A.json</Key><ETag>one</ETag></Contents>
          <Contents><Key>npm/B.json</Key><ETag>two</ETag></Contents></ListBucketResult>'''
        source = {'id': 'osv', 'url': 'https://example.invalid', 'ecosystems': ['npm']}
        def doc(url):
            return {'id': url.split('/')[-1][:-5], 'aliases': ['CVE-2026-1234']}
        def collect(state):
            return osv_feed(self.store, source, state, '', 1)
        with patch('sources.request', return_value=listing), patch('sources.get_json', side_effect=doc):
            result = self.store.transaction('osv', collect)
            self.assertEqual(result['offset'], 1)
            result = self.store.transaction('osv', collect)
        self.assertEqual(result['completed_loops'], 1)
        self.assertEqual(self.store.db.execute('SELECT count(*) FROM docs').fetchone()[0], 2)

    def test_api_window_and_cursor_survive_budget_boundary(self):
        source = {'id': 'vulncheck', 'secret': 'TEST_KEY', 'url': 'https://example.invalid'}
        responses = [{'data': [{'id': 'CVE-2026-1000', 'exploits': [{'url': 'https://example.invalid/poc'}]}],
                      '_meta': {'next_cursor': 'next'}}, {'data': [], '_meta': {}}]
        with patch.dict('os.environ', {'TEST_KEY': 'test'}), patch('sources.get_json', side_effect=responses) as fetch:
            first = vulncheck_feed(self.store, source, {}, '', 100)
            second = vulncheck_feed(self.store, source, first, '', 100)
        self.assertEqual(first['cursor'], 'next')
        self.assertEqual(second['status'], 'ok')
        self.assertIn('cursor=next', fetch.call_args_list[1].args[0])
        self.assertEqual(second['last_complete'], first['window']['end'])

    def test_missing_api_secret_is_explicit_skip(self):
        source = {'id': 'vulners', 'secret': 'ABSENT_TEST_KEY'}
        result = vulners_poc_feed(self.store, source, {}, '', 100)
        self.assertEqual(result['status'], 'skipped')


class ParserTests(unittest.TestCase):
    def test_kev_keeps_unmatched_cve_as_standalone_record(self):
        rows, _ = parse_kev('', b'{"vulnerabilities":[{"cveID":"CVE-2026-1000"}]}')
        self.assertTrue(rows[0]['known_exploited'])

    def test_nvd_retains_rejection_and_raw_affected_data(self):
        raw = {'id': 'CVE-2026-1000', 'vulnStatus': 'Rejected', 'affected': [{'vendor': 'example'}]}
        rows, _ = parse_nvd('', canonical(raw).encode())
        self.assertTrue(rows[0]['withdrawn'])
        self.assertEqual(rows[0]['raw']['affected'], raw['affected'])

    def test_exploitdb_multiple_cves_and_non_cve_aliases(self):
        data = b'id,description,codes\n1,"example, title",CVE-2026-1000;CVE-2026-2000;BID-3\n'
        rows, _ = parse_exploitdb('', data)
        self.assertEqual(len(rows), 2)
        self.assertIn('BID-3', rows[0]['aliases'])

    def test_github_index_deduplicates_repository_ids(self):
        raw = [{'id': 1, 'html_url': 'https://github.com/example/poc'}] * 2
        rows, blob = parse_github_poc('2026/CVE-2026-1000.json', canonical(raw).encode())
        self.assertEqual(len(rows), 1)
        self.assertIsNone(blob)

    def test_exploitdb_duplicate_rows_preserve_variants_under_one_stable_id(self):
        data = b'id,description,codes\n1,first,CVE-2026-1000\n1,second,CVE-2026-1000;BID-2\n'
        rows, _ = parse_exploitdb('', data)
        self.assertEqual(len(rows), 1)
        self.assertEqual(len(rows[0]['raw_variants']), 2)
        self.assertIn('BID-2', rows[0]['aliases'])

    def test_templates_are_structurally_checked_without_execution(self):
        rows, blob = parse_resource('a.yaml', b'id: sample\ninfo:\n  name: Sample\nhttp: []\n')
        self.assertEqual(rows[0]['kind'], 'template')
        self.assertFalse(rows[0]['runtime_validated'])
        self.assertIsNotNone(blob)
        rows, blob = parse_resource('b.yaml', b'broken: [')
        self.assertEqual(rows[0]['validation'], 'invalid-yaml')
        self.assertIsNone(blob)

    def test_missing_cve_is_coverage_gap_not_template(self):
        rows, blob = parse_missing('', b'[{"cve":"CVE-2026-1000","description":"example"}]')
        self.assertEqual(rows[0]['kind'], 'coverage-gap')
        self.assertIsNone(blob)


class ConfigurationTests(unittest.TestCase):
    def test_sources_are_unique_bounded_and_have_collectors(self):
        from sources import COLLECTORS, PARSERS
        config = json.loads((Path(__file__).resolve().parents[1] / 'sources.json').read_text())
        ids = [source['id'] for source in config['sources']]
        self.assertEqual(len(ids), len(set(ids)))
        for source in config['sources']:
            self.assertIn(source['type'], COLLECTORS)
            self.assertGreater(source['budget'], 0)
            if source['type'] == 'git':
                self.assertIn(source['parser'], PARSERS)


if __name__ == '__main__':
    unittest.main()
