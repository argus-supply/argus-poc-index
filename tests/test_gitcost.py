"""Actual bare-Git fixtures for bounded all-branch compressed object accounting."""
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from sync.gitcost import GitCostUnavailable, _Git, measure_increment


class GitCostTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='argus-git-cost-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.repo = self.root / 'repo.git'
        self.repo.mkdir()
        self.env = dict(os.environ, GIT_AUTHOR_NAME='Fixture', GIT_COMMITTER_NAME='Fixture',
            GIT_AUTHOR_EMAIL='fixture@example.invalid', GIT_COMMITTER_EMAIL='fixture@example.invalid',
            GIT_AUTHOR_DATE='2026-09-09T00:00:00Z', GIT_COMMITTER_DATE='2026-09-09T00:00:00Z')
        self.git('init', '--bare', '-q')

    def git(self, *args, data=None):
        return subprocess.run(['git', '-C', str(self.repo), *args], input=data,
            capture_output=True, check=True, env=self.env, timeout=10).stdout

    def commit(self, files, parent=None, message='fixture'):
        directory = {}
        for path, data in sorted(files.items()):
            parts = path.split('/')
            current = directory
            for name in parts[:-1]:
                current = current.setdefault(name, {})
            current[parts[-1]] = self.git('hash-object', '-w', '--stdin', data=data).decode().strip()

        def tree(entries):
            lines = []
            for name, value in sorted(entries.items()):
                kind, mode, oid = ('tree', '040000', tree(value)) if isinstance(value, dict) else ('blob', '100644', value)
                lines.append(f'{mode} {kind} {oid}\t{name}\n')
            return self.git('mktree', data=''.join(lines).encode()).decode().strip()

        root_tree = tree(directory)
        arguments = ['commit-tree', root_tree]
        for oid in ([parent] if isinstance(parent, str) else parent or []):
            arguments.extend(['-p', oid])
        oid = self.git(*arguments, data=(message + '\n').encode()).decode().strip()
        return oid, root_tree

    def measure(self, candidate, baseline, **limits):
        return measure_increment(self.repo, candidate, baseline, baseline_complete=True, **limits)

    def test_first_commit_counts_commit_recursive_trees_and_deduplicated_blobs(self):
        candidate, _ = self.commit({'one.json': b'identical\n', 'nested/two.json': b'identical\n'})
        report = self.measure(candidate, {})
        self.assertEqual(report['object_counts'], {'commit': 1, 'tree': 2, 'blob': 1})
        self.assertEqual(report['object_count'], 4)
        self.assertEqual(report['baseline_object_count'], 0)
        self.assertGreater(report['actual_pack_bytes'], 32)
        self.assertEqual(report['actual_pack_bytes'], report['compressed_object_upper_bound_bytes'])
        self.assertTrue(report['git_version'].startswith('git version '))
        build = self.git('version', '--build-options').decode()
        if 'zlib:' in build:
            self.assertIn('zlib: ' + report['git_zlib_version'], build)
        self.assertTrue(any('GitHub physical storage' in caveat for caveat in report['caveats']))

    def test_noop_tip_is_zero_even_with_missing_older_history(self):
        old, _ = self.commit({'old': b'old'})
        current, _ = self.commit({'new': b'new'}, old)
        (self.repo / 'objects' / old[:2] / old[2:]).unlink()
        report = self.measure(current, {'refs/heads/data': current})
        self.assertEqual(report['actual_pack_bytes'], 0)
        self.assertEqual(report['raw_object_bytes'], 0)
        self.assertEqual(report['object_count'], 0)
        self.assertIsNone(report['pack_sha256'])

    def test_same_tree_new_commit_counts_only_commit(self):
        baseline, _ = self.commit({'unchanged': b'large repeated data\n' * 1000})
        candidate, _ = self.commit({'unchanged': b'large repeated data\n' * 1000}, baseline, 'new commit')
        report = self.measure(candidate, {'refs/heads/data': baseline})
        self.assertEqual(report['object_counts'], {'commit': 1, 'tree': 0, 'blob': 0})
        self.assertEqual(report['raw_object_bytes'], int(self.git('cat-file', '-s', candidate)))

    def test_all_branch_tips_deduplicate_blob_and_tree_objects(self):
        data, _ = self.commit({'file': b'old'}, message='data')
        main, _ = self.commit({'file': b'reused from main'}, message='main')
        control, _ = self.commit({'ledger.json': b'{}'}, message='control')
        candidate, _ = self.commit({'file': b'reused from main'}, data, 'update')
        data_only = self.measure(candidate, {'refs/heads/data': data})
        all_branches = self.measure(candidate, {'refs/heads/main': main,
            'refs/heads/data': data, 'refs/heads/control': control})
        self.assertEqual(data_only['object_counts'], {'commit': 1, 'tree': 1, 'blob': 1})
        self.assertEqual(all_branches['object_counts'], {'commit': 1, 'tree': 0, 'blob': 0})
        self.assertLess(all_branches['actual_pack_bytes'], data_only['actual_pack_bytes'])
        self.assertEqual(all_branches['baseline_tip_count'], 3)

    def test_duplicate_branch_tips_do_not_charge_duplicate_objects(self):
        baseline, _ = self.commit({'one': b'one'})
        candidate, _ = self.commit({'one': b'two'}, baseline)
        first = self.measure(candidate, {'refs/heads/data': baseline})
        second = self.measure(candidate, {'refs/heads/data': baseline, 'refs/heads/main': baseline})
        self.assertEqual(first['baseline_object_count'], second['baseline_object_count'])
        self.assertEqual(first['actual_pack_bytes'], second['actual_pack_bytes'])
        self.assertEqual(first['pack_sha256'], second['pack_sha256'])

    def test_pack_is_valid_matches_actual_bytes_and_contains_no_deltas(self):
        parent, _ = self.commit({'file': b'before'})
        candidate, tree = self.commit({'file': b'after\n' * 1000}, parent)
        blob = self.git('rev-parse', candidate + ':file').decode().strip()
        report = self.measure(candidate, {'refs/heads/data': parent})
        pack = self.git('pack-objects', '--stdout', '--compression=6', '--window=0', '--depth=0',
            '--threads=1', '--no-reuse-object', '--no-reuse-delta',
            data=('\n'.join(sorted([candidate, tree, blob])) + '\n').encode())
        self.assertEqual(len(pack), report['actual_pack_bytes'])
        self.assertEqual(hashlib.sha256(pack).hexdigest(), report['pack_sha256'])
        pack_path = self.root / 'measured.pack'
        pack_path.write_bytes(pack)
        self.git('index-pack', '--strict', str(pack_path))
        verified = self.git('verify-pack', '-v', str(pack_path.with_suffix('.idx'))).decode().splitlines()
        objects = [line.split() for line in verified if line.split()[0] in (candidate, tree, blob)]
        self.assertEqual(len(objects), 3)
        self.assertTrue(all(len(fields) == 5 for fields in objects), verified)

    def test_measurement_survives_repacking_and_conflicting_pack_configuration(self):
        parent, _ = self.commit({'file': b'old\n' * 1000})
        candidate, _ = self.commit({'file': b'new\n' * 1000}, parent)
        baseline = {'refs/heads/data': parent}
        first = self.measure(candidate, baseline)
        self.git('update-ref', 'refs/heads/local-candidate', candidate)
        self.git('-c', 'pack.compression=1', 'repack', '-ad')
        for key, value in (('pack.compression', '0'), ('pack.threads', '8'), ('pack.window', '250')):
            self.git('config', key, value)
        second = self.measure(candidate, baseline)
        self.assertEqual(first['actual_pack_bytes'], second['actual_pack_bytes'])
        self.assertEqual(first['pack_sha256'], second['pack_sha256'])
        self.assertEqual(first['pack_parameters'], second['pack_parameters'])

    def test_unobserved_historical_duplicates_remain_a_conservative_upper_bound(self):
        old, old_tree = self.commit({'removed': b'historical duplicate'})
        parent, _ = self.commit({'present': b'present'}, old)
        candidate, _ = self.commit({'present': b'present', 'restored': b'historical duplicate'}, parent)
        first = self.measure(candidate, {'refs/heads/data': parent})
        self.assertEqual(first['object_counts']['blob'], 1)
        for oid in (old, old_tree):
            (self.repo / 'objects' / oid[:2] / oid[2:]).unlink()
        (self.repo / 'shallow').write_text(parent + '\n')
        second = self.measure(candidate, {'refs/heads/data': parent})
        self.assertEqual(first['actual_pack_bytes'], second['actual_pack_bytes'])
        self.assertEqual(first['pack_sha256'], second['pack_sha256'])

    def test_unknown_parent_rejected_but_new_root_branch_allowed(self):
        parent, _ = self.commit({'file': b'old'})
        candidate, _ = self.commit({'file': b'new'}, parent)
        with self.assertRaisesRegex(GitCostUnavailable, 'parent is absent'):
            self.measure(candidate, {})
        new_branch, _ = self.commit({'new': b'branch'}, message='orphan')
        report = self.measure(new_branch, {'refs/heads/main': parent})
        self.assertEqual(report['object_counts']['commit'], 1)

    def test_incomplete_or_invalid_baseline_fails_explicitly(self):
        candidate, _ = self.commit({'file': b'new'})
        for baseline, complete in (({}, False), (None, True), ({'main': candidate}, True),
                ({'refs/heads/data': 'b' * 40}, True)):
            with self.subTest(baseline=baseline, complete=complete), self.assertRaises(GitCostUnavailable):
                measure_increment(self.repo, candidate, baseline, baseline_complete=complete)

    def test_missing_baseline_blob_rejected_even_when_candidate_is_available(self):
        parent, _ = self.commit({'old': b'old'})
        blob = self.git('rev-parse', parent + ':old').decode().strip()
        candidate, _ = self.commit({'new': b'new'}, parent)
        (self.repo / 'objects' / blob[:2] / blob[2:]).unlink()
        with self.assertRaisesRegex(GitCostUnavailable, 'Missing or invalid local baseline object'):
            self.measure(candidate, {'refs/heads/data': parent})

    def test_submodule_snapshot_rejected_instead_of_ignoring_commit_objects(self):
        commit, _ = self.commit({'file': b'file'})
        tree = self.git('mktree', data=f'160000 commit {commit}\tsubmodule\n'.encode()).decode().strip()
        candidate = self.git('commit-tree', tree, data=b'submodule\n').decode().strip()
        with self.assertRaisesRegex(GitCostUnavailable, 'submodule'):
            self.measure(candidate, {})

    def test_object_raw_metadata_and_pack_limits_fail_closed(self):
        candidate, _ = self.commit({'file': b'payload\n' * 1000})
        for limits in ({'max_objects': 1}, {'max_raw_bytes': 1}, {'max_object_bytes': 1},
                       {'metadata_limit': 1}, {'max_pack_bytes': 1}):
            with self.subTest(limits=limits), self.assertRaises(GitCostUnavailable):
                self.measure(candidate, {}, **limits)

    def test_timeout_terminates_process_without_echoing_environment(self):
        original = subprocess.Popen

        def hung(*args, **kwargs):
            return original([sys.executable, '-c', 'import time; time.sleep(60)'], **kwargs)

        with patch('sync.gitcost.subprocess.Popen', side_effect=hung):
            with self.assertRaisesRegex(GitCostUnavailable, 'timed out'):
                _Git(self.repo, 0.05).run('version')

    def test_missing_linked_zlib_version_is_explicit_not_inferred_from_python(self):
        candidate, _ = self.commit({'file': b'new'})
        original = _Git.run

        def old_git(instance, *args, **kwargs):
            if args == ('version', '--build-options'):
                return b'git version 2.fixture\ncpu: fixture\n'
            return original(instance, *args, **kwargs)

        with patch.object(_Git, 'run', new=old_git):
            report = self.measure(candidate, {})
        self.assertIsNone(report['git_zlib_version'])
        self.assertIn('This Git build does not expose its linked zlib version.', report['caveats'])


if __name__ == '__main__':
    unittest.main()
