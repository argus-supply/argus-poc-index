"""Bounded, reproducible Git object costs from locally observed branch snapshots.

The resulting standalone pack is measured, not estimated from changed file sizes.
It conservatively omits reuse of historical objects absent from the observed tips;
it does not measure GitHub's physical storage, indexes, or transfer protocol bytes.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import subprocess
import tempfile
import threading


PACK_PARAMETERS = {'format_version': 2, 'compression': 6, 'window': 0, 'depth': 0,
    'threads': 1, 'reuse_object': False, 'reuse_delta': False, 'thin': False,
    'object_order': 'lexicographic_oid', 'policy_version': 'git-object-cost-v1'}


class GitCostUnavailable(RuntimeError):
    """Cost cannot be established within the complete, bounded local baseline."""


class _Git:
    def __init__(self, path, timeout):
        self.path, self.timeout = Path(path), timeout
        self.env = dict(os.environ, GIT_NO_LAZY_FETCH='1', GIT_TERMINAL_PROMPT='0',
            GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull, GIT_OPTIONAL_LOCKS='0')

    def run(self, *args, data=None, limit=1048576, digest_only=False):
        """Never fetch; bound stdout in memory/disk and terminate overdue Git work."""
        command = ['git', '--no-replace-objects', '-C', str(self.path),
                   '-c', 'protocol.allow=never', *args]
        output, size, digest = [], 0, hashlib.sha256()
        try:
            with tempfile.TemporaryFile() as input_file:
                if data:
                    input_file.write(data)
                input_file.seek(0)
                with subprocess.Popen(command, stdin=input_file, stdout=subprocess.PIPE,
                        stderr=subprocess.DEVNULL, env=self.env) as process:
                    expired = threading.Event()

                    def terminate():
                        expired.set()
                        process.kill()

                    timer = threading.Timer(self.timeout, terminate)
                    timer.daemon = True
                    timer.start()
                    try:
                        while chunk := process.stdout.read(65536):
                            size += len(chunk)
                            if size > limit:
                                process.kill()
                                raise GitCostUnavailable('Git measurement output exceeds limit')
                            digest.update(chunk)
                            if not digest_only:
                                output.append(chunk)
                        code = process.wait()
                        if expired.is_set():
                            raise GitCostUnavailable('Git measurement timed out')
                        if code:
                            raise GitCostUnavailable('Git measurement failed or local objects are missing')
                    finally:
                        timer.cancel()
                        if process.poll() is None:
                            process.kill()
                            process.wait()
        except (OSError, subprocess.SubprocessError) as error:
            raise GitCostUnavailable('Git measurement process unavailable') from error
        return (size, digest.hexdigest()) if digest_only else b''.join(output)


def _snapshot(git, oid, oid_pattern, max_objects, metadata_limit):
    commit = git.run('cat-file', 'commit', oid)
    headers = commit.split(b'\n\n', 1)[0].splitlines()
    trees = [line[5:].decode('ascii') for line in headers if line.startswith(b'tree ')]
    parents = [line[7:].decode('ascii') for line in headers if line.startswith(b'parent ')]
    if len(trees) != 1 or any(not oid_pattern.fullmatch(value) for value in [*trees, *parents]):
        raise GitCostUnavailable('Invalid local commit metadata')
    objects = {oid: 'commit', trees[0]: 'tree'}
    entries = git.run('ls-tree', '-rzt', '--full-tree', oid, limit=metadata_limit)
    for entry in entries.split(b'\0'):
        if not entry:
            continue
        try:
            metadata, _ = entry.split(b'\t', 1)
            _, kind, raw_oid = metadata.decode('ascii').split()
        except (UnicodeError, ValueError) as error:
            raise GitCostUnavailable('Invalid local tree metadata') from error
        if kind not in ('tree', 'blob') or not oid_pattern.fullmatch(raw_oid):
            raise GitCostUnavailable('Unsupported tree object or submodule in baseline')
        objects[raw_oid] = kind
        if len(objects) > max_objects:
            raise GitCostUnavailable('Git measurement object count exceeds limit')
    return objects, parents


def measure_increment(path, candidate, observed_tips, *, baseline_complete,
        max_objects=100000, max_raw_bytes=134217728, max_object_bytes=33554432,
        max_pack_bytes=67108864, metadata_limit=16777216, timeout_seconds=90):
    """Measure a candidate against a complete, immutable all-branch tip inventory.

    ``observed_tips`` maps all observed ``refs/heads/*`` names to immutable OIDs.
    A known empty remote requires ``{}`` and explicit ``baseline_complete=True``.
    All snapshot objects must already be present locally; no ancestry is fetched.
    Candidate parents must be observed tips, so an unmeasured intermediate commit
    cannot disappear from the cost. A candidate that is already a tip is a no-op.
    Bounds cover the union of baseline and candidate objects, not just new bytes.
    """
    if baseline_complete is not True or not isinstance(observed_tips, dict):
        raise GitCostUnavailable('Complete observed all-branch baseline is required')
    if len(observed_tips) > 1024:
        raise GitCostUnavailable('Observed branch inventory exceeds limit')
    limits = (max_objects, max_raw_bytes, max_object_bytes, max_pack_bytes, metadata_limit, timeout_seconds)
    if any(type(value) is not int or value <= 0 for value in limits):
        raise ValueError('Git measurement limits must be positive integers')
    git = _Git(path, timeout_seconds)
    if git.run('rev-parse', '--is-bare-repository').strip() != b'true':
        raise GitCostUnavailable('Git measurement requires an existing bare repository')
    object_format = git.run('rev-parse', '--show-object-format').decode().strip()
    if object_format not in ('sha1', 'sha256'):
        raise GitCostUnavailable('Unsupported Git object format')
    oid_pattern = re.compile('[0-9a-f]{' + ('40' if object_format == 'sha1' else '64') + '}')
    if not isinstance(candidate, str) or not oid_pattern.fullmatch(candidate):
        raise GitCostUnavailable('Candidate must be an immutable object ID')
    for branch, oid in observed_tips.items():
        if (not isinstance(branch, str) or not branch.startswith('refs/heads/')
                or not isinstance(oid, str) or not oid_pattern.fullmatch(oid)):
            raise GitCostUnavailable('Invalid observed branch or immutable object ID')
        git.run('check-ref-format', branch)
    baseline = {}
    tips = set(observed_tips.values())
    for oid in sorted(tips):
        objects, _ = _snapshot(git, oid, oid_pattern, max_objects, metadata_limit)
        baseline.update(objects)
        if len(baseline) > max_objects:
            raise GitCostUnavailable('Git baseline object count exceeds limit')
    proposed, parents = _snapshot(git, candidate, oid_pattern, max_objects, metadata_limit)
    if candidate not in tips and not set(parents) <= tips:
        raise GitCostUnavailable('Candidate parent is absent from observed branch tips')
    union = {**baseline, **proposed}
    if len(union) > max_objects:
        raise GitCostUnavailable('Git measurement object count exceeds limit')
    ordered = sorted(union)
    checks = git.run('cat-file', '--batch-check=%(objectname) %(objecttype) %(objectsize)',
        data=('\n'.join(ordered) + '\n').encode(), limit=metadata_limit).splitlines()
    if len(checks) != len(ordered):
        raise GitCostUnavailable('Incomplete local object inventory')
    sizes, total = {}, 0
    for expected, line in zip(ordered, checks):
        try:
            oid, kind, raw_size = line.decode('ascii').split()
            size = int(raw_size)
        except (UnicodeError, ValueError) as error:
            raise GitCostUnavailable('Missing or invalid local baseline object') from error
        if oid != expected or kind != union[expected] or not 0 <= size <= max_object_bytes:
            raise GitCostUnavailable('Invalid or oversized local baseline object')
        total += size
        if total > max_raw_bytes:
            raise GitCostUnavailable('Git measurement raw object bytes exceed limit')
        sizes[oid] = size
    added = sorted(set(proposed) - baseline.keys())
    pack_bytes, pack_sha = 0, None
    if added:
        pack_bytes, pack_sha = git.run('-c', 'pack.useBitmaps=false', 'pack-objects',
            '--stdout', '--compression=6', '--window=0', '--depth=0', '--threads=1',
            '--no-reuse-object', '--no-reuse-delta',
            data=('\n'.join(added) + '\n').encode(), limit=max_pack_bytes, digest_only=True)
    build = git.run('version', '--build-options').decode('utf-8').strip()
    zlib_versions = [line.split(':', 1)[1].strip() for line in build.splitlines() if line.startswith('zlib:')]
    return {'schema_version': '1.0', 'candidate': candidate, 'baseline_tips': dict(sorted(observed_tips.items())),
        'baseline_complete': True, 'baseline_tip_count': len(observed_tips),
        'baseline_object_count': len(baseline), 'baseline_raw_object_bytes': sum(sizes[oid] for oid in baseline),
        'actual_pack_bytes': pack_bytes, 'compressed_object_upper_bound_bytes': pack_bytes,
        'pack_sha256': pack_sha, 'object_count': len(added),
        'object_counts': {kind: sum(proposed[oid] == kind for oid in added) for kind in ('commit', 'tree', 'blob')},
        'raw_object_bytes': sum(sizes[oid] for oid in added), 'object_format': object_format,
        'git_version': build.splitlines()[0], 'git_build_options': build,
        'git_zlib_version': zlib_versions[0] if zlib_versions else None,
        'pack_parameters': dict(PACK_PARAMETERS),
        'measurement_scope': 'actual standalone non-delta pack of candidate minus all observed tip snapshot objects',
        'caveats': ['Historical objects absent from tip snapshots may be counted again; no full history was fetched.',
            'The upper bound applies to this fixed independent-object compression policy, not arbitrary server packing.',
            'This excludes GitHub physical storage, pack indexes, unreachable objects, and Git protocol transfer overhead.',
            *([] if zlib_versions else ['This Git build does not expose its linked zlib version.'])]}
