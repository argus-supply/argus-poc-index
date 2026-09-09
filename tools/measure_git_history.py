"""Read-only, bounded migration audit of fixed main/data/control cutoffs.

Fetch only explicitly named SHA snapshots with depth one, inspect each commit's
parent metadata, and replay closed linear branch chains in deterministic
topological order. No clone, unshallow, ref discovery, push or ledger mutation.
The replay is a declared reconstruction, not proof of historical ref timing.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import signal
import subprocess
import sys
import tempfile
import threading
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sync.gitcost import GitCostUnavailable, PACK_PARAMETERS, measure_increment

BRANCHES = ('main', 'data', 'control')
REPOSITORIES = ('argus-intel-data', 'argus-poc-index', 'argus-detection-resources')
SHA = re.compile(r'[0-9a-f]{40}')
CEILINGS = {'max_commits': 128, 'max_total_raw_bytes': 134217728,
    'max_total_pack_bytes': 134217728, 'max_repository_bytes': 536870912,
    'max_objects': 100000, 'max_object_bytes': 33554432,
    'max_snapshot_raw_bytes': 134217728, 'max_pack_bytes': 67108864,
    'metadata_bytes': 16777216, 'timeout_seconds': 720, 'command_seconds': 90}
DEFAULTS = {**CEILINGS, 'max_repository_bytes': 268435456, 'timeout_seconds': 600}


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


def instant(value):
    if not isinstance(value, str) or not re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z', value):
        raise ValueError('baseline completion must be an explicit UTC second')
    return dt.datetime.fromisoformat(value.replace('Z', '+00:00'))


def size_of(path):
    """Logical file bytes, including pack temporary files; no symlink traversal."""
    total = 0
    for root, directories, files in os.walk(path, followlinks=False):
        for name in [*directories, *files]:
            entry = Path(root) / name
            try:
                if entry.is_symlink():
                    raise GitCostUnavailable('Unexpected symlink in isolated measurement repository')
                if entry.is_file():
                    total += entry.stat().st_size
            except FileNotFoundError:
                # Git atomically renames its own temporary pack/index files.
                continue
    return total


class Commands:
    """One global deadline, bounded output and a private fetch allocation."""
    def __init__(self, path, limits, started):
        self.path, self.limits, self.started = Path(path), limits, started
        self.peak_bytes = self.fetches = 0
        self.env = {key: value for key, value in os.environ.items() if not key.startswith('GIT_')}
        self.env.update(GIT_TERMINAL_PROMPT='0', GIT_NO_LAZY_FETCH='1',
            GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull, GIT_OPTIONAL_LOCKS='0')

    def remaining(self):
        seconds = self.limits['timeout_seconds'] - (time.monotonic() - self.started)
        if seconds <= 0:
            raise GitCostUnavailable('History measurement total time limit exhausted')
        return seconds

    def disk(self):
        size = size_of(self.path)
        self.peak_bytes = max(size, self.peak_bytes)
        if size > self.limits['max_repository_bytes']:
            raise GitCostUnavailable('Temporary repository size limit exceeded')
        return size

    def run(self, command, *, output_limit=65536, fetch=False):
        remaining = self.remaining()
        available = self.limits['max_repository_bytes'] - self.disk()
        # Fetch is forced through index-pack (no loose-object expansion), with
        # auto maintenance/reverse indexes disabled. Allocate at most one eighth
        # of remaining space to each output file, leaving room for simultaneous
        # pack/index temporaries and bounded shallow metadata. RLIMIT_FSIZE is
        # inherited by Git's child processes; a watcher supplies a second guard.
        file_limit = (available - 65536) // 8
        if fetch and file_limit <= 0:
            raise GitCostUnavailable('Temporary repository fetch allocation exhausted')

        def set_file_limit():
            if fetch:
                resource.setrlimit(resource.RLIMIT_FSIZE, (file_limit, file_limit))

        output, count = [], 0
        reason, finished = [], threading.Event()
        timeout = min(remaining, self.limits['command_seconds']) if fetch else remaining
        deadline = time.monotonic() + timeout
        try:
            with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                    stdin=subprocess.DEVNULL, env=self.env, start_new_session=True,
                    preexec_fn=set_file_limit if fetch else None) as process:
                def stop(message):
                    reason.append(message)
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass

                def watch():
                    while not finished.wait(0.025):
                        if time.monotonic() >= deadline:
                            stop('History measurement total or command time limit exhausted')
                            return
                        try:
                            self.disk()
                        except GitCostUnavailable as error:
                            stop(str(error))
                            return

                watcher = threading.Thread(target=watch, daemon=True)
                watcher.start()
                try:
                    while chunk := process.stdout.read(65536):
                        count += len(chunk)
                        if count > output_limit:
                            stop('History measurement output limit exceeded')
                            break
                        output.append(chunk)
                    code = process.wait()
                finally:
                    finished.set()
                    watcher.join()
                    if process.poll() is None:
                        stop('History measurement interrupted')
                        process.wait()
                if reason:
                    raise GitCostUnavailable(reason[0])
                if code:
                    raise GitCostUnavailable('Read-only Git operation failed, object missing, or fetch allocation exceeded')
        except OSError as error:
            raise GitCostUnavailable('Read-only Git process unavailable') from error
        self.disk()
        self.remaining()
        return b''.join(output)

    def git(self, *arguments, output_limit=65536, fetch=False):
        return self.run(['git', '--no-replace-objects', '-C', str(self.path),
            '-c', 'protocol.allow=never', '-c', 'protocol.https.allow=always',
            '-c', 'protocol.file.allow=always', '-c', 'core.hooksPath=' + os.devnull,
            '-c', 'gc.auto=0', '-c', 'maintenance.auto=false', '-c', 'fetch.writeCommitGraph=false',
            '-c', 'fetch.unpackLimit=0', '-c', 'transfer.unpackLimit=0',
            '-c', 'pack.writeReverseIndex=false', *arguments], output_limit=output_limit, fetch=fetch)

    def snapshot(self, remote, oid):
        self.fetches += 1
        self.git('fetch', '--depth=1', '--no-tags', '--no-write-fetch-head',
            '--no-recurse-submodules', '--no-auto-maintenance', remote, oid, fetch=True)
        # Local-only pins let later shallow fetches negotiate already received
        # objects. They are never treated as historical remote branch tips.
        self.git('update-ref', 'refs/heads/audit-' + oid, oid)
        if int(self.git('cat-file', '-s', oid)) > 65536:
            raise GitCostUnavailable('Commit metadata exceeds limit')
        raw = self.git('cat-file', 'commit', oid)
        headers = raw.split(b'\n\n', 1)[0].splitlines()
        parents = [line[7:].decode('ascii') for line in headers if line.startswith(b'parent ')]
        if any(not SHA.fullmatch(parent) for parent in parents):
            raise GitCostUnavailable('Invalid parent metadata')
        if len(parents) > 1:
            raise GitCostUnavailable('Merge ancestry requires an independently verified ref replay')
        committer = [line for line in headers if line.startswith(b'committer ')]
        if len(committer) != 1:
            raise GitCostUnavailable('Missing or ambiguous committer timestamp')
        try:
            timestamp = int(committer[0].rsplit(b' ', 2)[1])
            committed = dt.datetime.fromtimestamp(timestamp, dt.timezone.utc).isoformat(timespec='seconds').replace('+00:00', 'Z')
        except (ValueError, OverflowError, OSError) as error:
            raise GitCostUnavailable('Invalid commit timestamp') from error
        return {'sha': oid, 'parents': parents, 'committed_at': committed, 'timestamp': timestamp}

    def measure(self, candidate, tips, request_path):
        remaining = int(self.remaining())
        if remaining < 1:
            raise GitCostUnavailable('History measurement total time limit exhausted')
        request_path.write_bytes(encoded({'path': str(self.path), 'candidate': candidate,
            'observed_tips': tips, 'limits': {'max_objects': self.limits['max_objects'],
                'max_raw_bytes': self.limits['max_snapshot_raw_bytes'],
                'max_object_bytes': self.limits['max_object_bytes'],
                'max_pack_bytes': self.limits['max_pack_bytes'],
                'metadata_limit': self.limits['metadata_bytes'],
                'timeout_seconds': min(remaining, self.limits['command_seconds'])}}))
        # A child process puts the whole multi-command pack measurement under
        # this tool's deadline; killing its process group also stops child Git.
        raw = self.run([sys.executable, str(Path(__file__).resolve()), '--measure-one', str(request_path)],
                       output_limit=262144)
        response = json.loads(raw)
        if response.get('error'):
            raise GitCostUnavailable(response['error'])
        return response['measurement']


def measure_history(repository, remote, cutoffs, *, baseline_completed_at=None, limits=None, work_parent=None):
    """Return a reproducible migration report; incomplete evidence never yields a baseline.

    ``cutoffs`` explicitly names main/data/control SHA-1 commits (None means the
    caller observed that branch absent). Public remotes are restricted to the
    named ARGUS repository; an existing local bare repository supports fixtures.
    Commit times group costs only; they do not establish real publication times.
    """
    if repository not in REPOSITORIES:
        raise ValueError('Repository is outside authorized migration scope')
    if set(cutoffs) != set(BRANCHES) or any(value is not None and
            (not isinstance(value, str) or not SHA.fullmatch(value)) for value in cutoffs.values()):
        raise ValueError('Explicit main/data/control immutable cutoffs are required')
    settings = {**DEFAULTS, **(limits or {})}
    if set(settings) != set(CEILINGS) or any(type(settings[key]) is not int or not 0 < settings[key] <= maximum
                                            for key, maximum in CEILINGS.items()):
        raise ValueError('Invalid history measurement limit')
    if settings['max_repository_bytes'] < 65536:
        raise ValueError('Temporary repository limit must leave 64 KiB for bounded metadata')
    baseline_time = instant(baseline_completed_at) if baseline_completed_at else None
    public = 'https://github.com/argus-supply/' + repository + '.git'
    local = Path(remote)
    if str(remote) == public:
        source, remote_kind = public, 'public-https'
    elif local.is_absolute() and local.is_dir() and (local / 'HEAD').is_file() and (local / 'objects').is_dir():
        source, remote_kind = local.as_uri(), 'local-bare-fixture'
    else:
        raise ValueError('Only the named public repository or an existing local bare fixture is allowed')
    started = time.monotonic()
    report = {'schema_version': '1.0', 'repository': 'argus-supply/' + repository,
        'cutoffs': dict(sorted(cutoffs.items())), 'remote_kind': remote_kind, 'complete': False, 'ancestry_closed': False,
        'status': 'incomplete', 'coverage_gaps': [], 'limits': settings, 'commits': [],
        'baseline_completed_at': baseline_completed_at, 'pack_parameters': dict(PACK_PARAMETERS),
        'ordering': 'linear-branch topological replay; ready commits ordered by committer UTC, branch name, SHA',
        'time_basis': 'commit committer time; actual historical publication/ref timing is not proven',
        'metric': 'sum of measured standalone packs; conservative increment relative to reconstructed tip snapshots',
        'git_protocol_bytes': None, 'totals': {'actual_pack_bytes_sum': 0, 'compressed_object_upper_bound_bytes': 0,
            'raw_object_bytes': 0, 'object_count': 0}, 'by_branch': {}, 'by_phase': {}, 'daily': {},
        'caveats': ['Not GitHub physical storage, pack indexes, unreachable objects or transfer bytes.',
            'Historical objects absent from reconstructed tips may be counted again.',
            'Explicit cutoffs define scope; deleted/unknown refs and other branches are not silently inferred.',
            'No baseline completion is inferred from legacy bootstrap flags or partial source watermarks.']}
    with tempfile.TemporaryDirectory(prefix='argus-git-history-', dir=work_parent) as directory:
        root, nodes, chains = Path(directory), {}, {}
        bare = root / 'objects.git'
        bare.mkdir()
        commands = Commands(bare, settings, started)
        try:
            commands.git('init', '--bare', '--template=', '-q')
            for branch in BRANCHES:
                head, chain = cutoffs[branch], []
                while head:
                    if head in chain:
                        raise GitCostUnavailable('Cyclic ancestry cannot be replayed')
                    if head not in nodes:
                        if len(nodes) >= settings['max_commits']:
                            raise GitCostUnavailable('History commit limit reached before ancestry closed')
                        nodes[head] = commands.snapshot(source, head)
                    chain.append(head)
                    head = next(iter(nodes[head]['parents']), None)
                chains[branch] = list(reversed(chain))
            # These repositories use independent orphan data/control chains.
            # Ref creation/deletion timing for shared or merged histories cannot
            # be reconstructed from cutoffs alone; do not invent those states.
            if sum(map(len, chains.values())) != len(nodes):
                raise GitCostUnavailable('Shared branch ancestry requires independently verified ref history')
            report['ancestry_closed'] = True
            positions, tips = {branch: 0 for branch in BRANCHES}, {}
            while True:
                ready = [(nodes[chain[positions[branch]]]['timestamp'], branch, chain[positions[branch]])
                         for branch, chain in chains.items() if positions[branch] < len(chain)]
                if not ready:
                    break
                _, branch, candidate = min(ready)
                node = nodes[candidate]
                measurement = commands.measure(candidate, tips, root / 'measure-request.json')
                total_raw = report['totals']['raw_object_bytes'] + measurement['raw_object_bytes']
                total_pack = report['totals']['actual_pack_bytes_sum'] + measurement['actual_pack_bytes']
                if total_raw > settings['max_total_raw_bytes'] or total_pack > settings['max_total_pack_bytes']:
                    report['limit_exceeded_measurement'] = measurement
                    raise GitCostUnavailable('History cumulative raw or pack limit exceeded')
                phase = 'steady' if baseline_time and instant(node['committed_at']) > baseline_time else 'initialization'
                item = {**node, 'branch': branch, 'phase': phase, 'day': node['committed_at'][:10],
                    'historical_tips': dict(sorted(tips.items())),
                    'measurement': measurement}
                report['commits'].append(item)
                costs = {'actual_pack_bytes_sum': measurement['actual_pack_bytes'],
                    'compressed_object_upper_bound_bytes': measurement['compressed_object_upper_bound_bytes'],
                    'raw_object_bytes': measurement['raw_object_bytes'], 'object_count': measurement['object_count']}
                for target in (report['totals'], report['by_branch'].setdefault(branch, {}),
                    report['by_phase'].setdefault(phase, {}), report['daily'].setdefault(node['committed_at'][:10], {}).setdefault(phase, {})):
                    for key, value in costs.items():
                        target[key] = target.get(key, 0) + value
                tips['refs/heads/' + branch] = candidate
                positions[branch] += 1
            expected = {'refs/heads/' + branch: sha for branch, sha in cutoffs.items() if sha}
            if tips != expected:
                raise GitCostUnavailable('Replay did not reach every fixed cutoff')
            report.update(complete=True, status='measured', final_tips=dict(sorted(tips.items())))
            report['history_baseline'] = {'complete': True, 'cutoffs': report['cutoffs'],
                'compressed_object_upper_bound_bytes': report['totals']['compressed_object_upper_bound_bytes'],
                'by_phase': report['by_phase'], 'metric_version': PACK_PARAMETERS['policy_version']}
        except (GitCostUnavailable, ValueError, OSError, UnicodeError) as error:
            report['coverage_gaps'].append(str(error)[:240])
        finally:
            report.update(audited_commit_count=len(nodes), measured_commit_count=len(report['commits']),
                shallow_snapshot_fetches=commands.fetches, temporary_repository_peak_bytes=commands.peak_bytes,
                elapsed_seconds=round(time.monotonic() - started, 3))
    report['evidence_sha256'] = hashlib.sha256(encoded(report)).hexdigest()
    return report


def main():
    if len(sys.argv) == 3 and sys.argv[1] == '--measure-one':
        request = json.loads(Path(sys.argv[2]).read_text())
        try:
            result = measure_increment(request['path'], request['candidate'], request['observed_tips'],
                baseline_complete=True, **request['limits'])
            print(json.dumps({'measurement': result}))
        except (GitCostUnavailable, ValueError) as error:
            print(json.dumps({'error': str(error)[:240]}))
        return
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repository', choices=REPOSITORIES, required=True)
    for branch in BRANCHES:
        parser.add_argument('--' + branch, required=True, help='Immutable SHA, or none for an explicitly absent branch')
    parser.add_argument('--remote', help='Defaults to the named public repository; absolute local bare path supports fixtures')
    parser.add_argument('--baseline-completed-at')
    parser.add_argument('--output', type=Path, required=True)
    for key, default in DEFAULTS.items():
        parser.add_argument('--' + key.replace('_', '-'), type=int, default=default)
    args = parser.parse_args()
    report = measure_history(args.repository, args.remote or 'https://github.com/argus-supply/' + args.repository + '.git',
        {branch: None if getattr(args, branch) == 'none' else getattr(args, branch) for branch in BRANCHES},
        baseline_completed_at=args.baseline_completed_at, limits={key: getattr(args, key) for key in DEFAULTS})
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(encoded(report))
    print(json.dumps({'status': report['status'], 'measured_commits': report['measured_commit_count'],
        'compressed_object_upper_bound_bytes': report['totals']['compressed_object_upper_bound_bytes'],
        'coverage_gaps': report['coverage_gaps']}))
    if not report['complete']:
        raise SystemExit(2)


if __name__ == '__main__':
    main()
