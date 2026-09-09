"""Test pinned standalone collectors, then precharge every authorized main push.

Git publication and control costs use the exported collector's ledger. Existing
history requires migration; code publication never completes the data baseline.
Failed pushes retain their durable intent and local candidate for inspection.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tarfile
import tempfile
import uuid

REPOS = ('argus-intel-data', 'argus-poc-index', 'argus-detection-resources')
TEST_TIMEOUT_SECONDS = 600


def command(args, *, timeout=240, **kwargs):
    return subprocess.run(args, check=True, timeout=timeout, **kwargs)


def output(args):
    return command(args, capture_output=True, text=True).stdout.strip()


def remote_url(repository):
    if repository not in REPOS:
        raise ValueError('repository is outside the three authorized targets')
    return 'https://github.com/argus-supply/' + repository + '.git'


def test_target(source, target, repository, commit, report_directory):
    """Generate and test one isolated worktree without contacting any remote."""
    if Path(output(['git', '-C', str(target), 'rev-parse', '--show-toplevel'])).resolve() != target:
        raise ValueError('target must be a repository root: ' + repository)
    if output(['git', '-C', str(target), 'rev-parse', '--abbrev-ref', 'HEAD']) not in ('main', 'HEAD'):
        raise ValueError('target must be detached or on main: ' + repository)
    if output(['git', '-C', str(target), 'status', '--porcelain']):
        raise ValueError('inspect unexpected worktree changes before regeneration: ' + repository)
    command([sys.executable, str(source / 'tools/distribute.py'), '--target', str(target),
             '--repository', repository, '--source-commit', commit, '--enable-schedule'])
    command([sys.executable, str(target / 'tools/check_distribution.py')])
    print(repository, 'testing pinned standalone copy', flush=True)
    # Tests have no publication credentials; only GitStore receives the token.
    env = {key: value for key, value in os.environ.items() if key not in ('GH_TOKEN', 'GITHUB_TOKEN')}
    log = report_directory / (repository + '-local-tests.txt')
    try:
        tested = subprocess.run([sys.executable, '-m', 'unittest', 'discover', '-s', 'tests', '-v'],
            cwd=target, capture_output=True, text=True, timeout=TEST_TIMEOUT_SECONDS, env=env)
    except subprocess.TimeoutExpired as error:
        parts = [value.decode(errors='replace') if isinstance(value, bytes) else value or ''
                 for value in (error.stdout, error.stderr)]
        log.write_text(''.join(parts) + '\nFAILED: standalone tests exceeded 600 seconds\n')
        raise RuntimeError('standalone tests timed out: ' + repository) from error
    log.write_text(tested.stdout + tested.stderr)
    if tested.returncode:
        raise RuntimeError('standalone tests failed: ' + repository)
    if re.search(r'\bskipped=[1-9]\d*\b', tested.stderr):
        raise RuntimeError('standalone tests skipped required verification: ' + repository)
    command([sys.executable, str(target / 'tools/check_distribution.py')])


def prepare_candidate(target, repository, report_directory):
    """Commit tested files locally and measure whole changed-file bytes separately."""
    git = ['git', '-C', str(target)]
    parent = output([*git, 'rev-parse', 'HEAD'])
    command([*git, 'add', '-A'])
    command([*git, 'diff', '--cached', '--check'])
    changed = subprocess.run([*git, 'diff', '--cached', '--quiet'], timeout=240).returncode
    if changed not in (0, 1):
        raise RuntimeError('unable to inspect staged candidate: ' + repository)
    if changed:
        (report_directory / (repository + '-staged-diff.txt')).write_text(
            output([*git, 'diff', '--cached', '--stat']) + '\n')
        command([*git, 'commit', '-m', 'fix(data): update pinned bounded collector'], capture_output=True)
    candidate = output([*git, 'rev-parse', 'HEAD'])
    raw = command([*git, 'diff', '--raw', '-z', '--no-abbrev', '--no-renames', parent, candidate], capture_output=True).stdout
    changed_bytes = 0
    fields = raw.split(b'\0')
    for index in range(0, len(fields) - 1, 2):
        metadata = fields[index].split()
        if metadata[-1] != b'D':
            changed_bytes += int(output([*git, 'cat-file', '-s', metadata[3].decode()]))
    return {'target': str(target), 'parent': parent, 'candidate': candidate,
            'full_changed_file_bytes': changed_bytes, 'local_tests': 'passed'}


def publish_candidate(repository, prepared, store, ledger, record, save):
    """Precharge and settle one candidate; an injected store supports local Git tests.

    The CLI constructs only the named public remote. Failures never refund or erase
    reservations: the report and control branch retain the last known push phase.
    """
    remote_url(repository)
    stage = 'check-cost-baseline'
    record.update(repository=repository, **prepared, status='pending', metric='git-object-cost-v1',
                  job_id='main-' + uuid.uuid4().hex, publication_intent_retained=False)

    def checkpoint():
        record['control_measurements'] = list(ledger.control_measurements)
        record['control_measured_pack_bytes'] = sum(item['measured_pack_bytes'] for item in ledger.control_measurements)
        record['control_charged_upper_bound_bytes'] = sum(item['charged_upper_bound_bytes'] for item in ledger.control_measurements)
        save()

    try:
        checkpoint()
        phase = ledger.initializing()
        record['phase'] = 'initialization' if phase else 'steady'
        observed = store.observe_heads().get('refs/heads/main')
        if observed == prepared['candidate']:
            record.update(status='unchanged', main_sha=observed)
            checkpoint()
            return
        if observed != prepared['parent']:
            raise RuntimeError('remote main moved; inspect the retained local candidate before retrying')
        stage = 'import-candidate'
        # Include the single parent edge: depth one marks the candidate shallow,
        # so Git cannot prove a non-force fast-forward even when the parent exists.
        store.run('fetch', '--depth=2', '--no-tags', str(Path(prepared['target']).resolve()), prepared['candidate'])
        parents = store.run('rev-list', '--parents', '-n', '1', prepared['candidate']).stdout.decode().split()
        if parents != [prepared['candidate'], prepared['parent']]:
            raise ValueError('candidate must have exactly the inspected main parent')
        stage = 'reserve-work'
        ledger.reserve(record['job_id'], 0, bootstrap=phase, publication_only=True)
        record['status'] = 'work-reserved'
        checkpoint()
        stage = 'reserve-publication'
        record['publication_intent_retained'] = None
        record['measurement'] = ledger.reserve_publication(record['job_id'], 'main',
            prepared['candidate'], prepared['full_changed_file_bytes'])
        record.update(status='publication-reserved', publication_intent_retained=True)
        checkpoint()
        stage = 'push-main'
        store.push_prepared('main', prepared['candidate'])
        record.update(status='pushed', main_sha=prepared['candidate'])
        checkpoint()
        stage = 'settle-publication'
        ledger.settle(record['job_id'], 0, 0, published=True, runner_seconds=0)
        record.update(status='published', publication_intent_retained=False)
        checkpoint()
    except Exception as error:
        record.update(status='failed', failed_stage=stage, error=type(error).__name__ + ': ' + str(error),
                      reservation_recovery='Inspect durable control state; no automatic refund or retry was attempted.')
        checkpoint()
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-commit', required=True)
    parser.add_argument('--report-directory', type=Path, required=True)
    args = parser.parse_args()
    application = Path(__file__).resolve().parents[3]
    report_directory = args.report_directory.resolve()
    report_path = report_directory / 'distribution.json'
    report = json.loads(report_path.read_text())
    if set(report['worktrees']) != set(REPOS):
        raise SystemExit('distribution does not identify exactly the authorized three repositories')
    targets = {name: Path(report['worktrees'][name]).resolve() for name in REPOS}
    if len(set(targets.values())) != len(REPOS):
        raise SystemExit('each authorized repository requires a distinct worktree')
    commit = output(['git', '-C', str(application), 'rev-parse', '--verify', '--end-of-options', args.source_commit + '^{commit}'])
    if not re.fullmatch(r'[a-f0-9]{40}', commit):
        raise SystemExit('source commit must resolve to an immutable SHA-1 commit')
    export = Path(tempfile.mkdtemp(prefix='argus-publish-' + commit[:8] + '-'))
    data = command(['git', '-C', str(application), 'archive', commit, 'services/argus-data-sync'], capture_output=True).stdout
    with tarfile.open(fileobj=io.BytesIO(data)) as archive:
        archive.extractall(export, filter='data')
    source = export / 'services/argus-data-sync'
    report.update(source_commit=commit, source_export=str(source))

    def save():
        temporary = report_path.with_suffix('.json.tmp')
        temporary.write_text(json.dumps(report, indent=2) + '\n')
        temporary.replace(report_path)

    failures = []
    with ThreadPoolExecutor(max_workers=len(REPOS)) as executor:
        futures = {name: executor.submit(test_target, source, targets[name], name, commit, report_directory) for name in REPOS}
        for name, future in futures.items():
            try:
                future.result()
                state = {'status': 'passed', 'timeout_seconds': TEST_TIMEOUT_SECONDS}
            except Exception as error:
                failures.append(name)
                state = {'status': 'failed', 'error': str(error), 'timeout_seconds': TEST_TIMEOUT_SECONDS}
            report.setdefault('standalone_tests', {})[name] = state
            save()
    if failures:
        raise SystemExit('publication refused; standalone verification failed: ' + ', '.join(failures))
    prepared = {name: prepare_candidate(targets[name], name, report_directory) for name in REPOS}
    # Cost policy and ledger implementation must come from the exact tested export.
    sys.path.insert(0, str(source))
    from sync.core import load_policy
    from sync.gitstore import GitStore
    from sync.ledger import Ledger
    policy = load_policy(source / 'policy.json')
    token = os.getenv('GH_TOKEN') or os.getenv('GITHUB_TOKEN') or command(
        ['gh', 'auth', 'token'], capture_output=True, text=True).stdout.strip()
    if not token:
        raise SystemExit('a GitHub publication token is required')
    for name in REPOS:
        store = GitStore(export / 'publication-ledgers' / (name + '.git'), remote_url(name), token)
        store.env.update(GIT_TRACE='0', GIT_TRACE_CURL='0', GIT_CURL_VERBOSE='0')
        ledger = Ledger(store, policy)
        record = {'source_commit': commit, 'remote': remote_url(name), 'shadow': str(store.path)}
        report.setdefault('main_publications', []).append(record)
        save()
        publish_candidate(name, prepared[name], store, ledger, record, save)
        report.setdefault('publication_history', []).append({'repository': name, 'main_sha': record['main_sha'],
            'source_commit': commit, 'job_id': record['job_id'], 'status': record['status']})
        report.setdefault('published', {})[name] = {'main_sha': record['main_sha'], 'source_commit': commit,
            'url': 'https://github.com/argus-supply/' + name, 'local_tests': 'passed', 'status': record['status']}
        save()
        print(name, record['status'], record['main_sha'], flush=True)


if __name__ == '__main__':
    main()
