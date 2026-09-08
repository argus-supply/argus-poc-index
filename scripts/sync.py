"""Run a bounded collection pass and stage a self-contained data release."""
import argparse
import json
import os
from pathlib import Path
import time

from runtime import Store, package, restore
from sources import COLLECTORS


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', default='sources.json')
    parser.add_argument('--work', default='.work')
    parser.add_argument('--output', default='dist')
    parser.add_argument('--repository', default=os.environ.get('GITHUB_REPOSITORY', 'local/test'))
    parser.add_argument('--restore', action='store_true')
    parser.add_argument('--source', help='Only run the selected source; retain other source snapshots')
    parser.add_argument('--limit', type=int, help='Override per-source item budget for a smoke run')
    args = parser.parse_args()
    config = json.loads(Path(args.config).read_text())
    if args.limit is not None and args.limit < 1:
        parser.error('--limit must be positive')
    if args.source and not any(s['id'] == args.source for s in config['sources']):
        parser.error('unknown source')
    work = Path(args.work)
    work.mkdir(parents=True, exist_ok=True)
    base = restore(work, args.repository) if args.restore else None
    store = Store(work / 'state.sqlite')
    before = store.signature()
    results = {}
    for source in config['sources']:
        sid = source['id']
        if args.source and sid != args.source:
            continue
        limit = args.limit or source['budget']
        print(f'Collecting {sid} (budget={limit})', flush=True)
        def collect(previous):
            return COLLECTORS[source['type']](store, source, previous, work / 'checkouts', limit)
        result = store.transaction(sid, collect)
        results[sid] = result
        print(f"{sid}: {result['status']}" + (f" ({result['error']})" if result.get('error') else ''), flush=True)
    failed = [sid for sid, row in results.items() if row['status'] == 'failed']
    summary = ['## Collection results', '', '| Source | Status | Error |', '| --- | --- | --- |']
    for sid, row in results.items():
        summary.append(f"| {sid} | {row['status']} | {row.get('error') or ''} |")
    for source in config['sources']:
        if source['id'] not in results:
            summary.append(f"| {source['id']} | not run | |")
    if os.environ.get('GITHUB_STEP_SUMMARY'):
        with open(os.environ['GITHUB_STEP_SUMMARY'], 'a') as stream:
            stream.write('\n'.join(summary) + '\n')
    changed = before != store.signature() or base is None
    count = store.db.execute('SELECT count(*) FROM docs').fetchone()[0]
    # Never promote a fresh, wholly failed/empty bootstrap as usable data.
    publish = changed and count > 0
    version = 'data-' + time.strftime('%Y%m%dT%H%M%SZ', time.gmtime()) + '-' + os.environ.get('GITHUB_RUN_ID', 'local') + '-' + os.environ.get('GITHUB_RUN_ATTEMPT', '1')
    if publish:
        manifest = package(store, args.output, args.repository, version, base, config)
        print(f"Staged {version}: {manifest['record_count']} records", flush=True)
    if os.environ.get('GITHUB_OUTPUT'):
        with open(os.environ['GITHUB_OUTPUT'], 'a') as stream:
            stream.write(f'publish={str(publish).lower()}\nversion={version}\nfailed={str(bool(failed)).lower()}\n')
    store.db.close()
    # Workflow publishes healthy sources first, then separately marks feed failures.
    if failed and not os.environ.get('GITHUB_ACTIONS'):
        raise SystemExit(1)


if __name__ == '__main__':
    main()
