"""Publish all assets as a draft first; only complete releases become visible."""
import json
import os
from pathlib import Path
import subprocess

from runtime import file_digest, run


def main():
    out = Path('dist')
    manifest = json.loads((out / 'manifest.json').read_text())
    repo = os.environ['GITHUB_REPOSITORY']
    version = manifest['version']
    if manifest['repository'] != repo:
        raise ValueError('release repository mismatch')
    for name, info in manifest['assets'].items():
        if file_digest(out / name) != info['sha256'] or (out / name).stat().st_size != info['size']:
            raise ValueError('release checksum mismatch')
    notes = ['Automated data supply snapshot.', '', f"Records: {manifest['record_count']}",
             f"Delta base: {manifest['base_version'] or 'empty database'}", '', 'Source status:']
    for source, status in manifest['sources'].items():
        notes.append(f"- {source}: {status['status']}" + (f" ({status['error']})" if status.get('error') else ''))
    notes.extend(['', 'Verify manifest checksums before importing. Partial sources are still backfilling.',
                  'This release does not authorize ARGUS runtime activation.'])
    note_path = Path('.work/release-notes.md')
    note_path.write_text('\n'.join(notes) + '\n')
    run(['gh', 'release', 'create', version, '--repo', repo, '--draft', '--target', os.environ['GITHUB_SHA'],
         '--title', version, '--notes-file', str(note_path)])
    assets = [str(out / name) for name in [*manifest['assets'], 'manifest.json']]
    run(['gh', 'release', 'upload', version, '--repo', repo, *assets])
    # The tag endpoint is intended for published releases. Find the authenticated
    # draft through the releases list instead, before promoting it.
    candidates = json.loads(run(['gh', 'api', f'repos/{repo}/releases?per_page=100']))
    uploaded = next(release for release in candidates if release['tag_name'] == version and release['draft'])
    facts = {entry['name']: entry for entry in uploaded['assets']}
    for asset in assets:
        path = Path(asset)
        remote = facts[path.name]
        if remote['size'] != path.stat().st_size:
            raise ValueError('uploaded asset size mismatch')
        if remote.get('digest') and remote['digest'] != 'sha256:' + file_digest(path):
            raise ValueError('uploaded asset digest mismatch')
    run(['gh', 'release', 'edit', version, '--repo', repo, '--draft=false', '--latest'])
    print(f'https://github.com/{repo}/releases/tag/{version}')


if __name__ == '__main__':
    main()
