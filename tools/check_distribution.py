"""Fail CI on edits or extra Python files in generated distributions."""
import hashlib
import json
from pathlib import Path


def check(root):
    manifest = json.loads((root / 'distribution.json').read_text())
    if len(manifest['source_commit']) != 40:
        raise ValueError('unpinned source commit')
    for name, sha in manifest['files'].items():
        path = root / name
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != sha:
            raise ValueError('generated file drift: ' + name)
    for folder in ('sync', 'schemas', 'tests', 'fixtures'):
        for path in (root / folder).rglob('*'):
            if path.is_file() and '__pycache__' not in path.parts and str(path.relative_to(root)) not in manifest['files']:
                raise ValueError('unexpected generated file: ' + str(path.relative_to(root)))


if __name__ == '__main__':
    check(Path(__file__).resolve().parents[1])
    print('Pinned distribution verified')
