"""Bare Git remotes that receive pushes in tests.

Local transport scrubs ``GIT_CONFIG_*`` before spawning ``receive-pack``, so
GitStore environment settings never reach the receiving repository. With
default settings receive-pack spawns a detached ``git maintenance run --auto``
that outlives the push and writes into ``objects/`` while
``TemporaryDirectory`` cleanup is already deleting it. Only the receiving
repository's own config keeps every push fully synchronous.
"""
import subprocess
from pathlib import Path


def init_bare_remote(path):
    """Create a bare repository that schedules no background work after receiving."""
    path = Path(path)
    subprocess.run(['git', 'init', '--bare', '-q', str(path)], check=True,
                   capture_output=True, timeout=30)
    # maintenance.auto and receive.autogc independently stop receive-pack from
    # spawning the detached post-push maintenance process.
    for key in ('maintenance.auto', 'receive.autogc'):
        subprocess.run(['git', '-C', str(path), 'config', key, 'false'],
                       check=True, capture_output=True, timeout=30)
    return path
