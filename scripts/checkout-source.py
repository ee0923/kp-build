"""Fetch the reviewed upstream tag and reject a moved tag before checking out."""
import json
from pathlib import Path
import re
import subprocess
import sys


def checkout(lock, target):
    target = Path(target)
    if target.exists():
        raise ValueError('Refusing to overwrite an existing source directory')
    if not re.fullmatch(r'[a-f0-9]{40}', lock['commit']):
        raise ValueError('Expected a full upstream commit')
    subprocess.run(['git', 'init', str(target)], check=True)
    git = ['git', '-C', str(target)]
    subprocess.run([*git, 'remote', 'add', 'origin', lock['repository']], check=True)
    subprocess.run([*git, 'fetch', '--depth=1', 'origin', lock['ref']], check=True)
    actual = subprocess.check_output([*git, 'rev-parse', 'FETCH_HEAD^{commit}'], text=True).strip()
    if actual != lock['commit']:
        raise ValueError('Upstream ref changed; review the source and patch before upgrading')
    subprocess.run([*git, 'checkout', '--detach', actual], check=True)
    print(f"Checked out {lock['name']} {lock['ref']} at {actual}")


if __name__ == '__main__':
    name = sys.argv[1]
    locks = json.loads((Path(__file__).resolve().parents[1] / 'sources.lock.json').read_text())
    checkout(locks[name], sys.argv[2] if len(sys.argv) > 2 else 'source')
