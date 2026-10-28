"""Hash only final packages; never archive the checkout or runner temporary files."""
import hashlib
from pathlib import Path

folder = Path('dist')
files = sorted(p for p in folder.iterdir() if p.is_file() and p.name != 'SHA256SUMS')
if not files:
    raise SystemExit('No packages to upload')
with (folder / 'SHA256SUMS').open('w', encoding='utf-8') as output:
    for path in files:
        digest = hashlib.sha256()
        with path.open('rb') as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                digest.update(chunk)
        output.write(f'{digest.hexdigest()}  {path.name}\n')
