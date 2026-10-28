#!/usr/bin/env bash
set -euo pipefail
: "${GH_TOKEN:?GitHub token required}"
: "${GH_REPO:?GitHub repository required}"
: "${APP:?Application required}"
: "${RELEASE_TARGET:?Snapshot commit required}"
: "${PACKAGE_ID:?Platform identifier required}"
case "$PACKAGE_ID" in android|linux|macos|windows) ;; *) exit 2 ;; esac
command -v gh >/dev/null
RELEASE_TAG="$(python3 - "$APP" <<'PY'
import json, re, sys
app = sys.argv[1]
if app not in ('keepass2android', 'keepassxc'):
    raise SystemExit('Unknown application')
with open('sources.lock.json') as stream:
    ref = json.load(stream)[app]['ref']
version = ref.removeprefix('v')
if not re.fullmatch(r'[0-9][0-9A-Za-z.+-]*', version):
    raise SystemExit('Invalid locked release version')
print(app + '-v' + version)
PY
)"

# Validate the exact files before publishing, and give each platform its own manifest.
python3 - "$PACKAGE_ID" <<'PY'
import hashlib
from pathlib import Path
import sys
root = Path('dist')
manifest = root / 'SHA256SUMS'
entries = manifest.read_text().splitlines()
if not entries:
    raise SystemExit('Empty package manifest')
names = set()
for line in entries:
    digest, name = line.split('  ', 1)
    path = root / name
    if Path(name).name != name or path.is_symlink() or name in names or not path.is_file():
        raise SystemExit('Invalid package manifest entry')
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    if digest != actual:
        raise SystemExit('Package checksum mismatch: ' + name)
    names.add(name)
if {p.name for p in root.iterdir()} != names | {'SHA256SUMS'}:
    raise SystemExit('Unexpected files in package directory')
manifest.rename(root / ('SHA256SUMS-' + sys.argv[1]))
PY

# Matrix jobs share a release; retries also handle simultaneous creation and reruns.
for attempt in 1 2 3 4 5; do
  if gh release view "$RELEASE_TAG" >/dev/null 2>&1 ||
     gh release create "$RELEASE_TAG" --target "$RELEASE_TARGET" --prerelease \
       --title "$RELEASE_TAG" --notes 'Custom build.'; then
    if gh release upload "$RELEASE_TAG" dist/* --clobber; then
      exit 0
    fi
  fi
  if [[ "$attempt" -lt 5 ]]; then sleep "$((attempt * 5))"; fi
done
echo '::error::Release publication failed after 5 attempts.'
exit 1
