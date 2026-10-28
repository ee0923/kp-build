#!/usr/bin/env bash
set -euo pipefail
set +x
: "${PATCH_BOOTSTRAP:?Configure the matching CUSTOMIZE_SCRIPT repository secret first}"
: "${RUNNER_TEMP:?Run inside GitHub Actions}"
export SOURCE
SOURCE="$(python3 -c 'from pathlib import Path; print(Path("source").resolve())')"
bootstrap="$(mktemp "$RUNNER_TEMP/keepass-bootstrap.XXXXXX")"
trap 'rm -f "$bootstrap"' EXIT
chmod 600 "$bootstrap"
printf '%s\n' "$PATCH_BOOTSTRAP" > "$bootstrap"
unset PATCH_BOOTSTRAP
# The fixed bootstrap downloads once, authenticates and decrypts before execution.
bash "$bootstrap"
