#!/usr/bin/env bash
set -euo pipefail
stage="${1:?build, test, audit or package}"
case "${APP:?Application required}" in
  keepass2android) exec bash scripts/build-android.sh "$stage" ;;
  keepassxc) exec bash scripts/build-desktop.sh "${KEEPASS_BUILD_PLATFORM:?Platform required}" "$stage" ;;
  *) exit 2 ;;
esac
