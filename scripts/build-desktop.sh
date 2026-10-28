#!/usr/bin/env bash
set -euo pipefail
platform="${1:?linux, macos or windows}"
stage_build() {
args=(-G Ninja -DCMAKE_BUILD_TYPE=Release -DKEEPASSXC_BUILD_TYPE=Release
      -DWITH_TESTS=ON -DWITH_GUI_TESTS=OFF -DKPXC_FEATURE_NETWORK=ON -DKPXC_FEATURE_DOCS=ON)
case "$platform" in
  linux) args+=(-DCMAKE_INSTALL_PREFIX=/usr) ;;
  macos|windows)
    vcpkg_root="$(python3 -c 'from pathlib import Path; print(Path("vcpkg").resolve().as_posix())')"
    args+=("-DCMAKE_TOOLCHAIN_FILE=$vcpkg_root/scripts/buildsystems/vcpkg.cmake" -DWITH_BUILD_QT=ON)
    if [[ "$platform" == macos ]]; then
      args+=(-DVCPKG_TARGET_TRIPLET=arm64-osx-dynamic-release -DVCPKG_HOST_TRIPLET=arm64-osx-dynamic-release)
    else
      args+=(-DVCPKG_TARGET_TRIPLET=x64-windows -DVCPKG_HOST_TRIPLET=x64-windows)
    fi ;;
  *) exit 2 ;;
esac
cmake -S source -B build "${args[@]}"
cmake --build build --parallel 2
}

stage_test() {
if [[ "$platform" != linux ]]; then
  # vcpkg does not put Qt platform plugins beside each test executable.
  export QT_PLUGIN_PATH
  QT_PLUGIN_PATH="$(python3 - <<'PYTHON'
from pathlib import Path
roots = [p.parent for p in Path('build/vcpkg_installed').glob('*/Qt6/plugins/platforms') if p.is_dir()]
if len(roots) != 1:
    raise SystemExit('Expected one release Qt plugin directory')
print(roots[0].resolve().as_posix())
PYTHON
)"
fi
if [[ "$platform" == linux ]]; then
  QT_QPA_PLATFORM=xcb xvfb-run -a ctest --test-dir build --output-on-failure --timeout 180
else
  ctest --test-dir build --output-on-failure --timeout 180
fi
cli=build/src/cli/keepassxc-cli
[[ "$platform" != windows ]] || cli+=.exe
python3 scripts/cli_smoke.py "$cli"
}

stage_audit() {
python3 scripts/audit-docs.py build/docs
}

stage_package() {
mkdir -p dist
case "$platform" in
  linux)
    DESTDIR="$PWD/stage" cmake --install build
    tar -czf dist/keepassxc-2.8.0-linux-x64.tar.gz -C stage . ;;
  macos)
    (cd build && cpack -G DragNDrop -C Release)
    cp build/KeePassXC-*.dmg dist/ ;;
  windows)
    (cd build && cpack -G ZIP -C Release)
    cp build/KeePassXC-*.zip dist/ ;;
esac
python3 scripts/checksums.py
}

case "${2:-all}" in
  all) stage_build; stage_test; stage_audit; stage_package ;;
  build|test|audit|package) "stage_$2" ;;
  *) exit 2 ;;
esac
