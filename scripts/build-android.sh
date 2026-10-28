#!/usr/bin/env bash
set -euo pipefail
root="$(pwd -P)"
export DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1
export GRADLE_OPTS='-Dorg.gradle.workers.max=2 -Dorg.gradle.daemon=false'
: "${ANDROID_HOME:?Android SDK required}"
export ANDROID_SDK_ROOT="$ANDROID_HOME"
export ANDROID_NDK_ROOT="$ANDROID_HOME/ndk/28.2.13676358"
cd source
stage_build() {
git submodule update --init src/java/argon2/phc-winner-argon2
(cd src/java/JavaFileStorageTest-AS && ./gradlew --no-daemon \
  :JavaFileStorage:clean :android-filechooser:clean :JavaFileStorage:assemble :android-filechooser:assemble)
make native java manifestlink Flavor=Net Configuration=Debug NoDonationMenu=true
dotnet restore src/keepass2android-app/keepass2android-app.csproj -p:Flavor=Net
python3 "$root/scripts/audit-artifacts.py" --assets src
dotnet build src/keepass2android-app/keepass2android-app.csproj --no-restore -c Debug -t:SignAndroidPackage \
  -p:Flavor=Net -p:NoDonationMenu=true -p:AndroidPackageFormats=apk -p:EmbedAssembliesIntoApk=true \
  -p:AndroidUseAssemblyStore=false -p:AndroidEnableAssemblyCompression=false
}

stage_test() {
DOTNET_ROLL_FORWARD=Major dotnet test src/Kp2aAutofillParser.Tests/Kp2aAutofillParser.Tests.csproj \
  --logger trx --results-directory "$root/reports"
}

stage_audit() {
python3 "$root/scripts/audit-artifacts.py" --archive src/java/JavaFileStorage/app/build/outputs/aar/JavaFileStorage-debug.aar
if ! python3 "$root/scripts/audit-artifacts.py" --apk-dir src/keepass2android-app/bin/Debug; then
  # Identify classes in the actual expanded Java inputs, including NuGet-provided AARs.
  python3 - "$root/scripts/audit-artifacts.py" <<'PY'
import importlib.util
from pathlib import Path
import sys
import zipfile
spec = importlib.util.spec_from_file_location('audit', sys.argv[1])
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)
for path in sorted(Path('src').rglob('*.jar')):
    if 'obj' not in path.parts:
        continue
    with zipfile.ZipFile(path) as jar:
        for name in jar.namelist():
            try:
                audit.check(jar.read(name), str(path) + ':' + name)
            except ValueError as error:
                print(error)
PY
  exit 1
fi
}

stage_package() {
cd "$root"
python3 - <<'PY'
from pathlib import Path
import shutil, subprocess
apks=list(Path('source/src/keepass2android-app/bin/Debug').rglob('*-Signed.apk'))
if len(apks) != 1:
    raise SystemExit(f'Expected one signed universal APK, found {len(apks)}')
import os
subprocess.run([os.environ['ANDROID_HOME']+'/build-tools/36.0.0/apksigner','verify','--verbose',str(apks[0])],check=True)
Path('dist').mkdir(exist_ok=True)
shutil.copy2(apks[0], 'dist/keepass2android-1.15-r6-debug.apk')
PY
python3 scripts/checksums.py
}

case "${1:-all}" in
  all) stage_build; stage_test; stage_audit; stage_package ;;
  build|test|audit|package) "stage_$1" ;;
  *) exit 2 ;;
esac
