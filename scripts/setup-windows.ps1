$ErrorActionPreference = 'Stop'
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
$installation = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if ($LASTEXITCODE -ne 0 -or -not $installation) { throw 'Visual C++ toolchain not found' }
$setup = Join-Path $installation 'Common7\Tools\VsDevCmd.bat'
if (-not (Test-Path $setup)) { throw 'Visual Studio environment script not found' }
$before = @{}
Get-ChildItem Env: | ForEach-Object { $before[$_.Name] = $_.Value }
$batch = Join-Path $env:RUNNER_TEMP ('keepass-msvc-' + [guid]::NewGuid().ToString('N') + '.cmd')
try {
    @('@echo off', "call `"$setup`" -no_logo -arch=x64 -host_arch=x64", 'if errorlevel 1 exit /b 1', 'set') |
        Set-Content -Path $batch -Encoding utf8
    $lines = & $env:ComSpec /d /c $batch
    $result = $LASTEXITCODE
} finally {
    Remove-Item $batch -ErrorAction SilentlyContinue
}
if ($result -ne 0) { throw 'Visual Studio environment initialization failed' }
foreach ($line in $lines) {
    if ($line -notmatch '^([^=]+)=(.*)$') { continue }
    $name, $value = $Matches[1], $Matches[2]
    if ($name -match '^(GITHUB_|RUNNER_)' -or $name -eq 'NODE_OPTIONS') { continue }
    if (-not $before.ContainsKey($name) -or $before[$name] -cne $value) {
        "$name=$value" | Out-File -FilePath $env:GITHUB_ENV -Encoding utf8 -Append
    }
}
