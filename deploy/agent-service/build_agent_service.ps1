param(
    [string]$PythonExe = "D:\anaconda3\envs\scanocr\python.exe",
    [string]$OutputDir = "D:\work\safeGuard\dist\agent-service"
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $PythonExe)) {
    throw "Python executable not found: $PythonExe"
}

$repoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path))
$specPath = Join-Path $repoRoot "deploy\agent-service\SafeGuardAgent.spec"
$pyInstaller = Join-Path (Split-Path $PythonExe -Parent) "Scripts\pyinstaller.exe"

if (-not (Test-Path $pyInstaller)) {
    & $PythonExe -m pip install pyinstaller | Out-Host
}

New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
Push-Location $repoRoot
try {
    & $PythonExe -m PyInstaller --clean --noconfirm --distpath $OutputDir --workpath "$OutputDir\build" $specPath
    Write-Host "[agent-build] Output:" (Join-Path $OutputDir "SafeGuardAgent.exe")
}
finally {
    Pop-Location
}
