param(
    [string]$ExePath = "D:\work\safeGuard\dist\agent-service\SafeGuardAgent.exe"
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $ExePath)) {
    throw "Agent executable not found: $ExePath"
}

& sc.exe stop SafeGuardAgent | Out-Host
Start-Sleep -Seconds 2
& $ExePath remove | Out-Host

Write-Host "[agent-uninstall] Service removed."
