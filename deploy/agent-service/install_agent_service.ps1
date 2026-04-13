param(
    [string]$ExePath = "D:\work\safeGuard\dist\agent-service\SafeGuardAgent.exe",
    [string]$ServerBase = "http://192.168.175.1:8000",
    [string]$WorkDir = "C:\ProgramData\SafeGuardAgent"
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $ExePath)) {
    throw "Agent executable not found: $ExePath"
}

& $ExePath remove | Out-Host
& $ExePath install --server-base $ServerBase --work-dir $WorkDir | Out-Host
& sc.exe config SafeGuardAgent start= auto | Out-Host
& sc.exe failure SafeGuardAgent reset= 86400 actions= restart/60000/restart/60000/restart/300000 | Out-Host
& sc.exe failureflag SafeGuardAgent 1 | Out-Host
& sc.exe start SafeGuardAgent | Out-Host

Write-Host "[agent-install] Service installed."
Write-Host "[agent-install] SAFEGUARD_SERVER_BASE=$ServerBase"
Write-Host "[agent-install] SAFEGUARD_AGENT_WORKDIR=$WorkDir"
