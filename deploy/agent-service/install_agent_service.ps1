param(
    [string]$ExePath = "D:\work\safeGuard\dist\agent-service\SafeGuardAgent.exe",
    [string]$ServerBase = "http://192.168.175.1:8000",
    [string]$WorkDir = "C:\ProgramData\SafeGuardAgent",
    [string]$GrpcUploadTarget = ""
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $ExePath)) {
    throw "Agent executable not found: $ExePath"
}

& $ExePath remove | Out-Host
if ([string]::IsNullOrWhiteSpace($GrpcUploadTarget)) {
    & $ExePath install --server-base $ServerBase --work-dir $WorkDir | Out-Host
} else {
    & $ExePath install --server-base $ServerBase --work-dir $WorkDir --grpc-upload-target $GrpcUploadTarget | Out-Host
}
& sc.exe config SafeGuardAgent start= auto | Out-Host
& sc.exe failure SafeGuardAgent reset= 86400 actions= restart/60000/restart/60000/restart/300000 | Out-Host
& sc.exe failureflag SafeGuardAgent 1 | Out-Host

Write-Host "[agent-install] Service installed."
Write-Host "[agent-install] Main config file: $env:ProgramData\SafeGuardAgent\install_config.json"
Write-Host "[agent-install] ServerBase=$ServerBase"
Write-Host "[agent-install] WorkDir=$WorkDir"
if (-not [string]::IsNullOrWhiteSpace($GrpcUploadTarget)) {
    Write-Host "[agent-install] GrpcUploadTarget=$GrpcUploadTarget"
}
Write-Host "[agent-install] Self-check: sc.exe query SafeGuardAgent"
