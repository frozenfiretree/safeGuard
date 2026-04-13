# Agent Service Delivery

This directory contains the service-delivery chain for the v2 Windows Agent.

## Files

- `SafeGuardAgent.spec`
  PyInstaller onefile spec.
- `build_agent_service.ps1`
  Builds `SafeGuardAgent.exe`.
- `build_agent_service.bat`
  Batch wrapper for the PowerShell build script.
- `install_agent_service.ps1`
  Installs the service, configures machine-level env vars, enables auto start, and sets SCM failure actions.
- `uninstall_agent_service.ps1`
  Stops and removes the service.
- `start_agent_service.bat`
  Starts the installed service.
- `stop_agent_service.bat`
  Stops the installed service.

## Build

```powershell
deploy\agent-service\build_agent_service.bat
```

Output:

```text
dist\agent-service\SafeGuardAgent.exe
```

## Install

```powershell
powershell -ExecutionPolicy Bypass -File deploy\agent-service\install_agent_service.ps1 `
  -ExePath D:\work\safeGuard\dist\agent-service\SafeGuardAgent.exe `
  -ServerBase http://192.168.175.1:8000 `
  -WorkDir C:\ProgramData\SafeGuardAgent
```

## One-Click Install

`SafeGuardAgent.exe` now supports double-click installation on the target Windows host:

- double-click the EXE
- accept the UAC prompt
- the agent writes `C:\ProgramData\SafeGuardAgent\install_config.json`
- the Windows service is installed and started automatically
- an installation result page opens automatically from `C:\ProgramData\SafeGuardAgent\install_result.html`

Optional packaged defaults can be placed next to the EXE in `agent-install.json`:

```json
{
  "server_base": "http://192.168.175.1:8000",
  "work_dir": "C:\\ProgramData\\SafeGuardAgent"
}
```

The install script configures:

- install settings file: `C:\ProgramData\SafeGuardAgent\install_config.json`
- service start mode: `auto`
- SCM failure actions:
  - first failure -> restart after 60s
  - second failure -> restart after 60s
  - subsequent failures -> restart after 300s

## Remove

```powershell
powershell -ExecutionPolicy Bypass -File deploy\agent-service\uninstall_agent_service.ps1 `
  -ExePath D:\work\safeGuard\dist\agent-service\SafeGuardAgent.exe
```
