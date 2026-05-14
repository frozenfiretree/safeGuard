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
  Installs the service, writes the main install config file, enables auto start, and sets SCM failure actions.
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
  -WorkDir C:\ProgramData\SafeGuardAgent `
  -GrpcUploadTarget 192.168.175.1:50051
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
  "work_dir": "C:\\ProgramData\\SafeGuardAgent",
  "grpc_upload_target": "192.168.175.1:50051"
}
```

The install script configures:

- install settings file: `C:\ProgramData\SafeGuardAgent\install_config.json`
- service start mode: `auto`
- SCM failure actions:
  - first failure -> restart after 60s
  - second failure -> restart after 60s
  - subsequent failures -> restart after 300s

## Configuration Priority

The agent resolves base connection settings in one place. Priority is:

1. command line flags, such as `--server-base`, `--work-dir`, `--grpc-upload-target`
2. environment variables, kept only for compatibility: `SAFEGUARD_SERVER_BASE`, `SAFEGUARD_AGENT_WORKDIR`, `SAFEGUARD_GRPC_UPLOAD_TARGET`
3. main install config file: `C:\ProgramData\SafeGuardAgent\install_config.json`
4. packaged defaults file next to the EXE: `agent-install.json`
5. built-in defaults

New installs use `install_config.json` as the single main persistent source. The installer does not write machine-level environment variables. On startup, the agent writes the effective base config, field sources, and any ignored conflicting sources to `C:\ProgramData\SafeGuardAgent\logs\agent.log`.

Self-check after install:

```powershell
sc.exe query SafeGuardAgent
Get-Content C:\ProgramData\SafeGuardAgent\install_config.json
Get-Content C:\ProgramData\SafeGuardAgent\logs\agent.log -Tail 80
```

## Remove

```powershell
powershell -ExecutionPolicy Bypass -File deploy\agent-service\uninstall_agent_service.ps1 `
  -ExePath D:\work\safeGuard\dist\agent-service\SafeGuardAgent.exe
```
