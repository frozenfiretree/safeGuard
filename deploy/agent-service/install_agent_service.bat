@echo off
setlocal
powershell -ExecutionPolicy Bypass -File "%~dp0install_agent_service.ps1" %*
exit /b %errorlevel%
