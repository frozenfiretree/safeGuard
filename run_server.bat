@echo off
setlocal

set ROOT_DIR=%~dp0
set SERVER_DIR=%ROOT_DIR%server
set PYTHON_EXE=D:\anaconda3\envs\scanocr\python.exe

if not exist "%PYTHON_EXE%" (
  set PYTHON_EXE=python
)

cd /d "%SERVER_DIR%" || goto :error

if "%SAFEGUARD_ADMIN_TOKEN%"=="" (
  set SAFEGUARD_ADMIN_TOKEN=dev-admin-token
)

echo Starting SafeGuard server in development-compatible mode.
echo Admin token: %SAFEGUARD_ADMIN_TOKEN%
echo Set SAFEGUARD_REQUIRE_PRODUCTION_DEPS=true to require PostgreSQL/Redis/MinIO.

"%PYTHON_EXE%" -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload
goto :eof

:error
echo Failed to start server.
exit /b 1
