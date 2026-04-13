@echo off
setlocal


set ROOT_DIR=%~dp0
set FRONTEND_DIR=%ROOT_DIR%frontend
set SERVER_DIR=%ROOT_DIR%server
set WEBUI_DIR=%SERVER_DIR%\webui

echo [1/5] Enter frontend directory...
cd /d "%FRONTEND_DIR%" || goto :error

echo [2/5] Install frontend dependencies...
call npm install || goto :error

echo [3/5] Build frontend...
call npm run build || goto :error

echo [4/5] Recreate webui directory...
if exist "%WEBUI_DIR%" rmdir /s /q "%WEBUI_DIR%"
mkdir "%WEBUI_DIR%" || goto :error

echo [5/5] Copy dist to server\webui...
xcopy "%FRONTEND_DIR%\dist\*" "%WEBUI_DIR%\" /E /I /Y >nul || goto :error

echo Done. Frontend has been deployed to:
echo %WEBUI_DIR%
goto :eof

:error
echo Deployment failed.
exit /b 1