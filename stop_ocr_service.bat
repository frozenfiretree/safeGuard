@echo off
setlocal

set OCR_PORT=8010
set FOUND=

for /f "tokens=5" %%p in ('netstat -ano ^| findstr ":%OCR_PORT%" ^| findstr "LISTENING"') do (
  set FOUND=1
  echo Stopping OCR service process PID %%p on port %OCR_PORT%...
  taskkill /PID %%p /T /F
)

if "%FOUND%"=="" (
  echo No OCR service process is listening on port %OCR_PORT%.
)

endlocal
