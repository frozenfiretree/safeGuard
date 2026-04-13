@echo off
setlocal

set ROOT_DIR=%~dp0
set SERVER_DIR=%ROOT_DIR%server
set PYTHON_EXE=D:\anaconda3\envs\scanocr\python.exe

if not exist "%PYTHON_EXE%" (
  set PYTHON_EXE=python
)

cd /d "%SERVER_DIR%" || goto :error

echo Starting SafeGuard OCR service at http://127.0.0.1:8010
echo The service will use server\artifacts\models\paddlex_models or extract server\artifacts\models.zip automatically.
echo GPU mode: %SAFEGUARD_OCR_USE_GPU%  GPU id: %SAFEGUARD_OCR_GPU_ID%

"%PYTHON_EXE%" -c "import sys; print('Python:', sys.executable); import paddle; print('Paddle:', paddle.__version__, 'CUDA compiled:', paddle.device.is_compiled_with_cuda(), 'CUDA devices:', paddle.device.cuda.device_count() if paddle.device.is_compiled_with_cuda() else 0)" 2>nul
if errorlevel 1 (
  echo Paddle CUDA check failed. OCR service may fall back to CPU.
)

for /f "tokens=5" %%p in ('netstat -ano ^| findstr ":8010" ^| findstr "LISTENING"') do (
  echo OCR service already appears to be running on port 8010, PID %%p.
  echo If you want to restart it, run stop_ocr_service.bat first.
  exit /b 0
)

"%PYTHON_EXE%" -m uvicorn ocr_service:app --host 127.0.0.1 --port 8010 --reload
goto :eof

:error
echo Failed to start OCR service.
exit /b 1
