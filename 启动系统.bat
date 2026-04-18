@echo off
chcp 65001 >nul
echo ============================================
echo SafeGuard 安全监控系统
echo ============================================
echo.

conda activate scanocr
python start_all.py

pause
