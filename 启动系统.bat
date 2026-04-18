@echo off
chcp 65001 >nul
echo ============================================
echo SafeGuard 安全监控系统
echo ============================================
echo.
echo Python路径: D:\anaconda3\envs\scanocr\python.exe
echo.

:: 使用conda的Python
D:\anaconda3\envs\scanocr\python.exe start_all.py

pause
