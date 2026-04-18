#!/usr/bin/env python3
"""单独启动SafeGuard后端服务"""
import subprocess
import sys
import os

# 使用正确的Python路径
PYTHON = r"D:\anaconda3\envs\scanocr\python.exe"

def main():
    backend_dir = r"D:\work\safeGuard\server"
    print(f"启动后端服务...")
    print(f"目录: {backend_dir}")
    print(f"Python: {PYTHON}")
    print("-" * 60)

    try:
        result = subprocess.run(
            [PYTHON, "main.py"],
            cwd=backend_dir,
            check=False
        )
        return result.returncode
    except Exception as e:
        print(f"启动失败: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
