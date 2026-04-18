#!/usr/bin/env python3
"""启动SafeGuard完整系统（后端+前端）"""
import subprocess
import sys
import os
import time
import signal

def start_backend():
    """启动后端服务"""
    os.chdir(r"D:\work\safeGuard\server")
    return subprocess.Popen([sys.executable, "main.py"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

def start_frontend():
    """启动前端开发服务器"""
    os.chdir(r"D:\work\safeGuard\frontend")
    return subprocess.Popen(["npm", "run", "dev"], shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

def main():
    backend_proc = None
    frontend_proc = None

    def cleanup(signum=None, frame=None):
        print("\n正在关闭服务...")
        if frontend_proc:
            frontend_proc.terminate()
            frontend_proc.wait()
        if backend_proc:
            backend_proc.terminate()
            backend_proc.wait()
        print("服务已关闭")
        sys.exit(0)

    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)

    print("="*60)
    print("SafeGuard 安全监控系统")
    print("="*60)

    # 启动后端
    print("\n[1/2] 启动后端服务...")
    backend_proc = start_backend()

    # 等待后端启动
    for i in range(10):
        time.sleep(0.5)
        print(f"  等待后端启动... {i+1}/10")
        if backend_proc.poll() is not None:
            print("后端启动失败！")
            cleanup()
            return

    print("  后端服务已启动 (http://localhost:8000)")

    # 启动前端
    print("\n[2/2] 启动前端开发服务器...")
    frontend_proc = start_frontend()

    print("  前端服务正在启动...")

    print("\n" + "="*60)
    print("系统访问地址:")
    print("  - 前端界面: http://localhost:5173")
    print("  - 后端API:  http://localhost:8000")
    print("="*60)
    print("\n按 Ctrl+C 停止服务")
    print()

    # 等待进程
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        cleanup()

if __name__ == "__main__":
    main()
