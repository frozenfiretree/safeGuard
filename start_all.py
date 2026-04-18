#!/usr/bin/env python3
"""启动SafeGuard完整系统（后端+前端）"""
import subprocess
import sys
import os
import time
import signal

# 使用正确的Python路径
PYTHON = r"D:\anaconda3\envs\scanocr\python.exe"

def start_backend():
    """启动后端服务"""
    backend_dir = r"D:\work\safeGuard\server"
    print(f"  后端目录: {backend_dir}")
    return subprocess.Popen(
        [PYTHON, "main.py"],
        cwd=backend_dir,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == 'nt' else 0
    )

def start_frontend():
    """启动前端开发服务器"""
    frontend_dir = r"D:\work\safeGuard\frontend"
    print(f"  前端目录: {frontend_dir}")
    cmd = "npm run dev"
    return subprocess.Popen(
        cmd,
        cwd=frontend_dir,
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == 'nt' else 0
    )

def main():
    backend_proc = None
    frontend_proc = None

    def cleanup(signum=None, frame=None):
        print("\n正在关闭服务...")
        if frontend_proc:
            try:
                frontend_proc.terminate()
                frontend_proc.wait(timeout=5)
            except:
                pass
        if backend_proc:
            try:
                backend_proc.terminate()
                backend_proc.wait(timeout=5)
            except:
                pass
        print("服务已关闭")
        sys.exit(0)

    if os.name == 'nt':
        signal.signal(signal.SIGINT, cleanup)
        signal.signal(signal.SIGTERM, cleanup)
    else:
        signal.signal(signal.SIGINT, cleanup)
        signal.signal(signal.SIGTERM, cleanup)

    print("="*60)
    print("SafeGuard 安全监控系统")
    print("="*60)
    print(f"Python: {PYTHON}")

    # 启动后端
    print("\n[1/2] 启动后端服务...")
    try:
        backend_proc = start_backend()
    except Exception as e:
        print(f"  启动失败: {e}")
        cleanup()
        return

    # 等待后端启动
    backend_ready = False
    for i in range(15):
        time.sleep(0.5)
        print(f"  等待后端启动... {i+1}/15")

        # 检查进程是否还在运行
        if backend_proc.poll() is not None:
            print("  后端进程异常退出！")
            stdout, stderr = backend_proc.communicate()
            if stdout:
                print(f"  输出: {stdout[-2000:]}")  # 显示最后2000字符
            cleanup()
            return

        # 尝试连接后端
        if i >= 3:  # 从第2秒开始尝试连接
            try:
                import urllib.request
                req = urllib.request.Request('http://localhost:8000/health', method='GET')
                req.add_header('Accept', 'application/json')
                with urllib.request.urlopen(req, timeout=2) as response:
                    if response.status == 200:
                        backend_ready = True
                        print("  后端服务已就绪!")
                        break
            except:
                pass

    if not backend_ready:
        print("  后端启动超时！")
        cleanup()
        return

    print("  后端服务已启动 (http://localhost:8000)")

    # 启动前端
    print("\n[2/2] 启动前端开发服务器...")
    try:
        frontend_proc = start_frontend()
    except Exception as e:
        print(f"  前端启动失败: {e}")
        cleanup()
        return

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
