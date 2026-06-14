import subprocess
import time
import signal
import sys
import os
import platform

# -----------------------------
# Sipar Security — Version 3.0
# run_soc.py
# Cross-platform launcher.
# Supports Linux, Windows, Termux
# -----------------------------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
OS       = platform.system()   # "Linux", "Windows", "Darwin"

# -----------------------------
# PLATFORM CHECK
# -----------------------------
def check_privileges():
    """
    Ensure the script is running with the required privileges.
    - Linux / macOS / Termux : must be root (sudo)
    - Windows                : must be Administrator
    Raw socket operations (Scapy ARP + packet sniffing)
    require elevated privileges on all platforms.
    """
    if OS == "Windows":
        import ctypes
        is_admin = ctypes.windll.shell32.IsUserAnAdmin()
        if not is_admin:
            print("[!] ERROR: Please run as Administrator on Windows.")
            print("    Right-click run_soc.py -> 'Run as administrator'")
            print("    Or open Command Prompt as Administrator and run:")
            print("    python run_soc.py")
            sys.exit(1)
    else:
        if os.geteuid() != 0:
            print("[!] ERROR: Please run with sudo on Linux/macOS/Termux.")
            print("    sudo python3 run_soc.py")
            sys.exit(1)


def launch(cmd):
    """
    Launch a child process from BASE_DIR.
    On Linux/macOS: run directly (already root from sudo).
    On Windows    : run directly (already Administrator).
    No sudo prefix needed — the parent process is already elevated.
    """
    return subprocess.Popen(cmd, cwd=BASE_DIR)


# -----------------------------
# PRIVILEGE CHECK
# -----------------------------
check_privileges()

print("[+] Starting Sipar Security SOC...")
print(f"[+] Platform     : {OS}")
print(f"[+] Base directory: {BASE_DIR}")
print()

# -----------------------------
# STARTUP ORDER
# -----------------------------
# Windows needs longer startup delays — processes are slower to initialize
DELAY_SERVER    = 3 if OS == "Windows" else 2
DELAY_SCANNER   = 4 if OS == "Windows" else 3
DELAY_DASHBOARD = 2 if OS == "Windows" else 1

print("[1/3] Starting event server...")
event_server = launch(["python3", "event_server.py"] if OS != "Windows"
                      else ["python", "event_server.py"])
time.sleep(DELAY_SERVER)

print("[2/3] Starting network scanner...")
ids_process = launch(["python3", "network_scan.py"] if OS != "Windows"
                     else ["python", "network_scan.py"])
time.sleep(DELAY_SCANNER)

print("[3/3] Starting dashboard...")
dashboard_process = launch(["python3", "dashboard.py"] if OS != "Windows"
                           else ["python", "dashboard.py"])
time.sleep(DELAY_DASHBOARD)

print()
# Detect local IP for phone/browser access info
def get_local_ip():
    import socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "YOUR_IP"

local_ip = get_local_ip()

print("[+] Sipar Security SOC running")
print()
print("[+] LOCAL ACCESS (this machine)")
print(f"    Dashboard  -> http://127.0.0.1:5000")
print(f"    API        -> http://127.0.0.1:5050")
print()
print("[+] NETWORK ACCESS (phone, tablet, other devices on same WiFi)")
print(f"    Dashboard  -> http://{local_ip}:5000")
print(f"    API        -> http://{local_ip}:5050")
print()
print("[+] Press Ctrl+C to stop")
print()

# -----------------------------
# HEALTH MONITOR
# -----------------------------
def check_process(proc, name):
    if proc.poll() is not None:
        print(f"[!] WARNING: {name} has stopped (exit code {proc.returncode})")
        return False
    return True


# -----------------------------
# CLEAN SHUTDOWN
# -----------------------------
def shutdown(sig, frame):
    print("\n[+] Stopping Sipar Security SOC...")

    for proc in [dashboard_process, ids_process, event_server]:
        try:
            proc.terminate()
        except Exception:
            pass

    deadline = time.time() + 3
    for proc, name in [
        (dashboard_process, "dashboard"),
        (ids_process,       "network_scan"),
        (event_server,      "event_server")
    ]:
        remaining = max(0, deadline - time.time())
        try:
            proc.wait(timeout=remaining)
        except subprocess.TimeoutExpired:
            print(f"[!] Force killing {name}...")
            proc.kill()

    print("[+] All processes stopped.")
    sys.exit(0)


signal.signal(signal.SIGINT,  shutdown)
signal.signal(signal.SIGTERM, shutdown)

# -----------------------------
# KEEP ALIVE + HEALTH CHECK
# -----------------------------
CHECK_INTERVAL = 30
last_check     = time.time()

while True:
    time.sleep(1)
    if time.time() - last_check >= CHECK_INTERVAL:
        check_process(event_server,      "event_server")
        check_process(ids_process,       "network_scan")
        check_process(dashboard_process, "dashboard")
        last_check = time.time()