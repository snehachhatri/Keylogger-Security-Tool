import psutil
import os
from datetime import datetime

# Suspicious process names
SUSPICIOUS_PROCESSES = [
    "keylog", "logger", "spy", "hook",
    "monitor", "record", "capture", "stealer"
]

# Suspicious file locations
SUSPICIOUS_LOCATIONS = [
    os.path.expanduser("~\\AppData\\Roaming"),
    os.path.expanduser("~\\AppData\\Local\\Temp"),
    "C:\\Windows\\Temp"
]

# Suspicious file extensions
SUSPICIOUS_EXTENSIONS = [".log", ".txt", ".dat"]
# Known safe file patterns to ignore
SAFE_PATTERNS = [
    "desktop-", "python", "mat-debug", "mpcmd",
    "office", "vcredist", "squirrel", "javalaunch",
    "fxs", "sdx", "structured"
]

# Results store
results = {
    "suspicious_processes": [],
    "suspicious_files": [],
    "suspicious_connections": []
}

# =====================
# 1. Process Monitoring
# =====================
def scan_processes():
    print("\n[*] Scanning processes...")
    for proc in psutil.process_iter(['pid', 'name', 'cpu_percent']):
        try:
            name = proc.info['name'].lower()
            pid = proc.info['pid']
            for keyword in SUSPICIOUS_PROCESSES:
                if keyword in name:
                    result = f"PID {pid} — {proc.info['name']}"
                    results["suspicious_processes"].append(result)
                    print(f"  [!] Suspicious process: {result}")
        except:
            pass

    if not results["suspicious_processes"]:
        print("  [✓] No suspicious processes found")

# =====================
# 2. File System Monitoring
# =====================
def scan_files():
    print("\n[*] Scanning suspicious file locations...")
    for location in SUSPICIOUS_LOCATIONS:
        if not os.path.exists(location):
            continue
        for file in os.listdir(location):
            ext = os.path.splitext(file)[1].lower()
            if ext in SUSPICIOUS_EXTENSIONS:
                # Skip known safe files
                if any(pattern in file.lower() for pattern in SAFE_PATTERNS):
                    continue
                full_path = os.path.join(location, file)
                results["suspicious_files"].append(full_path)
                print(f"  [!] Suspicious file: {full_path}")

    if not results["suspicious_files"]:
        print("  [✓] No suspicious files found")

# =====================
# 3. Network Monitoring
# =====================
def scan_network():
    print("\n[*] Scanning network connections...")
    for conn in psutil.net_connections(kind='inet'):
        try:
            if conn.raddr and conn.raddr.port in [587, 465, 25]:
                try:
                    proc = psutil.Process(conn.pid)
                    result = f"{proc.name()} (PID {conn.pid}) → {conn.raddr.ip}:{conn.raddr.port}"
                except:
                    result = f"PID {conn.pid} → {conn.raddr.ip}:{conn.raddr.port}"
                results["suspicious_connections"].append(result)
                print(f"  [!] Suspicious connection: {result}")
        except:
            pass

    if not results["suspicious_connections"]:
        print("  [✓] No suspicious network connections found")

# =====================
# Main
# =====================
def run_detector():
    print("=" * 40)
    print("  Keylogger Detection Tool")
    print(f"  Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 40)

    scan_processes()
    scan_files()
    scan_network()

    print("\n" + "=" * 40)
    print("SCAN SUMMARY:")
    print("=" * 40)
    print(f"  Suspicious Processes : {len(results['suspicious_processes'])}")
    print(f"  Suspicious Files     : {len(results['suspicious_files'])}")
    print(f"  Suspicious Connections: {len(results['suspicious_connections'])}")
    print("=" * 40)
    print("\n[*] Scan complete!")

run_detector()