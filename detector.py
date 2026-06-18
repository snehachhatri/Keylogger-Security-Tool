"""
===========================================
KEYLOGGER DETECTION TOOL - DEFENSIVE SECURITY
===========================================
Author  : Sneha Chhatri
Purpose : Detects keyloggers via 3 methods:
          1. Process Monitoring
          2. File System Monitoring
          3. Network Traffic Monitoring
Warning : Use only on your own system!
===========================================
"""

import os
import psutil
from datetime import datetime

# ─────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────

# Keywords that suggest a suspicious process
SUSPICIOUS_PROCESSES = [
    "keylog", "logger", "spy", "hook",
    "monitor", "record", "capture", "stealer"
]

# Locations where keyloggers commonly hide
SUSPICIOUS_LOCATIONS = [
    os.path.expanduser("~\\AppData\\Roaming"),
    os.path.expanduser("~\\AppData\\Local\\Temp"),
    os.path.expanduser("~\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"),
    "C:\\Windows\\Temp",
    "C:\\ProgramData"
]

# File extensions commonly used by keyloggers
SUSPICIOUS_EXTENSIONS = [".log", ".txt", ".dat"]

# Known safe file patterns to avoid false positives
SAFE_PATTERNS = [
    "desktop-", "python", "mat-debug", "mpcmd",
    "office", "vcredist", "squirrel", "javalaunch",
    "fxs", "sdx", "structured"
]

# Keywords that suggest a keylog file
KEYLOG_KEYWORDS = ["keylog", "keystroke", "keyboard_log", "klog"]

# Ports commonly used by keyloggers to exfiltrate data
SUSPICIOUS_PORTS = [587, 465, 25, 4444, 1337]

# Store all findings
results = {
    "suspicious_processes": [],
    "suspicious_files": [],
    "suspicious_connections": []
}


# ─────────────────────────────────────────
# 1. PROCESS MONITORING
# ─────────────────────────────────────────
def scan_processes() -> None:
    """Scan all running processes for suspicious names."""
    print("\n[*] Scanning running processes...")

    for proc in psutil.process_iter(['pid', 'name']):
        try:
            proc_name = proc.info['name'].lower()
            proc_id   = proc.info['pid']

            for keyword in SUSPICIOUS_PROCESSES:
                if keyword in proc_name:
                    entry = f"PID {proc_id} — {proc.info['name']}"
                    results["suspicious_processes"].append(entry)
                    print(f"  [!] Suspicious process: {entry}")

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    if not results["suspicious_processes"]:
        print("  [✓] No suspicious processes found")


# ─────────────────────────────────────────
# 2. FILE SYSTEM MONITORING
# ─────────────────────────────────────────
def scan_files() -> None:
    """Scan common keylogger hiding spots for suspicious files."""
    print("\n[*] Scanning file system...")

    # Check suspicious locations for log/data files
    for location in SUSPICIOUS_LOCATIONS:
        if not os.path.exists(location):
            continue

        for filename in os.listdir(location):
            ext = os.path.splitext(filename)[1].lower()

            if ext not in SUSPICIOUS_EXTENSIONS:
                continue

            # Skip known safe Windows system files
            if any(pattern in filename.lower() for pattern in SAFE_PATTERNS):
                continue

            full_path = os.path.join(location, filename)
            results["suspicious_files"].append(full_path)
            print(f"  [!] Suspicious file: {full_path}")

    # Check startup folder — keyloggers persist here
    startup_folder = os.path.expanduser(
        "~\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"
    )
    if os.path.exists(startup_folder):
        for filename in os.listdir(startup_folder):
            full_path = os.path.join(startup_folder, filename)
            results["suspicious_files"].append(full_path)
            print(f"  [!] Startup entry found: {full_path}")

    # Search common user folders for keylog files by name
    user_folders = [
        os.path.expanduser("~\\Desktop"),
        os.path.expanduser("~\\Documents"),
        os.path.expanduser("~\\Downloads"),
        os.path.expanduser("~\\AppData\\Roaming"),
        os.path.expanduser("~\\AppData\\Local\\Temp"),
    ]

    for folder in user_folders:
        if not os.path.exists(folder):
            continue
        for filename in os.listdir(folder):
            if any(kw in filename.lower() for kw in KEYLOG_KEYWORDS):
                full_path = os.path.join(folder, filename)
                results["suspicious_files"].append(full_path)
                print(f"  [!] Keylog file found: {full_path}")

    if not results["suspicious_files"]:
        print("  [✓] No suspicious files found")


# ─────────────────────────────────────────
# 3. NETWORK TRAFFIC MONITORING
# ─────────────────────────────────────────
def scan_network() -> None:
    """Check for suspicious outgoing connections on known exfiltration ports."""
    print("\n[*] Scanning network connections...")

    for conn in psutil.net_connections(kind='inet'):
        try:
            if conn.raddr and conn.raddr.port in SUSPICIOUS_PORTS:
                try:
                    proc_name = psutil.Process(conn.pid).name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    proc_name = "Unknown"

                entry = f"{proc_name} (PID {conn.pid}) → {conn.raddr.ip}:{conn.raddr.port}"
                results["suspicious_connections"].append(entry)
                print(f"  [!] Suspicious connection: {entry}")

        except Exception:
            pass

    if not results["suspicious_connections"]:
        print("  [✓] No suspicious network connections found")


# ─────────────────────────────────────────
# 4. HTML REPORT GENERATOR
# ─────────────────────────────────────────
def generate_report() -> None:
    """Generate a professional dark-themed HTML report with all findings."""
    total_threats = (
        len(results['suspicious_processes']) +
        len(results['suspicious_files']) +
        len(results['suspicious_connections'])
    )
    threat_level = (
        "HIGH 🔴" if total_threats > 5 else
        "MEDIUM 🟡" if total_threats > 0 else
        "SAFE 🟢"
    )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Detection Report</title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@400;600;700&display=swap');
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Rajdhani', sans-serif; background: #050f05; color: #c8ffc8; min-height: 100vh; }}
        body::before {{ content: ''; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(0,255,70,0.03) 2px, rgba(0,255,70,0.03) 4px); pointer-events: none; z-index: 1000; }}
        .header {{ background: linear-gradient(135deg, #050f05, #0a1f0a); padding: 40px; border-bottom: 1px solid #00ff4433; position: relative; }}
        .header::after {{ content: ''; position: absolute; bottom: 0; left: 0; width: 100%; height: 1px; background: linear-gradient(90deg, transparent, #00ff44, transparent); }}
        .header-top {{ display: flex; align-items: center; gap: 16px; margin-bottom: 8px; }}
        .header h1 {{ font-family: 'Share Tech Mono', monospace; font-size: 26px; color: #00ff44; letter-spacing: 4px; text-shadow: 0 0 20px #00ff4466; }}
        .header p {{ color: #4a7a4a; font-size: 13px; letter-spacing: 2px; font-family: 'Share Tech Mono', monospace; }}
        .blink {{ animation: blink 1s infinite; color: #00ff44; }}
        @keyframes blink {{ 0%, 100% {{ opacity: 1; }} 50% {{ opacity: 0; }} }}
        .threat-banner {{ margin: 30px 40px; background: #0a1a0a; border-radius: 12px; padding: 24px 30px; display: flex; align-items: center; justify-content: space-between; border: 1px solid #00ff4422; position: relative; overflow: hidden; }}
        .threat-banner::before {{ content: ''; position: absolute; top: 0; left: 0; right: 0; height: 2px; background: linear-gradient(90deg, transparent, #00ff44, transparent); }}
        .threat-label {{ font-size: 11px; color: #4a7a4a; text-transform: uppercase; letter-spacing: 3px; font-family: 'Share Tech Mono', monospace; }}
        .threat-value {{ font-size: 28px; font-weight: 700; margin-top: 6px; color: #00ff44; text-shadow: 0 0 15px #00ff4466; }}
        .threat-time .label {{ font-size: 11px; color: #4a7a4a; letter-spacing: 2px; font-family: 'Share Tech Mono', monospace; }}
        .threat-time .value {{ font-size: 13px; color: #7aaa7a; margin-top: 6px; font-family: 'Share Tech Mono', monospace; }}
        .stats {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px; margin: 0 40px 30px; }}
        .stat-card {{ background: #0a1a0a; border-radius: 12px; padding: 24px; border: 1px solid #00ff4411; position: relative; overflow: hidden; }}
        .stat-card::before {{ content: ''; position: absolute; top: 0; left: 0; right: 0; height: 2px; }}
        .stat-card.process::before {{ background: linear-gradient(90deg, #00ff44, #00cc33); }}
        .stat-card.file::before {{ background: linear-gradient(90deg, #ffaa00, #ff7700); }}
        .stat-card.network::before {{ background: linear-gradient(90deg, #00ffaa, #00ccaa); }}
        .stat-num {{ font-size: 48px; font-weight: 700; font-family: 'Share Tech Mono', monospace; }}
        .stat-card.process .stat-num {{ color: #00ff44; text-shadow: 0 0 20px #00ff4466; }}
        .stat-card.file .stat-num {{ color: #ffaa00; text-shadow: 0 0 20px #ffaa0066; }}
        .stat-card.network .stat-num {{ color: #00ffaa; text-shadow: 0 0 20px #00ffaa66; }}
        .stat-label {{ font-size: 11px; color: #4a7a4a; margin-top: 8px; text-transform: uppercase; letter-spacing: 2px; font-family: 'Share Tech Mono', monospace; }}
        .stat-icon {{ font-size: 28px; position: absolute; right: 20px; top: 20px; opacity: 0.2; }}
        .section {{ margin: 0 40px 30px; }}
        .section-title {{ font-size: 11px; font-weight: 600; color: #00ff44; text-transform: uppercase; letter-spacing: 3px; margin-bottom: 14px; display: flex; align-items: center; gap: 12px; font-family: 'Share Tech Mono', monospace; }}
        .section-title::before {{ content: '>>'; color: #00ff4466; }}
        .section-title::after {{ content: ''; flex: 1; height: 1px; background: linear-gradient(90deg, #00ff4422, transparent); }}
        .item-card {{ background: #0a1a0a; border-radius: 8px; padding: 12px 16px; margin-bottom: 6px; border: 1px solid #00ff4411; display: flex; align-items: center; gap: 12px; font-size: 13px; font-family: 'Share Tech Mono', monospace; }}
        .item-card.danger {{ border-left: 3px solid #ff4444; background: #1a0a0a; }}
        .item-card.safe {{ border-left: 3px solid #00ff44; color: #00ff44; }}
        .item-dot {{ width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0; }}
        .dot-danger {{ background: #ff4444; box-shadow: 0 0 8px #ff4444; animation: pulse 2s infinite; }}
        .dot-safe {{ background: #00ff44; box-shadow: 0 0 8px #00ff44; }}
        @keyframes pulse {{ 0%, 100% {{ opacity: 1; }} 50% {{ opacity: 0.3; }} }}
        .item-text {{ flex: 1; word-break: break-all; color: #aaccaa; }}
        .item-card.safe .item-text {{ color: #00ff44; }}
        .item-badge {{ font-size: 10px; padding: 2px 8px; border-radius: 4px; white-space: nowrap; flex-shrink: 0; letter-spacing: 1px; }}
        .badge-danger {{ background: #ff444422; color: #ff4444; border: 1px solid #ff444444; }}
        .badge-safe {{ background: #00ff4422; color: #00ff44; border: 1px solid #00ff4444; }}
        .footer {{ margin: 40px; padding: 20px 0; border-top: 1px solid #00ff4411; display: flex; justify-content: space-between; font-family: 'Share Tech Mono', monospace; }}
        .footer-left {{ font-size: 11px; color: #2a4a2a; }}
        .footer-right {{ font-size: 11px; color: #2a4a2a; }}
    </style>
</head>
<body>
<div class="header">
    <div class="header-top"><span class="blink">▮</span><h1>KEYLOGGER DETECTION REPORT</h1></div>
    <p>// DEFENSIVE SECURITY SCANNER — POWERED BY PYTHON + PSUTIL</p>
</div>
<div class="threat-banner">
    <div><div class="threat-label">// threat level</div><div class="threat-value">{threat_level}</div></div>
    <div><div class="threat-label">// total threats</div><div class="threat-value">{total_threats}</div></div>
    <div class="threat-time"><div class="label">// scan completed</div><div class="value">{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div></div>
</div>
<div class="stats">
    <div class="stat-card process"><div class="stat-icon">⚙️</div><div class="stat-num">{len(results['suspicious_processes'])}</div><div class="stat-label">// suspicious processes</div></div>
    <div class="stat-card file"><div class="stat-icon">📁</div><div class="stat-num">{len(results['suspicious_files'])}</div><div class="stat-label">// suspicious files</div></div>
    <div class="stat-card network"><div class="stat-icon">🌐</div><div class="stat-num">{len(results['suspicious_connections'])}</div><div class="stat-label">// suspicious connections</div></div>
</div>
<div class="section">
    <div class="section-title">suspicious processes</div>
    {"".join(f'<div class="item-card danger"><div class="item-dot dot-danger"></div><div class="item-text">{p}</div><span class="item-badge badge-danger">PROCESS</span></div>' for p in results["suspicious_processes"]) if results["suspicious_processes"] else '<div class="item-card safe"><div class="item-dot dot-safe"></div><div class="item-text">no suspicious processes detected</div><span class="item-badge badge-safe">CLEAN</span></div>'}
</div>
<div class="section">
    <div class="section-title">suspicious files</div>
    {"".join(f'<div class="item-card danger"><div class="item-dot dot-danger"></div><div class="item-text">{f}</div><span class="item-badge badge-danger">FILE</span></div>' for f in results["suspicious_files"]) if results["suspicious_files"] else '<div class="item-card safe"><div class="item-dot dot-safe"></div><div class="item-text">no suspicious files detected</div><span class="item-badge badge-safe">CLEAN</span></div>'}
</div>
<div class="section">
    <div class="section-title">suspicious network connections</div>
    {"".join(f'<div class="item-card danger"><div class="item-dot dot-danger"></div><div class="item-text">{c}</div><span class="item-badge badge-danger">NETWORK</span></div>' for c in results["suspicious_connections"]) if results["suspicious_connections"] else '<div class="item-card safe"><div class="item-dot dot-safe"></div><div class="item-text">no suspicious connections detected</div><span class="item-badge badge-safe">CLEAN</span></div>'}
</div>
<div class="footer">
    <div class="footer-left">// keylogger detection tool — educational purposes only</div>
    <div class="footer-right">// built by sneha chhatri</div>
</div>
</body>
</html>"""

    with open("detection_report.html", "w", encoding="utf-8") as f:
        f.write(html)
    print("\n[*] Report saved → detection_report.html")


# ─────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────
def main() -> None:
    """Run all detection scans and generate report."""
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
    print(f"  Suspicious Processes  : {len(results['suspicious_processes'])}")
    print(f"  Suspicious Files      : {len(results['suspicious_files'])}")
    print(f"  Suspicious Connections: {len(results['suspicious_connections'])}")
    print("=" * 40)

    generate_report()
    print("\n[*] Scan complete!")


if __name__ == "__main__":
    main()