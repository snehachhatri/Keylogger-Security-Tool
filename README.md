# 🔐 Keylogger Security Tool

A Python-based educational security project demonstrating both **offensive** and **defensive** cybersecurity techniques — a keylogger that records keystrokes and an intelligent detection tool that finds it.

---

## ⚠️ Disclaimer
This tool is for **educational purposes only**.
Use only on your own system. Unauthorized use is illegal and unethical.

---

## 📁 Project Structure
Keylogger-Security-Tool/

├── keylogger.py       ← Records keypresses + sends email report

├── detector.py        ← Detects keyloggers via 3 scanning methods

├── .env               ← Email credentials (never pushed to GitHub)

└── detection_report.html  ← Auto-generated scan report

---

## ⚡ Features

### 🔴 Keylogger (Offensive)
- Records all keypresses with timestamp
- Captures special keys (Enter, Backspace, Caps Lock etc.)
- Saves logs to local file automatically
- Sends email report every 60 seconds
- Secure credentials via environment variables

### 🟢 Detection Tool (Defensive)
- **Process Monitoring** — scans all running processes for suspicious names
- **File System Monitoring** — checks common keylogger hiding spots
- **Network Monitoring** — detects suspicious outgoing connections
- **Startup Folder Check** — finds programs that auto-run on boot
- **Keylog File Scanner** — searches for keylog files by name
- Generates professional **dark-themed HTML report**

---

## 🛠️ Tech Stack

| Tool | Purpose |
|---|---|
| Python 3 | Core language |
| pynput | Keyboard monitoring |
| psutil | Process + network scanning |
| smtplib | Email functionality |
| python-dotenv | Secure credential management |
| threading | Background email timer |
| HTML/CSS | Report generation |

---

## ⚙️ Requirements

```bash
pip install pynput psutil python-dotenv
```

---

## 🔧 Setup

**Step 1 — Clone the repo**
```bash
git clone https://github.com/snehachhatri/Keylogger-Security-Tool.git
cd Keylogger-Security-Tool
```

**Step 2 — Install dependencies**
```bash
pip install pynput psutil python-dotenv
```

**Step 3 — Create `.env` file**

EMAIL_ADDRESS=your@gmail.com
EMAIL_PASSWORD=your-app-password

> Get Gmail App Password: Google Account → Security → 2-Step Verification → App Passwords

---

## 🚀 How to Run

### Run Keylogger
```bash
python keylogger.py
```
Press **ESC** to stop. Logs saved to `keylog.txt`.

### Run Detection Tool
```bash
python detector.py
```
Opens `detection_report.html` with full scan results.

---

## 📸 Sample Output

### Keylogger — Terminal
<img width="1366" height="768" alt="image" src="https://github.com/user-attachments/assets/3f2d6aab-93ed-40a8-8151-56d76500ab83" />

### Detection Tool — HTML Report
<img width="1361" height="730" alt="image" src="https://github.com/user-attachments/assets/9eebac2e-5f53-412b-8582-52a8797e7295" />


---

## 🧠 What I Learned

- How keyloggers work at a low level using keyboard hooks
- How to detect malware using process, file, and network monitoring
- Importance of false positive filtering in security tools
- Secure credential management using environment variables
- Offensive + defensive security mindset

---

## 👩‍💻 Author
**Sneha Chhatri**
Cybersecurity Enthusiast | Final Year Student
[GitHub](https://github.com/snehachhatri)
[LinkedIn] (https://www.linkedin.com/in/sneha-chhatri-0ab424405/?skipRedirect=true)
