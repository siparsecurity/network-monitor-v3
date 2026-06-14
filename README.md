# Sipar Security — Network Intrusion Detection System

A lightweight SOC-style network monitoring platform built in Python.
Automatically discovers devices, detects attacks, scores threats, and
displays everything on a live web dashboard.

---

## What It Does

- Discovers all devices on your local network via ARP scanning
- Detects new devices, rogue devices, and offline devices
- Detects ARP spoofing with confidence scoring (LOW / MEDIUM / HIGH)
- Detects duplicate MAC addresses and port scans
- Scores every device with a threat level: LOW / MEDIUM / HIGH / CRITICAL
- Risk decays automatically when a device stays clean
- Live web dashboard — accessible from any browser on the same network
- One-command startup

---

## Platform Support

| Platform | Run Tool | View Dashboard |
|---|---|---|
| Kali Linux | ✅ | ✅ |
| Ubuntu / Debian | ✅ | ✅ |
| Windows 10/11 | ✅ with Npcap | ✅ |
| Termux rooted | ✅ | ✅ |
| Termux not rooted | ❌ | ✅ browser only |
| Any phone/tablet browser | ❌ | ✅ same WiFi |

---

## Files

| File | Purpose |
|---|---|
| `run_soc.py` | Main launcher — starts all components |
| `network_scan.py` | ARP scanner + attack detection engine |
| `event_server.py` | Flask API server — stores and serves events |
| `dashboard.py` | Web dashboard |
| `attack_detector.py` | Duplicate MAC + port scan detection |
| `threat_engine.py` | Risk scoring + threat level logic |
| `setup.sh` | Installer for Linux and Termux |
| `setup.bat` | Installer for Windows |

---

## Installation

### Linux (Kali, Ubuntu, Debian)

```bash
chmod +x setup.sh
./setup.sh
```

Or manually:

```bash
pip3 install flask requests scapy netifaces --break-system-packages
```

### Windows

1. Install Python from https://www.python.org/downloads/
   - Check **"Add Python to PATH"** during install
2. Install Npcap from https://npcap.com/#download
   - Check **"Install Npcap in WinPcap API-compatible Mode"**
3. Right-click `setup.bat` → **Run as Administrator**

### Termux (Android)

```bash
chmod +x setup.sh
./setup.sh
```

---

## Running

### Linux / Termux

```bash
sudo python3 run_soc.py
```

### Windows

Open Command Prompt as Administrator:
python run_soc.py

---

## Accessing the Dashboard

After starting, the terminal will print:
[+] LOCAL ACCESS (this machine)

Dashboard  -> http://127.0.0.1:5000
[+] NETWORK ACCESS (phone, tablet, other devices on same WiFi)

Dashboard  -> http://YOUR_LOCAL_IP:5000

Open either URL in any browser.
To access from your phone, connect to the same WiFi and open the network access URL.

---

## API Endpoints

All endpoints are on port 5050.

| Endpoint | Description |
|---|---|
| `/events` | All events |
| `/devices` | All device records |
| `/alerts` | Security alerts only |
| `/alerts?level=HIGH` | Filter alerts by threat level |
| `/threats` | Devices above LOW threat level |
| `/stats` | Summary statistics |
| `/reset/<ip>` | Reset risk score for a device (POST) |
| `/logs` | Raw event log |

---

## Threat Level System

| Score | Level | Color |
|---|---|---|
| 0 – 4 | LOW | Green |
| 5 – 14 | MEDIUM | Yellow |
| 15 – 29 | HIGH | Orange |
| 30+ | CRITICAL | Red |

Risk decays automatically — every 3 consecutive clean scans with no alerts,
risk drops by 1 until it reaches 0.

---

## Requirements

- Python 3.8+
- Linux: libpcap
- Windows: Npcap
- Termux: pkg install libpcap

---

## Responsible Use

This tool is built for monitoring your own network only.
Do not use on networks you do not own or have permission to monitor.

---

## About

Built by Sipar Security — an open-source cybersecurity company from Pakistan.

- 🌐 Website: https://siparsecurity.github.io
- 💼 LinkedIn: https://linkedin.com/company/siparsecurity
- 📧 Email: siparsecurity@gmail.com
- ⭐ GitHub: https://github.com/siparsecurity
