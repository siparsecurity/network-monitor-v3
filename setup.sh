#!/bin/bash
# ================================================
# Sipar Security — Version 3.0
# setup.sh
# One-command installer for Linux and Termux
# ================================================
# Usage:
#   chmod +x setup.sh
#   ./setup.sh
# ================================================

echo ""
echo "================================================"
echo "  Sipar Security — Version 3.0"
echo "  Setup Script for Linux / Termux"
echo "================================================"
echo ""

# -----------------------------
# DETECT ENVIRONMENT
# -----------------------------
if [ -d "/data/data/com.termux" ]; then
    ENV="termux"
    echo "[+] Environment : Termux (Android)"
else
    ENV="linux"
    echo "[+] Environment : Linux"
fi

# -----------------------------
# CHECK PYTHON
# -----------------------------
echo "[+] Checking Python..."

if ! command -v python3 &> /dev/null; then
    echo "[!] Python3 not found."
    if [ "$ENV" = "termux" ]; then
        echo "[+] Installing Python via pkg..."
        pkg install python -y
    else
        echo "[!] Please install Python3 first:"
        echo "    sudo apt install python3 python3-pip"
        exit 1
    fi
else
    PYTHON_VER=$(python3 --version)
    echo "[+] Found: $PYTHON_VER"
fi

# -----------------------------
# CHECK PIP
# -----------------------------
echo "[+] Checking pip..."

if ! command -v pip3 &> /dev/null && ! python3 -m pip --version &> /dev/null; then
    echo "[!] pip not found."
    if [ "$ENV" = "termux" ]; then
        pkg install python -y
    else
        echo "[!] Please install pip:"
        echo "    sudo apt install python3-pip"
        exit 1
    fi
else
    echo "[+] pip found."
fi

# -----------------------------
# INSTALL DEPENDENCIES
# -----------------------------
echo ""
echo "[+] Installing dependencies..."
echo ""

if [ "$ENV" = "termux" ]; then
    # Termux needs these system packages first
    pkg install libpcap nmap -y
    pip3 install flask requests scapy netifaces
else
    # Linux — use --break-system-packages for modern pip
    pip3 install flask requests scapy netifaces --break-system-packages 2>/dev/null \
        || pip3 install flask requests scapy netifaces
fi

# -----------------------------
# CHECK NPCAP / LIBPCAP
# -----------------------------
echo ""
echo "[+] Checking packet capture library..."

if python3 -c "from scapy.all import ARP" 2>/dev/null; then
    echo "[+] Scapy import OK."
else
    echo "[!] Scapy import failed."
    echo "    On Linux try: sudo apt install libpcap-dev"
    echo "    Then re-run: pip3 install scapy --break-system-packages"
fi

# -----------------------------
# DONE
# -----------------------------
echo ""
echo "================================================"
echo "  Setup complete."
echo ""
echo "  To run Sipar Security:"
if [ "$ENV" = "termux" ]; then
echo "    python3 run_soc.py"
echo "    (Termux may need tsu for root: tsu then python3 run_soc.py)"
else
echo "    sudo python3 run_soc.py"
fi
echo ""
echo "  Then open your browser at:"
echo "    http://127.0.0.1:5000"
echo "================================================"
echo ""
