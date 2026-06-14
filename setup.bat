@echo off
:: ================================================
:: Sipar Security — Version 3.0
:: setup.bat
:: One-command installer for Windows
:: ================================================
:: Usage:
::   Right-click setup.bat -> Run as Administrator
:: ================================================

echo.
echo ================================================
echo   Sipar Security -- Version 3.0
echo   Setup Script for Windows
echo ================================================
echo.

:: -----------------------------
:: CHECK ADMINISTRATOR
:: -----------------------------
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [!] ERROR: Please run as Administrator.
    echo     Right-click setup.bat and select "Run as administrator"
    pause
    exit /b 1
)
echo [+] Running as Administrator. OK.

:: -----------------------------
:: CHECK PYTHON
:: -----------------------------
echo [+] Checking Python...
python --version >nul 2>&1
if %errorLevel% neq 0 (
    echo [!] Python not found.
    echo     Please download and install Python from:
    echo     https://www.python.org/downloads/
    echo     Make sure to check "Add Python to PATH" during install.
    pause
    exit /b 1
)
for /f "tokens=*" %%i in ('python --version') do echo [+] Found: %%i

:: -----------------------------
:: CHECK NPCAP
:: -----------------------------
echo [+] Checking Npcap...
if exist "C:\Windows\System32\Npcap\wpcap.dll" (
    echo [+] Npcap found.
) else if exist "C:\Windows\System32\wpcap.dll" (
    echo [+] WinPcap found.
) else (
    echo [!] Npcap not found.
    echo     Npcap is required for network scanning on Windows.
    echo     Please download and install from:
    echo     https://npcap.com/#download
    echo     During install, check "Install Npcap in WinPcap API-compatible Mode"
    echo.
    echo     After installing Npcap, re-run this setup.
    pause
    exit /b 1
)

:: -----------------------------
:: INSTALL DEPENDENCIES
:: -----------------------------
echo.
echo [+] Installing Python dependencies...
echo.
python -m pip install --upgrade pip
python -m pip install flask requests scapy netifaces

:: -----------------------------
:: VERIFY SCAPY
:: -----------------------------
echo.
echo [+] Verifying Scapy...
python -c "from scapy.all import ARP; print('[+] Scapy import OK.')" 2>nul
if %errorLevel% neq 0 (
    echo [!] Scapy import failed.
    echo     Make sure Npcap is installed and re-run this setup.
)

:: -----------------------------
:: DONE
:: -----------------------------
echo.
echo ================================================
echo   Setup complete.
echo.
echo   To run Sipar Security:
echo     Right-click run_soc.py and open with Python
echo     OR open Command Prompt as Administrator and run:
echo     python run_soc.py
echo.
echo   Then open your browser at:
echo     http://127.0.0.1:5000
echo ================================================
echo.
pause
