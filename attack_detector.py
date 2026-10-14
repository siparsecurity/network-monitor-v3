# -----------------------------
# attack_detector.py
# Sipar Security — Version 3.0
# -----------------------------
# Detects network attacks:
#   - Duplicate MAC
#   - Port Scan (packet sniffing)
# -----------------------------

from collections import defaultdict
from datetime import datetime
from threat_engine import get_risk_score
import threading
import time
import requests

# -----------------------------
# CONFIG
# -----------------------------
EVENT_SERVER        = "http://127.0.0.1:5050/push"
PORT_SCAN_WINDOW    = 10    # seconds to watch for port scan activity
PORT_SCAN_THRESHOLD = 5     # distinct ports within window = port scan
COUNT_UDP           = False  # UDP has no SYN flag; counting it causes false positives

# -----------------------------
# EVENT SENDER
# -----------------------------
def send_event(event, ip, mac="", details="", risk=None):
    if risk is None:
        risk = get_risk_score(event)
    try:
        requests.post(
            EVENT_SERVER,
            json={
                "event"  : event,
                "ip"     : ip,
                "mac"    : mac,
                "details": details,
                "risk"   : risk
            },
            timeout=1
        )
    except:
        pass


# ============================================================
# DUPLICATE MAC DETECTION
# ============================================================
# State: track which IPs each MAC has been seen on
# mac -> {ip: last_seen_timestamp}  (kept across scans)
_mac_ip_seen = defaultdict(dict)

# Cooldown: mac -> last alert timestamp
# Prevents the same duplicate MAC from spamming alerts
_dup_mac_alerted_at = {}
DUP_MAC_COOLDOWN = 60   # seconds
DUP_MAC_WINDOW   = 60   # seconds: rolling window across scans


def check_duplicate_mac(scan_result: dict):
    """
    Called after every ARP scan with the full current scan result.

    scan_result format:
        { "10.0.0.1": "aa:bb:cc:dd:ee:ff", "10.0.0.2": "11:22:33:44:55:66", ... }

    Logic:
        1. Build mac -> [ip1, ip2, ...] map from current scan
        2. If any MAC maps to 2+ IPs -> DUPLICATE_MAC alert
        3. Cooldown prevents repeat alerts within DUP_MAC_COOLDOWN seconds
    """
    now = time.time()

    # Remember when each (mac, ip) pair was last seen, across scans
    for ip, mac in scan_result.items():
        if mac:
            _mac_ip_seen[mac][ip] = now

    for mac in list(_mac_ip_seen):
        # Keep only IPs seen inside the rolling window
        _mac_ip_seen[mac] = {
            ip: t for ip, t in _mac_ip_seen[mac].items()
            if now - t <= DUP_MAC_WINDOW
        }
        ips = list(_mac_ip_seen[mac])
        if not ips:
            del _mac_ip_seen[mac]
            continue

        if len(ips) >= 2:
            last_alert = _dup_mac_alerted_at.get(mac, 0)

            if now - last_alert > DUP_MAC_COOLDOWN:
                ip_list = ", ".join(sorted(ips))
                details = f"MAC {mac} seen on {len(ips)} IPs within {DUP_MAC_WINDOW}s: {ip_list}"

                print(f"[ALERT] DUPLICATE MAC: {details}")

                # Report against the first IP in the list
                send_event(
                    "DUPLICATE_MAC",
                    ips[0],
                    mac,
                    details
                )

                _dup_mac_alerted_at[mac] = now


# ============================================================
# PORT SCAN DETECTION
# ============================================================
# Uses Scapy packet sniffing — runs in a background thread.
# Watches for one IP hitting PORT_SCAN_THRESHOLD distinct
# destination ports within PORT_SCAN_WINDOW seconds.

# State: ip -> list of (port, timestamp) tuples
_port_activity   = defaultdict(list)
_portscan_alerted_at = {}
PORT_SCAN_COOLDOWN   = 120  # seconds

# Track which IPs we have already confirmed as port scanners
# so we can report which ports were probed
_port_scan_lock = threading.Lock()


def _handle_packet(pkt):
    """
    Scapy packet callback.
    Called for every captured TCP SYN or UDP packet.
    """
    try:
        from scapy.all import IP, TCP, UDP

        if not pkt.haslayer(IP):
            return

        src_ip = pkt[IP].src
        now    = time.time()
        port   = None

        if pkt.haslayer(TCP):
            # Only care about SYN packets (new connection attempts)
            if (pkt[TCP].flags & 0x12) == 0x02:
                port = pkt[TCP].dport

        elif COUNT_UDP and pkt.haslayer(UDP):
            port = pkt[UDP].dport

        if port is None:
            return

        with _port_scan_lock:
            log = _port_activity[src_ip]
            log.append((port, now))

            # Trim entries outside the window
            _port_activity[src_ip] = [
                (p, t) for p, t in log if now - t <= PORT_SCAN_WINDOW
            ]

            recent_ports = set(p for p, t in _port_activity[src_ip])

            if len(recent_ports) >= PORT_SCAN_THRESHOLD:
                last_alert = _portscan_alerted_at.get(src_ip, 0)

                if now - last_alert > PORT_SCAN_COOLDOWN:
                    port_list = sorted(recent_ports)
                    details   = (
                        f"{len(recent_ports)} distinct ports probed "
                        f"in {PORT_SCAN_WINDOW}s: {port_list}"
                    )

                    print(f"[ALERT] PORT SCAN: {src_ip} -> {details}")

                    send_event("PORT_SCAN", src_ip, "", details)

                    _portscan_alerted_at[src_ip] = now

                    # Clear log after alert so we don't re-alert on same ports
                    _port_activity[src_ip] = []

    except Exception:
        pass


def start_port_scan_detector(interface=None):
    """
    Start the Scapy packet sniffer in a background daemon thread.
    Captures TCP SYN and UDP packets only (filter = 'tcp or udp').

    Call this once from run_soc.py or network_scan.py after startup.
    The thread is a daemon so it stops automatically when the main
    process exits.

    On Windows, Scapy requires the interface in its own format.
    We resolve the interface using Scapy's own interface list
    to avoid GUID mismatch errors.
    """
    def _sniff():
        import platform
        from scapy.all import sniff, get_if_list

        kwargs = {
            "filter" : "tcp or udp",
            "prn"    : _handle_packet,
            "store"  : False
        }

        if interface and platform.system() == "Windows":
            # On Windows, resolve the correct Scapy interface name
            # by matching against Scapy's own interface list
            scapy_ifaces = get_if_list()
            matched = None
            for iface in scapy_ifaces:
                if interface.lower() in iface.lower() or iface.lower() in interface.lower():
                    matched = iface
                    break
            if matched:
                kwargs["iface"] = matched
                print(f"[+] Port scan detector listening on {matched}")
            else:
                # Cannot match interface — run without specifying iface
                # Scapy will pick the default
                print(f"[+] Port scan detector listening on default interface")
        elif interface:
            kwargs["iface"] = interface
            print(f"[+] Port scan detector listening on {interface}")
        else:
            print(f"[+] Port scan detector listening on all interfaces")

        try:
            sniff(**kwargs)
        except Exception as e:
            print(f"[!] Port scan detector error: {e}")
            print(f"[!] Port scan detection disabled — ARP and duplicate MAC detection still active")

    t = threading.Thread(target=_sniff, daemon=True, name="PortScanDetector")
    t.start()
    return t