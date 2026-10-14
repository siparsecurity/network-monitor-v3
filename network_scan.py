from scapy.all import ARP, Ether, srp, conf
import netifaces
import ipaddress
import time
import requests
import platform
from collections import defaultdict
from threat_engine import get_risk_score
from attack_detector import check_duplicate_mac, start_port_scan_detector, start_arp_sniffer

# -----------------------------
# PLATFORM DETECTION
# -----------------------------
OS = platform.system()   # "Linux", "Windows", "Darwin" 

# -----------------------------
# CONFIG
# -----------------------------
SCAN_INTERVAL        = 7     # seconds between scans
OFFLINE_THRESHOLD    = 3     # missed scans before DEVICE_OFFLINE
SPOOF_WINDOW         = 60    # seconds window for MAC change tracking
SPOOF_ALERT_COOLDOWN = 120   # seconds before same IP can alert again

# ARP spoof confidence thresholds
# 3 distinct MACs in window  -> LOW confidence
# 4 distinct MACs in window  -> MEDIUM confidence
# 5+ distinct MACs in window -> HIGH confidence
SPOOF_CONF_LOW    = 3
SPOOF_CONF_MEDIUM = 4
SPOOF_CONF_HIGH   = 5

# Risk decay config
# After DECAY_CLEAN_SCANS consecutive scans with no alert
# for an IP, risk drops by 1. Repeats until risk hits 0.
DECAY_CLEAN_SCANS = 3

# -----------------------------
# EVENT SENDER
# -----------------------------
def send_event(event, ip, mac="", details="", risk=None):
    if risk is None:
        risk = get_risk_score(event)
    try:
        requests.post(
            "http://127.0.0.1:5050/push",
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


# -----------------------------
# AUTO NETWORK DETECTION
# Cross-platform interface detection:
# - Linux/macOS/Termux : uses netifaces + scapy conf.iface
# - Windows            : uses netifaces, skips loopback/tunnel ifaces
# -----------------------------
def detect_interface():
    """
    Return (iface_name, ip_addr, netmask) for the best available
    network interface on any platform.
    """
    if OS == "Windows":
        # On Windows, netifaces lists GUIDs as interface names.
        # Pick the first non-loopback interface that has an IPv4 address.
        for iface_name in netifaces.interfaces():
            addrs = netifaces.ifaddresses(iface_name)
            if netifaces.AF_INET not in addrs:
                continue
            ip = addrs[netifaces.AF_INET][0].get("addr", "")
            mask = addrs[netifaces.AF_INET][0].get("netmask", "")
            if ip and not ip.startswith("127."):
                return iface_name, ip, mask
        raise RuntimeError("No suitable network interface found on Windows.")
    else:
        # Linux / macOS / Termux
        iface_name = str(conf.iface)
        addrs      = netifaces.ifaddresses(iface_name)
        ip         = addrs[netifaces.AF_INET][0]["addr"]
        mask       = addrs[netifaces.AF_INET][0]["netmask"]
        return iface_name, ip, mask


iface, ip_addr, netmask = detect_interface()

network = ipaddress.IPv4Network(f"{ip_addr}/{netmask}", strict=False)
target  = str(network)

print(f"[+] Platform     : {OS}")
print(f"[+] Interface    : {iface}")
print(f"[+] IDS Running on {target}")
send_event("IDS_START", ip_addr, "", target, 0)


# -----------------------------
# SCAN FUNCTION
# -----------------------------
def scan():
    arp   = ARP(pdst=target)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    pkt   = ether / arp

    ans = srp(pkt, timeout=1, verbose=False)[0]

    result = {}
    for _, r in ans:
        result[r.psrc] = r.hwsrc

    return result


# -----------------------------
# STATE
# -----------------------------
trusted      = scan()
miss_count   = defaultdict(int)
online_state = {}

# ARP spoof tracking: ip -> list of (mac, timestamp)
mac_change_log   = defaultdict(list)
spoof_alerted_at = {}

# Rogue device tracking: MACs seen in initial scan are trusted
trusted_macs  = set(trusted.values())
rogue_alerted = set()   # IPs already flagged as rogue

# Risk decay tracking
# ip -> consecutive clean scan count (no alert events)
# Resets to 0 whenever an alert fires for that IP
clean_scan_count  = defaultdict(int)

# IPs that triggered an alert in the current scan cycle
# populated during detection, cleared at end of loop
alerted_this_scan = set()

print("\n[+] Initial Devices:")
for ip, mac in trusted.items():
    print(ip, "->", mac)
    send_event("INITIAL_DEVICE", ip, mac)
    online_state[ip] = True

print(f"[+] {len(trusted_macs)} trusted MACs recorded")

# Start port scan detector in background thread
start_port_scan_detector(interface=iface)
start_arp_sniffer(interface=iface)

print("\n[+] IDS Running...\n")


# -----------------------------
# ARP SPOOF CONFIDENCE SCORING
# -----------------------------
def get_spoof_confidence(num_macs: int) -> str:
    """
    Return confidence level string based on number of
    distinct MACs seen for one IP within SPOOF_WINDOW.

    3  -> LOW
    4  -> MEDIUM
    5+ -> HIGH
    """
    if num_macs >= SPOOF_CONF_HIGH:
        return "HIGH"
    elif num_macs >= SPOOF_CONF_MEDIUM:
        return "MEDIUM"
    else:
        return "LOW"


# -----------------------------
# MAIN LOOP
# -----------------------------
while True:
    time.sleep(SCAN_INTERVAL)
    current = scan()
    now     = time.time()

    # ----------------------------------------
    # NEW DEVICE + ROGUE DEVICE DETECTION
    # ----------------------------------------
    for ip, mac in current.items():

        # New IP not seen before
        if ip not in trusted:
            print(f"[NEW DEVICE] {ip} -> {mac}")
            send_event("NEW_DEVICE", ip, mac, "new device detected")
            alerted_this_scan.add(ip)

        trusted[ip]      = mac
        miss_count[ip]   = 0
        online_state[ip] = True

        # Rogue device: MAC not in initial trusted set
        # Only alert once per IP
        if mac not in trusted_macs and ip not in rogue_alerted:
            print(f"[ROGUE DEVICE] {ip} -> {mac} not in trusted MACs")
            send_event(
                "ROGUE_DEVICE",
                ip,
                mac,
                f"MAC {mac} was not present in initial network scan"
            )
            rogue_alerted.add(ip)
            alerted_this_scan.add(ip)

    # ----------------------------------------
    # OFFLINE DETECTION
    # ----------------------------------------
    for ip in list(trusted.keys()):
        if ip not in current:
            miss_count[ip] += 1

            if miss_count[ip] == OFFLINE_THRESHOLD:
                if online_state.get(ip, True):
                    print(f"[OFFLINE] {ip} — missed {OFFLINE_THRESHOLD} scans")
                    send_event(
                        "DEVICE_OFFLINE",
                        ip,
                        trusted[ip],
                        f"missed {OFFLINE_THRESHOLD} consecutive scans"
                    )
                    online_state[ip] = False

    # ----------------------------------------
    # HARDENED ARP SPOOF DETECTION
    # Confidence scoring based on MAC change rate.
    # ----------------------------------------
    for ip, mac in current.items():
        log = mac_change_log[ip]

        # Record MAC change only if different from last seen
        if log and log[-1][0] != mac:
            log.append((mac, now))
        elif not log:
            log.append((mac, now))

        # Trim entries outside window
        mac_change_log[ip] = [(m, t) for m, t in log if now - t <= SPOOF_WINDOW]

        recent_macs = set(m for m, t in mac_change_log[ip])
        num_macs    = len(recent_macs)

        if num_macs >= SPOOF_CONF_LOW:
            last_alert = spoof_alerted_at.get(ip, 0)

            if now - last_alert > SPOOF_ALERT_COOLDOWN:
                confidence  = get_spoof_confidence(num_macs)
                event_type  = f"ARP_SPOOF_{confidence}"
                details     = (
                    f"Confidence: {confidence} — "
                    f"{num_macs} distinct MACs in {SPOOF_WINDOW}s: {sorted(recent_macs)}"
                )

                print(f"[ALERT] {event_type}: {ip} | {details}")
                send_event(event_type, ip, mac, details)
                spoof_alerted_at[ip] = now
                alerted_this_scan.add(ip)

    # ----------------------------------------
    # DUPLICATE MAC DETECTION
    # Delegated to attack_detector
    # ----------------------------------------
    check_duplicate_mac(current)

    # ----------------------------------------
    # RISK DECAY
    # For every online device:
    #   - If it had NO alert this scan -> clean_scan_count += 1
    #   - If it had an alert           -> clean_scan_count reset to 0
    #   - Every DECAY_CLEAN_SCANS clean scans -> risk drops by 1
    #     and a RISK_DECAY event is sent
    # ----------------------------------------
    for ip in list(trusted.keys()):
        if ip not in current:
            continue   # offline devices don't decay

        if ip in alerted_this_scan:
            clean_scan_count[ip] = 0
        else:
            clean_scan_count[ip] += 1

            if clean_scan_count[ip] >= DECAY_CLEAN_SCANS:
                clean_scan_count[ip] = 0

                # Only decay if the device actually has risk
                # We ask the event server for current risk via a lightweight check
                # by sending a RISK_DECAY event with risk = -1
                # event_server.update_device_state handles negative risk correctly
                try:
                    resp = requests.get(
                        "http://127.0.0.1:5050/devices",
                        timeout=1
                    ).json()
                    current_risk = resp.get(ip, {}).get("risk", 0)
                except Exception:
                    current_risk = 1  # assume non-zero to be safe

                if current_risk > 0:
                    print(f"[DECAY] {ip} risk dropping by 1 (was {current_risk})")
                    send_event(
                        "RISK_DECAY",
                        ip,
                        trusted.get(ip, ""),
                        f"no alerts for {DECAY_CLEAN_SCANS} consecutive scans — risk reduced",
                        risk=-1
                    )

    # Reset per-scan alert tracker
    alerted_this_scan.clear()