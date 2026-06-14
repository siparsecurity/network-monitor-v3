from flask import Flask, jsonify, request
from collections import deque
from datetime import datetime
from threat_engine import get_threat_summary, get_risk_score, LEVEL_LOW
import json
import os

app = Flask(__name__)

# -----------------------------
# CONFIG
# -----------------------------
LOG_FILE = "soc_events.jsonl"

ALERT_EVENTS = {"NEW_DEVICE", "ARP_SPOOF", "ARP_SPOOF_LOW", "ARP_SPOOF_MEDIUM",
                "ARP_SPOOF_HIGH", "DEVICE_OFFLINE", "PORT_SCAN",
                "DUPLICATE_MAC", "ROGUE_DEVICE", "RISK_DECAY"}

events  = deque(maxlen=500)
devices = {}

# -----------------------------
# DEVICE STATE HELPER
# -----------------------------
def update_device_state(ip, mac, event_type, risk, timestamp):
    """
    Update device record on every incoming event.
    - first_seen is set once and never overwritten.
    - last_seen is always updated.
    - risk is cumulative (adds up across events).
    - threat_level is recalculated after every risk update.
    - status stays ONLINE until offline logic sets it.
    """
    if ip not in devices:
        summary = get_threat_summary(risk)
        devices[ip] = {
            "mac"         : mac,
            "first_seen"  : timestamp,
            "last_seen"   : timestamp,
            "status"      : "ONLINE",
            "risk"        : risk,
            "threat_level": summary["level"],
            "threat_color": summary["color"]
        }
    else:
        existing = devices[ip]

        if mac:
            existing["mac"] = mac

        existing["last_seen"] = timestamp

        new_risk = max(0, existing.get("risk", 0) + risk)
        existing["risk"] = new_risk

        summary = get_threat_summary(new_risk)
        existing["threat_level"] = summary["level"]
        existing["threat_color"] = summary["color"]

        if existing["status"] == "OFFLINE" and event_type not in ("DEVICE_OFFLINE",):
            existing["status"] = "ONLINE"

# -----------------------------
# LOAD OLD EVENTS ON STARTUP
# -----------------------------
if os.path.exists(LOG_FILE):
    try:
        with open(LOG_FILE, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                data = json.loads(line)
                events.append(data)
                ip         = data.get("ip", "")
                mac        = data.get("mac", "")
                event_type = data.get("event", "")
                risk       = data.get("risk", 0)
                timestamp  = data.get("timestamp", "")
                if ip:
                    update_device_state(ip, mac, event_type, risk, timestamp)

        print(f"[+] Loaded {len(events)} historical events")
        print(f"[+] Reconstructed {len(devices)} device records")

    except Exception as e:
        print(f"[!] Error loading logs: {e}")

# -----------------------------
# RECEIVE EVENTS FROM IDS
# -----------------------------
@app.route("/push", methods=["POST"])
def push_event():
    data = request.json or {}
    data["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    events.append(data)

    ip         = data.get("ip", "")
    mac        = data.get("mac", "")
    event_type = data.get("event", "")
    risk       = data.get("risk", 0)
    timestamp  = data["timestamp"]

    if ip:
        update_device_state(ip, mac, event_type, risk, timestamp)

    try:
        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(data) + "\n")
    except Exception as e:
        print(f"[!] Log write error: {e}")

    return {"status": "ok"}

# -----------------------------
# EVENTS API
# -----------------------------
@app.route("/events")
def get_events():
    return jsonify(list(events))

# -----------------------------
# DEVICES API
# -----------------------------
@app.route("/devices")
def get_devices():
    return jsonify(devices)

# -----------------------------
# LOG FILE API
# -----------------------------
@app.route("/logs")
def get_logs():
    try:
        data = []
        with open(LOG_FILE, "r") as f:
            for line in f:
                line = line.strip()
                if line:
                    data.append(json.loads(line))
        return jsonify(data)
    except:
        return jsonify([])

# -----------------------------
# STATS API
# -----------------------------
@app.route("/stats")
def get_stats():
    online_count   = sum(1 for d in devices.values() if d.get("status") == "ONLINE")
    offline_count  = sum(1 for d in devices.values() if d.get("status") == "OFFLINE")
    critical_count = sum(1 for d in devices.values() if d.get("threat_level") == "CRITICAL")
    high_count     = sum(1 for d in devices.values() if d.get("threat_level") == "HIGH")
    alert_count    = sum(1 for e in events if e.get("event") in ALERT_EVENTS)

    top_risk = sorted(
        [{"ip": ip, "risk": d.get("risk", 0), "threat_level": d.get("threat_level", "LOW")}
         for ip, d in devices.items()],
        key=lambda x: x["risk"],
        reverse=True
    )[:5]

    return jsonify({
        "total_devices" : len(devices),
        "online"        : online_count,
        "offline"       : offline_count,
        "critical"      : critical_count,
        "high"          : high_count,
        "total_events"  : len(events),
        "total_alerts"  : alert_count,
        "top_risk_devices": top_risk
    })

# -----------------------------
# ALERTS API
# /alerts              -> all security events
# /alerts?level=HIGH   -> filtered by threat level
# -----------------------------
@app.route("/alerts")
def get_alerts():
    level_filter = request.args.get("level", "").upper()

    alert_list = [e for e in events if e.get("event") in ALERT_EVENTS]

    if level_filter:
        # To filter by level we need to know the device risk at time of alert.
        # We use the current device threat_level as an approximation.
        filtered = []
        for e in alert_list:
            ip = e.get("ip", "")
            device = devices.get(ip, {})
            if device.get("threat_level", "LOW") == level_filter:
                filtered.append(e)
        alert_list = filtered

    return jsonify(alert_list)

# -----------------------------
# THREATS API
# /threats -> all devices above LOW
# -----------------------------
@app.route("/threats")
def get_threats():
    threat_devices = {
        ip: d for ip, d in devices.items()
        if d.get("threat_level", LEVEL_LOW) != LEVEL_LOW
    }

    # Sort by risk descending
    sorted_threats = dict(
        sorted(threat_devices.items(),
               key=lambda x: x[1].get("risk", 0),
               reverse=True)
    )

    return jsonify(sorted_threats)

# -----------------------------
# RISK RESET API
# POST /reset/<ip> -> reset risk to 0 for a device
# -----------------------------
@app.route("/reset/<path:ip>", methods=["POST"])
def reset_device(ip):
    if ip not in devices:
        return jsonify({"status": "error", "message": f"{ip} not found"}), 404

    devices[ip]["risk"]         = 0
    devices[ip]["threat_level"] = "LOW"
    devices[ip]["threat_color"] = "#22c55e"

    # Log the reset as an event
    reset_event = {
        "event"    : "RISK_RESET",
        "ip"       : ip,
        "mac"      : devices[ip].get("mac", ""),
        "details"  : "risk manually reset to 0",
        "risk"     : 0,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    events.append(reset_event)

    try:
        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(reset_event) + "\n")
    except Exception as e:
        print(f"[!] Log write error: {e}")

    print(f"[+] Risk reset for {ip}")
    return jsonify({"status": "ok", "ip": ip, "risk": 0})

# -----------------------------
# STATUS PAGE
# -----------------------------
@app.route("/")
def home():
    online  = sum(1 for d in devices.values() if d.get("status") == "ONLINE")
    offline = sum(1 for d in devices.values() if d.get("status") == "OFFLINE")

    return f"""
    <h2>Sipar Security — Event Server</h2>

    <p>Total Events : {len(events)}</p>
    <p>Total Devices: {len(devices)}</p>
    <p>Online        : {online}</p>
    <p>Offline       : {offline}</p>

    <ul>
        <li><a href="/events">/events</a></li>
        <li><a href="/devices">/devices</a></li>
        <li><a href="/logs">/logs</a></li>
        <li><a href="/stats">/stats</a></li>
        <li><a href="/alerts">/alerts</a></li>
        <li><a href="/threats">/threats</a></li>
    </ul>
    """

# -----------------------------
# START SERVER
# -----------------------------
if __name__ == "__main__":
    print("[+] Event Server running on http://127.0.0.1:5050")
    app.run(host="0.0.0.0", port=5050, debug=False)
