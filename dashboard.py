from flask import Flask
import requests

app = Flask(__name__)

EVENT_SERVER_EVENTS  = "http://127.0.0.1:5050/events"
EVENT_SERVER_DEVICES = "http://127.0.0.1:5050/devices"
EVENT_SERVER_ALERTS  = "http://127.0.0.1:5050/alerts"
EVENT_SERVER_RESET   = "http://127.0.0.1:5050/reset"

ALERT_EVENTS = {
    "NEW_DEVICE", "ROGUE_DEVICE",
    "ARP_SPOOF", "ARP_SPOOF_LOW", "ARP_SPOOF_MEDIUM", "ARP_SPOOF_HIGH",
    "DEVICE_OFFLINE", "PORT_SCAN", "DUPLICATE_MAC", "RISK_DECAY"
}

# -----------------------------
# THREAT LEVEL HELPERS
# -----------------------------
def threat_badge(level):
    styles = {
        "LOW"     : ("background:#052e16; color:#22c55e; border:1px solid #166534;",  "LOW"),
        "MEDIUM"  : ("background:#422006; color:#facc15; border:1px solid #854d0e;",  "MEDIUM"),
        "HIGH"    : ("background:#431407; color:#f97316; border:1px solid #9a3412;",  "HIGH"),
        "CRITICAL": ("background:#450a0a; color:#ef4444; border:1px solid #991b1b;",  "CRITICAL"),
    }
    style, label = styles.get(level, styles["LOW"])
    return (f'<span style="padding:2px 10px; border-radius:12px; font-size:11px; '
            f'font-weight:bold; letter-spacing:1px; {style}">{label}</span>')


def event_label(event_type):
    if "ARP_SPOOF" in event_type or event_type == "DUPLICATE_MAC":
        cls = "label-critical"
    elif event_type in ("ROGUE_DEVICE", "PORT_SCAN"):
        cls = "label-high"
    elif event_type == "NEW_DEVICE":
        cls = "label-warn"
    elif event_type == "DEVICE_OFFLINE":
        cls = "label-offline"
    elif event_type == "RISK_DECAY":
        cls = "label-decay"
    else:
        cls = "label-info"
    return f'<span class="event-label {cls}">{event_type}</span>'


@app.route("/")
def home():
    try:
        events  = requests.get(EVENT_SERVER_EVENTS,  timeout=3).json()
        devices = requests.get(EVENT_SERVER_DEVICES, timeout=3).json()
        alerts  = requests.get(EVENT_SERVER_ALERTS,  timeout=3).json()
    except:
        return """
        <!DOCTYPE html><html>
        <head><title>Sipar Security</title></head>
        <body style="background:#0b1220;color:white;font-family:Arial;margin:40px;">
            <h1 style="color:#38bdf8;">SIPAR SECURITY</h1>
            <p style="color:#ef4444;">Cannot connect to Event Server on port 5050.
            Make sure event_server.py is running.</p>
        </body></html>
        """

    # ----------------------------------------
    # STATS
    # ----------------------------------------
    total_devices  = len(devices)
    total_events   = len(events)
    online_count   = sum(1 for d in devices.values() if d.get("status") == "ONLINE")
    offline_count  = sum(1 for d in devices.values() if d.get("status") == "OFFLINE")
    critical_count = sum(1 for d in devices.values() if d.get("threat_level") == "CRITICAL")
    high_count     = sum(1 for d in devices.values() if d.get("threat_level") == "HIGH")

    # ----------------------------------------
    # DEVICE TABLE ROWS
    # ----------------------------------------
    device_rows = ""
    for ip, info in devices.items():
        risk          = info.get("risk", 0)
        status        = info.get("status", "ONLINE")
        threat_level  = info.get("threat_level", "LOW")

        status_badge = (
            '<span class="badge-online">ONLINE</span>'
            if status == "ONLINE"
            else '<span class="badge-offline">OFFLINE</span>'
        )

        device_rows += f"""
        <tr>
            <td>{ip}</td>
            <td class="mono">{info.get("mac", "")}</td>
            <td>{status_badge}</td>
            <td>{threat_badge(threat_level)}</td>
            <td>{info.get("first_seen", "—")}</td>
            <td>{info.get("last_seen",  "—")}</td>
            <td style="color:#94a3b8;">{risk}</td>
            <td>
                <button class="reset-btn"
                    onclick="resetRisk('{ip}', this)">
                    Reset
                </button>
            </td>
        </tr>
        """

    # ----------------------------------------
    # ALERT ROWS
    # ----------------------------------------
    alert_rows = ""
    for e in reversed(alerts[-30:]):
        alert_rows += f"""
        <tr>
            <td>{e.get("timestamp", "")}</td>
            <td>{event_label(e.get("event", ""))}</td>
            <td>{e.get("ip", "")}</td>
            <td class="mono">{e.get("mac", "")}</td>
            <td style="color:#94a3b8; font-size:12px;">{e.get("details", "")}</td>
            <td style="color:#94a3b8;">{e.get("risk", 0)}</td>
        </tr>
        """

    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Sipar Security</title>
        <meta http-equiv="refresh" content="5">
        <style>

            * {{ box-sizing: border-box; margin: 0; padding: 0; }}

            body {{
                background: #0b1220;
                color: #e2e8f0;
                font-family: 'Segoe UI', Arial, sans-serif;
                font-size: 14px;
                padding: 24px;
            }}

            /* ---- HEADER ---- */
            .header {{
                display: flex;
                align-items: center;
                justify-content: space-between;
                margin-bottom: 24px;
                border-bottom: 1px solid #1e293b;
                padding-bottom: 16px;
            }}

            .header h1 {{
                color: #38bdf8;
                font-size: 22px;
                letter-spacing: 2px;
            }}

            .header .subtitle {{
                color: #64748b;
                font-size: 12px;
                margin-top: 4px;
            }}

            .live-dot {{
                width: 10px; height: 10px;
                background: #22c55e;
                border-radius: 50%;
                display: inline-block;
                margin-right: 6px;
                animation: pulse 1.5s infinite;
            }}

            @keyframes pulse {{
                0%, 100% {{ opacity: 1; }}
                50%       {{ opacity: 0.3; }}
            }}

            /* ---- STAT CARDS ---- */
            .stats {{
                display: grid;
                grid-template-columns: repeat(6, 1fr);
                gap: 12px;
                margin-bottom: 24px;
            }}

            .stat-card {{
                background: #1e293b;
                border-radius: 10px;
                padding: 16px;
                text-align: center;
                border-top: 3px solid #334155;
            }}

            .stat-card.online   {{ border-top-color: #22c55e; }}
            .stat-card.offline  {{ border-top-color: #64748b; }}
            .stat-card.critical {{ border-top-color: #ef4444; }}
            .stat-card.high     {{ border-top-color: #f97316; }}
            .stat-card.events   {{ border-top-color: #38bdf8; }}
            .stat-card.devices  {{ border-top-color: #a78bfa; }}

            .stat-value {{
                font-size: 28px;
                font-weight: bold;
                color: white;
            }}

            .stat-label {{
                font-size: 11px;
                color: #64748b;
                text-transform: uppercase;
                letter-spacing: 1px;
                margin-top: 4px;
            }}

            /* ---- SECTION ---- */
            .section {{
                background: #1e293b;
                border-radius: 10px;
                padding: 20px;
                margin-bottom: 20px;
            }}

            .section h2 {{
                color: #94a3b8;
                font-size: 13px;
                text-transform: uppercase;
                letter-spacing: 1px;
                margin-bottom: 16px;
                border-bottom: 1px solid #334155;
                padding-bottom: 10px;
            }}

            /* ---- TABLES ---- */
            table {{ width: 100%; border-collapse: collapse; }}

            th {{
                background: #0f172a;
                color: #64748b;
                padding: 10px 12px;
                text-align: left;
                font-size: 11px;
                text-transform: uppercase;
                letter-spacing: 1px;
            }}

            td {{
                padding: 10px 12px;
                border-bottom: 1px solid #0f172a;
                color: #cbd5e1;
            }}

            tr:last-child td {{ border-bottom: none; }}
            tr:hover td {{ background: #0f172a; }}

            .mono {{ font-family: monospace; font-size: 12px; color: #94a3b8; }}

            /* ---- STATUS BADGES ---- */
            .badge-online {{
                background: #14532d; color: #22c55e;
                padding: 2px 10px; border-radius: 12px;
                font-size: 11px; font-weight: bold; letter-spacing: 1px;
            }}

            .badge-offline {{
                background: #1e293b; color: #64748b;
                padding: 2px 10px; border-radius: 12px;
                font-size: 11px; font-weight: bold; letter-spacing: 1px;
                border: 1px solid #334155;
            }}

            /* ---- EVENT LABELS ---- */
            .event-label {{
                padding: 2px 8px; border-radius: 4px;
                font-size: 11px; font-weight: bold; letter-spacing: 0.5px;
            }}

            .label-critical {{ background: #450a0a; color: #ef4444; }}
            .label-high     {{ background: #431407; color: #f97316; }}
            .label-warn     {{ background: #422006; color: #facc15; }}
            .label-offline  {{ background: #1e293b; color: #94a3b8; border: 1px solid #334155; }}
            .label-info     {{ background: #0c1a2e; color: #38bdf8; }}
            .label-decay    {{ background: #052e16; color: #4ade80; border: 1px solid #166534; }}

            /* ---- RESET BUTTON ---- */
            .reset-btn {{
                background: #1e293b;
                color: #64748b;
                border: 1px solid #334155;
                padding: 3px 10px;
                border-radius: 6px;
                font-size: 11px;
                cursor: pointer;
                transition: all 0.2s;
            }}

            .reset-btn:hover {{
                background: #334155;
                color: #e2e8f0;
            }}

            .reset-btn:disabled {{
                opacity: 0.4;
                cursor: not-allowed;
            }}

            /* ---- EMPTY STATE ---- */
            .empty {{
                text-align: center;
                color: #334155;
                padding: 30px;
                font-size: 13px;
            }}

        </style>
    </head>
    <body>

    <!-- HEADER -->
    <div class="header">
        <div>
            <h1>SIPAR SECURITY</h1>
            <div class="subtitle">Network Intrusion Detection System — Version 3.0</div>
        </div>
        <div style="color:#64748b; font-size:12px;">
            <span class="live-dot"></span> Live — refreshes every 5s
        </div>
    </div>

    <!-- STAT CARDS -->
    <div class="stats">
        <div class="stat-card devices">
            <div class="stat-value">{total_devices}</div>
            <div class="stat-label">Total Devices</div>
        </div>
        <div class="stat-card online">
            <div class="stat-value">{online_count}</div>
            <div class="stat-label">Online</div>
        </div>
        <div class="stat-card offline">
            <div class="stat-value">{offline_count}</div>
            <div class="stat-label">Offline</div>
        </div>
        <div class="stat-card high">
            <div class="stat-value">{high_count}</div>
            <div class="stat-label">High</div>
        </div>
        <div class="stat-card critical">
            <div class="stat-value">{critical_count}</div>
            <div class="stat-label">Critical</div>
        </div>
        <div class="stat-card events">
            <div class="stat-value">{total_events}</div>
            <div class="stat-label">Total Events</div>
        </div>
    </div>

    <!-- DEVICE INVENTORY -->
    <div class="section">
        <h2>Device Inventory</h2>
        <table>
            <tr>
                <th>IP Address</th>
                <th>MAC Address</th>
                <th>Status</th>
                <th>Threat Level</th>
                <th>First Seen</th>
                <th>Last Seen</th>
                <th>Risk</th>
                <th>Action</th>
            </tr>
            {'<tr><td colspan="8" class="empty">No devices discovered yet.</td></tr>' if not device_rows else device_rows}
        </table>
    </div>

    <!-- SECURITY ALERTS -->
    <div class="section">
        <h2>Security Alerts — Last 30</h2>
        <table>
            <tr>
                <th>Timestamp</th>
                <th>Event</th>
                <th>IP</th>
                <th>MAC</th>
                <th>Details</th>
                <th>Risk</th>
            </tr>
            {'<tr><td colspan="6" class="empty">No security alerts recorded.</td></tr>' if not alert_rows else alert_rows}
        </table>
    </div>

    <script>
    function resetRisk(ip, btn) {{
        btn.disabled = true;
        btn.textContent = '...';

        fetch('/reset_device', {{
            method: 'POST',
            headers: {{'Content-Type': 'application/json'}},
            body: JSON.stringify({{ip: ip}})
        }})
        .then(r => r.json())
        .then(data => {{
            if (data.status === 'ok') {{
                btn.textContent = 'Done';
                btn.style.color = '#22c55e';
                setTimeout(() => location.reload(), 800);
            }} else {{
                btn.textContent = 'Error';
                btn.style.color = '#ef4444';
                btn.disabled = false;
            }}
        }})
        .catch(() => {{
            btn.textContent = 'Error';
            btn.style.color = '#ef4444';
            btn.disabled = false;
        }});
    }}
    </script>

    </body>
    </html>
    """
    return html


# -----------------------------
# RESET PROXY ROUTE
# dashboard -> event_server /reset/<ip>
# -----------------------------
@app.route("/reset_device", methods=["POST"])
def reset_device():
    from flask import request, jsonify
    data = request.json or {}
    ip   = data.get("ip", "")
    if not ip:
        return jsonify({"status": "error", "message": "no ip provided"}), 400
    try:
        resp = requests.post(f"{EVENT_SERVER_RESET}/{ip}", timeout=3)
        return jsonify(resp.json())
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


if __name__ == "__main__":
    print("[+] Dashboard running at http://127.0.0.1:5000")
    app.run(host="0.0.0.0", port=5000, debug=False)