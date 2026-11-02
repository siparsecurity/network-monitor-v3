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


# ============================================================
# THREAT LEVEL HELPERS
# ============================================================

def threat_badge(level):
    styles = {
        "LOW": (
            "background:#ecfdf5; color:#047857; "
            "border:1px solid #6ee7b7;"
        ),
        "MEDIUM": (
            "background:#fffbeb; color:#a16207; "
            "border:1px solid #fcd34d;"
        ),
        "HIGH": (
            "background:#fff7ed; color:#c2410c; "
            "border:1px solid #fdba74;"
        ),
        "CRITICAL": (
            "background:#fef2f2; color:#b91c1c; "
            "border:1px solid #fca5a5;"
        ),
    }

    style = styles.get(level, styles["LOW"])
    label = level

    return (
        f'<span class="threat-badge" style="{style}">{label}</span>'
    )


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


# ============================================================
# MAIN DASHBOARD
# ============================================================

@app.route("/")
def home():

    try:
        events = requests.get(
            EVENT_SERVER_EVENTS,
            timeout=3
        ).json()

        devices = requests.get(
            EVENT_SERVER_DEVICES,
            timeout=3
        ).json()

        alerts = requests.get(
            EVENT_SERVER_ALERTS,
            timeout=3
        ).json()

    except Exception:
        return """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Sipar Security</title>
            <style>
                body {
                    background:#f8fafc;
                    color:#111827;
                    font-family:Arial,sans-serif;
                    margin:50px;
                }

                .error-box {
                    max-width:700px;
                    margin:auto;
                    background:white;
                    border:1px solid #d1d5db;
                    border-radius:12px;
                    padding:30px;
                    box-shadow:0 4px 15px rgba(0,0,0,0.08);
                }

                h1 {
                    color:#0369a1;
                    margin-bottom:10px;
                }

                .error {
                    color:#b91c1c;
                    font-weight:600;
                }
            </style>
        </head>

        <body>
            <div class="error-box">
                <h1>SIPAR SECURITY</h1>

                <p>
                    Network Intrusion Detection System — Version 3.0
                </p>

                <p class="error">
                    Cannot connect to Event Server on port 5050.
                </p>

                <p>
                    Make sure event_server.py is running.
                </p>
            </div>
        </body>
        </html>
        """

    # ========================================================
    # STATISTICS
    # ========================================================

    total_devices = len(devices)
    total_events = len(events)

    online_count = sum(
        1 for d in devices.values()
        if d.get("status") == "ONLINE"
    )

    offline_count = sum(
        1 for d in devices.values()
        if d.get("status") == "OFFLINE"
    )

    critical_count = sum(
        1 for d in devices.values()
        if d.get("threat_level") == "CRITICAL"
    )

    high_count = sum(
        1 for d in devices.values()
        if d.get("threat_level") == "HIGH"
    )

    # ========================================================
    # DEVICE TABLE
    # ========================================================

    device_rows = ""

    for ip, info in devices.items():

        risk = info.get("risk", 0)
        status = info.get("status", "ONLINE")
        threat_level = info.get("threat_level", "LOW")

        if status == "ONLINE":
            status_badge = (
                '<span class="badge-online">ONLINE</span>'
            )
        else:
            status_badge = (
                '<span class="badge-offline">OFFLINE</span>'
            )

        device_rows += f"""
        <tr>

            <td class="ip-cell">
                {ip}
            </td>

            <td class="mono">
                {info.get("mac", "")}
            </td>

            <td>
                {status_badge}
            </td>

            <td>
                {threat_badge(threat_level)}
            </td>

            <td class="time-cell">
                {info.get("first_seen", "—")}
            </td>

            <td class="time-cell">
                {info.get("last_seen", "—")}
            </td>

            <td class="risk-cell">
                {risk}
            </td>

            <td>
                <button
                    class="reset-btn"
                    onclick="resetRisk('{ip}', this)">
                    Reset
                </button>
            </td>

        </tr>
        """

    # ========================================================
    # ALERT TABLE
    # ========================================================

    alert_rows = ""

    for e in reversed(alerts[-30:]):

        alert_rows += f"""
        <tr>

            <td class="time-cell">
                {e.get("timestamp", "")}
            </td>

            <td>
                {event_label(e.get("event", ""))}
            </td>

            <td class="ip-cell">
                {e.get("ip", "")}
            </td>

            <td class="mono">
                {e.get("mac", "")}
            </td>

            <td class="details-cell">
                {e.get("details", "")}
            </td>

            <td class="risk-cell">
                {e.get("risk", 0)}
            </td>

        </tr>
        """

    # ========================================================
    # HTML
    # ========================================================

    html = f"""
    <!DOCTYPE html>

    <html>

    <head>

        <title>Sipar Security — Network Monitor V3</title>

        <meta
            http-equiv="refresh"
            content="5"
        >

        <meta
            name="viewport"
            content="width=device-width, initial-scale=1.0"
        >

        <style>

        /* ==================================================
           GLOBAL
           ================================================== */

        * {{
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }}

        body {{

            background: #f4f7fa;

            color: #111827;

            font-family:
                "Segoe UI",
                Arial,
                Helvetica,
                sans-serif;

            font-size: 15px;

            line-height: 1.5;

            padding: 32px;

        }}


        /* ==================================================
           MAIN CONTAINER
           ================================================== */

        .dashboard-container {{

            max-width: 1800px;

            margin: 0 auto;

        }}


        /* ==================================================
           HEADER
           ================================================== */

        .header {{

            display: flex;

            align-items: center;

            justify-content: space-between;

            background: #ffffff;

            border: 1px solid #dbe3ea;

            border-left: 5px solid #0284c7;

            border-radius: 12px;

            padding: 22px 26px;

            margin-bottom: 24px;

            box-shadow:
                0 2px 8px rgba(15, 23, 42, 0.05);

        }}


        .header h1 {{

            color: #075985;

            font-size: 28px;

            font-weight: 750;

            letter-spacing: 2px;

        }}


        .header .subtitle {{

            color: #475569;

            font-size: 14px;

            margin-top: 5px;

            font-weight: 500;

        }}


        .live-status {{

            display: flex;

            align-items: center;

            gap: 8px;

            color: #334155;

            font-size: 14px;

            font-weight: 600;

            background: #f8fafc;

            border: 1px solid #dbe3ea;

            padding: 9px 14px;

            border-radius: 8px;

        }}


        .live-dot {{

            width: 10px;

            height: 10px;

            background: #16a34a;

            border-radius: 50%;

            display: inline-block;

        }}


        /* ==================================================
           STATISTICS
           ================================================== */

        .stats {{

            display: grid;

            grid-template-columns:
                repeat(6, minmax(130px, 1fr));

            gap: 14px;

            margin-bottom: 24px;

        }}


        .stat-card {{

            background: #ffffff;

            border: 1px solid #dbe3ea;

            border-top: 4px solid #94a3b8;

            border-radius: 10px;

            padding: 20px 16px;

            text-align: center;

            min-height: 105px;

            display: flex;

            flex-direction: column;

            justify-content: center;

            box-shadow:
                0 2px 6px rgba(15, 23, 42, 0.04);

        }}


        .stat-card.online {{
            border-top-color: #16a34a;
        }}

        .stat-card.offline {{
            border-top-color: #64748b;
        }}

        .stat-card.critical {{
            border-top-color: #dc2626;
        }}

        .stat-card.high {{
            border-top-color: #ea580c;
        }}

        .stat-card.events {{
            border-top-color: #0284c7;
        }}

        .stat-card.devices {{
            border-top-color: #7c3aed;
        }}


        .stat-value {{

            font-size: 30px;

            font-weight: 750;

            color: #111827;

            line-height: 1.1;

        }}


        .stat-label {{

            font-size: 12px;

            color: #64748b;

            text-transform: uppercase;

            letter-spacing: 1px;

            margin-top: 7px;

            font-weight: 650;

        }}


        /* ==================================================
           SECTIONS
           ================================================== */

        .section {{

            background: #ffffff;

            border: 1px solid #dbe3ea;

            border-radius: 12px;

            padding: 22px;

            margin-bottom: 24px;

            box-shadow:
                0 2px 8px rgba(15, 23, 42, 0.05);

            overflow-x: auto;

        }}


        .section h2 {{

            color: #1e3a5f;

            font-size: 16px;

            font-weight: 750;

            text-transform: uppercase;

            letter-spacing: 1px;

            margin-bottom: 18px;

            border-bottom: 2px solid #e2e8f0;

            padding-bottom: 11px;

        }}


        /* ==================================================
           TABLES
           ================================================== */

        table {{

            width: 100%;

            border-collapse: separate;

            border-spacing: 0;

            min-width: 900px;

        }}


        th {{

            background: #eef3f7;

            color: #1e293b;

            padding: 13px 14px;

            text-align: left;

            font-size: 12px;

            font-weight: 750;

            text-transform: uppercase;

            letter-spacing: 0.7px;

            border-top: 1px solid #dbe3ea;

            border-bottom: 2px solid #cbd5e1;

        }}


        th:first-child {{

            border-left: 1px solid #dbe3ea;

        }}


        th:last-child {{

            border-right: 1px solid #dbe3ea;

        }}


        td {{

            padding: 13px 14px;

            border-bottom: 1px solid #e2e8f0;

            color: #1f2937;

            font-size: 14px;

            vertical-align: middle;

        }}


        tr:last-child td {{

            border-bottom: 0;

        }}


        tbody tr:hover td {{

            background: #f8fafc;

        }}


        .ip-cell {{

            font-weight: 650;

            color: #0f172a;

            white-space: nowrap;

        }}


        .mono {{

            font-family:
                "Consolas",
                "Courier New",
                monospace;

            font-size: 13px;

            color: #334155;

            white-space: nowrap;

        }}


        .time-cell {{

            color: #475569;

            font-size: 13px;

            white-space: nowrap;

        }}


        .details-cell {{

            color: #334155;

            font-size: 13px;

            min-width: 260px;

        }}


        .risk-cell {{

            color: #111827;

            font-size: 16px;

            font-weight: 750;

            text-align: center;

        }}


        /* ==================================================
           STATUS BADGES
           ================================================== */

        .badge-online {{

            display: inline-block;

            background: #ecfdf5;

            color: #047857;

            border: 1px solid #6ee7b7;

            padding: 4px 11px;

            border-radius: 12px;

            font-size: 11px;

            font-weight: 750;

            letter-spacing: 0.8px;

        }}


        .badge-offline {{

            display: inline-block;

            background: #f1f5f9;

            color: #475569;

            border: 1px solid #cbd5e1;

            padding: 4px 11px;

            border-radius: 12px;

            font-size: 11px;

            font-weight: 750;

            letter-spacing: 0.8px;

        }}


        .threat-badge {{

            display: inline-block;

            padding: 4px 11px;

            border-radius: 12px;

            font-size: 11px;

            font-weight: 750;

            letter-spacing: 0.8px;

        }}


        /* ==================================================
           EVENT LABELS
           ================================================== */

        .event-label {{

            display: inline-block;

            padding: 4px 9px;

            border-radius: 5px;

            font-size: 11px;

            font-weight: 750;

            letter-spacing: 0.4px;

            white-space: nowrap;

        }}


        .label-critical {{

            background: #fef2f2;

            color: #b91c1c;

            border: 1px solid #fca5a5;

        }}


        .label-high {{

            background: #fff7ed;

            color: #c2410c;

            border: 1px solid #fdba74;

        }}


        .label-warn {{

            background: #fffbeb;

            color: #a16207;

            border: 1px solid #fcd34d;

        }}


        .label-offline {{

            background: #f1f5f9;

            color: #475569;

            border: 1px solid #cbd5e1;

        }}


        .label-info {{

            background: #eff6ff;

            color: #0369a1;

            border: 1px solid #93c5fd;

        }}


        .label-decay {{

            background: #ecfdf5;

            color: #047857;

            border: 1px solid #6ee7b7;

        }}


        /* ==================================================
           RESET BUTTON
           ================================================== */

        .reset-btn {{

            background: #ffffff;

            color: #475569;

            border: 1px solid #94a3b8;

            padding: 6px 12px;

            border-radius: 6px;

            font-size: 12px;

            font-weight: 650;

            cursor: pointer;

            transition:
                background 0.15s ease,
                color 0.15s ease,
                border-color 0.15s ease;

        }}


        .reset-btn:hover {{

            background: #f1f5f9;

            color: #0f172a;

            border-color: #64748b;

        }}


        .reset-btn:disabled {{

            opacity: 0.45;

            cursor: not-allowed;

        }}


        /* ==================================================
           EMPTY STATE
           ================================================== */

        .empty {{

            text-align: center;

            color: #64748b;

            padding: 40px;

            font-size: 14px;

        }}


        /* ==================================================
           RESPONSIVE DISPLAY
           ================================================== */

        @media (max-width: 1200px) {{

            body {{

                padding: 20px;

            }}

            .stats {{

                grid-template-columns:
                    repeat(3, 1fr);

            }}

        }}


        @media (max-width: 700px) {{

            body {{

                padding: 12px;

            }}

            .header {{

                flex-direction: column;

                align-items: flex-start;

                gap: 16px;

            }}

            .stats {{

                grid-template-columns:
                    repeat(2, 1fr);

            }}

            .section {{

                padding: 15px;

            }}

        }}

        </style>

    </head>


    <body>

        <div class="dashboard-container">


            <!-- ==========================================
                 HEADER
                 ========================================== -->

            <div class="header">

                <div>

                    <h1>
                        SIPAR SECURITY
                    </h1>

                    <div class="subtitle">
                        Network Intrusion Detection System — Version 3.0
                    </div>

                </div>


                <div class="live-status">

                    <span class="live-dot"></span>

                    <span>
                        Live — refreshes every 5s
                    </span>

                </div>

            </div>


            <!-- ==========================================
                 STATISTICS
                 ========================================== -->

            <div class="stats">


                <div class="stat-card devices">

                    <div class="stat-value">
                        {total_devices}
                    </div>

                    <div class="stat-label">
                        Total Devices
                    </div>

                </div>


                <div class="stat-card online">

                    <div class="stat-value">
                        {online_count}
                    </div>

                    <div class="stat-label">
                        Online
                    </div>

                </div>


                <div class="stat-card offline">

                    <div class="stat-value">
                        {offline_count}
                    </div>

                    <div class="stat-label">
                        Offline
                    </div>

                </div>


                <div class="stat-card high">

                    <div class="stat-value">
                        {high_count}
                    </div>

                    <div class="stat-label">
                        High
                    </div>

                </div>


                <div class="stat-card critical">

                    <div class="stat-value">
                        {critical_count}
                    </div>

                    <div class="stat-label">
                        Critical
                    </div>

                </div>


                <div class="stat-card events">

                    <div class="stat-value">
                        {total_events}
                    </div>

                    <div class="stat-label">
                        Total Events
                    </div>

                </div>

            </div>


            <!-- ==========================================
                 DEVICE INVENTORY
                 ========================================== -->

            <div class="section">

                <h2>
                    Device Inventory
                </h2>

                <table>

                    <thead>

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

                    </thead>


                    <tbody>

                        {
                            '<tr><td colspan="8" class="empty">No devices discovered yet.</td></tr>'
                            if not device_rows
                            else device_rows
                        }

                    </tbody>

                </table>

            </div>


            <!-- ==========================================
                 SECURITY ALERTS
                 ========================================== -->

            <div class="section">

                <h2>
                    Security Alerts — Last 30
                </h2>

                <table>

                    <thead>

                        <tr>

                            <th>Timestamp</th>

                            <th>Event</th>

                            <th>IP</th>

                            <th>MAC</th>

                            <th>Details</th>

                            <th>Risk</th>

                        </tr>

                    </thead>


                    <tbody>

                        {
                            '<tr><td colspan="6" class="empty">No security alerts recorded.</td></tr>'
                            if not alert_rows
                            else alert_rows
                        }

                    </tbody>

                </table>

            </div>


        </div>


        <!-- ==============================================
             RESET RISK SCRIPT
             ============================================== -->

        <script>

        function resetRisk(ip, btn) {{

            btn.disabled = true;

            btn.textContent = '...';


            fetch('/reset_device', {{

                method: 'POST',

                headers: {{
                    'Content-Type': 'application/json'
                }},

                body: JSON.stringify({{
                    ip: ip
                }})

            }})

            .then(r => r.json())

            .then(data => {{

                if (data.status === 'ok') {{

                    btn.textContent = 'Done';

                    btn.style.color = '#047857';

                    setTimeout(
                        () => location.reload(),
                        800
                    );

                }}

                else {{

                    btn.textContent = 'Error';

                    btn.style.color = '#b91c1c';

                    btn.disabled = false;

                }}

            }})

            .catch(() => {{

                btn.textContent = 'Error';

                btn.style.color = '#b91c1c';

                btn.disabled = false;

            }});

        }}

        </script>

    </body>

    </html>
    """

    return html


# ============================================================
# RESET PROXY ROUTE
# dashboard -> event_server /reset/<ip>
# ============================================================

@app.route("/reset_device", methods=["POST"])
def reset_device():

    from flask import request, jsonify

    data = request.json or {}

    ip = data.get("ip", "")

    if not ip:

        return jsonify({
            "status": "error",
            "message": "no ip provided"
        }), 400

    try:

        resp = requests.post(
            f"{EVENT_SERVER_RESET}/{ip}",
            timeout=3
        )

        return jsonify(resp.json())

    except Exception as e:

        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500


# ============================================================
# START DASHBOARD
# ============================================================

if __name__ == "__main__":

    print(
        "[+] Dashboard running at "
        "http://127.0.0.1:5000"
    )

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False
    )
