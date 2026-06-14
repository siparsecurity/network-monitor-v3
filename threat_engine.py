# -----------------------------
# threat_engine.py
# Sipar Security — Version 3.0
# -----------------------------
# Central threat level engine.
# All risk scoring and level
# decisions go through here.
# -----------------------------

# -----------------------------
# THREAT LEVELS
# -----------------------------
LEVEL_LOW      = "LOW"
LEVEL_MEDIUM   = "MEDIUM"
LEVEL_HIGH     = "HIGH"
LEVEL_CRITICAL = "CRITICAL"

# -----------------------------
# RISK THRESHOLDS
# -----------------------------
THRESHOLD_MEDIUM   =  5
THRESHOLD_HIGH     = 15
THRESHOLD_CRITICAL = 30

# -----------------------------
# RISK SCORES PER EVENT
# -----------------------------
RISK_SCORES = {
    "NEW_DEVICE"      :  5,
    "ROGUE_DEVICE"    : 10,
    "PORT_SCAN"       : 15,
    "ARP_SPOOF_LOW"   : 10,
    "ARP_SPOOF_MEDIUM": 15,
    "ARP_SPOOF_HIGH"  : 20,
    "DUPLICATE_MAC"   : 20,
    "DEVICE_OFFLINE"  :  0,
    "IDS_START"       :  0,
    "INITIAL_DEVICE"  :  0,
}

# -----------------------------
# THREAT LEVEL FROM SCORE
# -----------------------------
def get_threat_level(risk: int) -> str:
    """
    Return threat level string based on cumulative risk score.

    0-4   -> LOW
    5-14  -> MEDIUM
    15-29 -> HIGH
    30+   -> CRITICAL
    """
    if risk >= THRESHOLD_CRITICAL:
        return LEVEL_CRITICAL
    elif risk >= THRESHOLD_HIGH:
        return LEVEL_HIGH
    elif risk >= THRESHOLD_MEDIUM:
        return LEVEL_MEDIUM
    else:
        return LEVEL_LOW


# -----------------------------
# RISK SCORE FROM EVENT TYPE
# -----------------------------
def get_risk_score(event_type: str) -> int:
    """
    Return the risk score for a given event type.
    Unknown events return 0.
    """
    return RISK_SCORES.get(event_type, 0)


# -----------------------------
# THREAT LEVEL COLOR
# (for dashboard use)
# -----------------------------
LEVEL_COLORS = {
    LEVEL_LOW     : "#22c55e",   # green
    LEVEL_MEDIUM  : "#facc15",   # yellow
    LEVEL_HIGH    : "#f97316",   # orange
    LEVEL_CRITICAL: "#ef4444",   # red
}

def get_threat_color(level: str) -> str:
    """Return hex color for a given threat level."""
    return LEVEL_COLORS.get(level, "#64748b")


# -----------------------------
# FULL THREAT SUMMARY
# (single call for dashboard)
# -----------------------------
def get_threat_summary(risk: int) -> dict:
    """
    Return a complete threat summary dict for a given risk score.
    Used by dashboard and API responses.

    Example:
        get_threat_summary(18)
        -> {
            "risk"  : 18,
            "level" : "HIGH",
            "color" : "#f97316"
           }
    """
    level = get_threat_level(risk)
    return {
        "risk" : risk,
        "level": level,
        "color": get_threat_color(level)
    }
