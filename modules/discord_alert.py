"""
Discord webhook alerter for Sentinel-Apex.
Sends threat notifications with embed formatting.
"""

import logging
import requests
from datetime import datetime, timezone

logger = logging.getLogger("sentinel")

THREAT_COLORS = {
    "brute_force": 0xFF4444,
    "port_scan":   0xFF8800,
    "rate_limit":  0xFFAA00,
    "default":     0xCC0000,
}

THREAT_ICONS = {
    "brute_force": "🔐",
    "port_scan":   "🔍",
    "rate_limit":  "⚡",
    "default":     "⚠️",
}


def send_block_alert(webhook_url: str, ip: str, threat_type: str, detail: str, action: str) -> bool:
    if not webhook_url:
        return False
    color = THREAT_COLORS.get(threat_type, THREAT_COLORS["default"])
    icon = THREAT_ICONS.get(threat_type, THREAT_ICONS["default"])
    label = threat_type.replace("_", " ").title()

    payload = {
        "embeds": [{
            "title": f"{icon} Sentinel-Apex — {label} Detected",
            "color": color,
            "fields": [
                {"name": "IP Address", "value": f"`{ip}`", "inline": True},
                {"name": "Threat Type", "value": label, "inline": True},
                {"name": "Action Taken", "value": action, "inline": True},
                {"name": "Detail", "value": detail, "inline": False},
            ],
            "footer": {"text": "Sentinel-Apex-UND • Universal Network Development LLC"},
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }]
    }

    try:
        r = requests.post(webhook_url, json=payload, timeout=10)
        r.raise_for_status()
        return True
    except Exception as e:
        logger.warning(f"Discord alert failed: {e}")
        return False


def send_startup_alert(webhook_url: str) -> None:
    if not webhook_url:
        return
    payload = {
        "embeds": [{
            "title": "🛡️ Sentinel-Apex Online",
            "description": "Network intrusion detection is now active.",
            "color": 0x00CC66,
            "footer": {"text": "Sentinel-Apex-UND • Universal Network Development LLC"},
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }]
    }
    try:
        requests.post(webhook_url, json=payload, timeout=10)
    except Exception:
        pass
