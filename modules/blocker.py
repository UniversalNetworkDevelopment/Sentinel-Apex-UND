"""
IP blocker using Windows Advanced Firewall (netsh advfirewall).
Requires administrator privileges.
"""

import subprocess
import time
import logging
from threading import Timer

logger = logging.getLogger("sentinel")

RULE_PREFIX = "Sentinel-Apex-Block"


def _rule_name(ip: str) -> str:
    return f"{RULE_PREFIX}-{ip.replace('.', '_')}"


def block_ip(ip: str, duration_minutes: int = 60) -> bool:
    name = _rule_name(ip)
    try:
        result = subprocess.run(
            [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={name}",
                "dir=in",
                "action=block",
                f"remoteip={ip}",
                "protocol=any",
                "enable=yes",
            ],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            logger.info(f"BLOCKED {ip} (duration: {duration_minutes}min)")
            if duration_minutes > 0:
                t = Timer(duration_minutes * 60, unblock_ip, args=[ip])
                t.daemon = True
                t.start()
            return True
        else:
            logger.warning(f"Failed to block {ip}: {result.stderr.strip()}")
            return False
    except Exception as e:
        logger.error(f"blocker error for {ip}: {e}")
        return False


def unblock_ip(ip: str) -> bool:
    name = _rule_name(ip)
    try:
        result = subprocess.run(
            ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={name}"],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            logger.info(f"UNBLOCKED {ip}")
            return True
        return False
    except Exception as e:
        logger.error(f"unblock error for {ip}: {e}")
        return False


def is_blocked(ip: str) -> bool:
    name = _rule_name(ip)
    try:
        result = subprocess.run(
            ["netsh", "advfirewall", "firewall", "show", "rule", f"name={name}"],
            capture_output=True, text=True, timeout=5
        )
        return result.returncode == 0 and "No rules match" not in result.stdout
    except Exception:
        return False


def clear_all_sentinel_rules() -> int:
    """Remove all rules created by Sentinel (for clean restart)."""
    try:
        result = subprocess.run(
            ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={RULE_PREFIX}*"],
            capture_output=True, text=True, timeout=15
        )
        count = result.stdout.count("Deleted")
        logger.info(f"Cleared {count} Sentinel firewall rules")
        return count
    except Exception as e:
        logger.error(f"clear_all error: {e}")
        return 0
