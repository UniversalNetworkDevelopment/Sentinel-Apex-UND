"""
Sentinel-Apex-UND — Network Intrusion Detection & Response Daemon
Universal Network Development LLC

Run with administrator privileges.
"""

import os
import sys
import time
import logging
import yaml
from pathlib import Path

from modules import detector as det_mod
from modules import blocker
from modules import discord_alert
from modules import logger as log_mod


def load_config() -> dict:
    cfg_path = Path(__file__).parent / "config.yml"
    if not cfg_path.exists():
        print("[Sentinel] config.yml not found. Copy config.example.yml to config.yml and edit it.")
        sys.exit(1)
    with open(cfg_path, encoding="utf-8") as f:
        return yaml.safe_load(f)


def get_webhook(cfg: dict) -> str:
    return os.environ.get("SENTINEL_DISCORD_WEBHOOK") or cfg.get("alerts", {}).get("discord_webhook", "")


def handle_threat(threat: dict, cfg: dict, webhook: str, log_path: str) -> None:
    ip = threat["ip"]
    ttype = threat["type"]
    detail = threat["detail"]
    duration = cfg["ban"]["duration_minutes"]

    already = blocker.is_blocked(ip)
    action = "already blocked"
    if not already:
        success = blocker.block_ip(ip, duration_minutes=duration)
        action = f"BLOCKED for {duration}min" if success else "block failed (check admin rights)"

    log_mod.write_incident(log_path, ttype, ip, detail, action)
    logging.getLogger("sentinel").warning(f"THREAT [{ttype}] {ip} — {detail} → {action}")

    if cfg.get("alerts", {}).get("alert_on_block", True) and not already:
        discord_alert.send_block_alert(webhook, ip, ttype, detail, action)


def main() -> None:
    cfg = load_config()
    log_path = cfg.get("logging", {}).get("path", "logs/incidents.jsonl")
    log_level = cfg.get("logging", {}).get("level", "INFO")
    log_mod.setup(log_path, log_level)
    logger = logging.getLogger("sentinel")

    webhook = get_webhook(cfg)
    detector = det_mod.Detector(cfg)

    logger.info("Sentinel-Apex-UND starting up")
    discord_alert.send_startup_alert(webhook)

    try:
        while True:
            threats = detector.scan_event_log() + detector.scan_netstat()
            for threat in threats:
                handle_threat(threat, cfg, webhook, log_path)
            time.sleep(30)
    except KeyboardInterrupt:
        logger.info("Sentinel-Apex shutting down")


if __name__ == "__main__":
    main()
