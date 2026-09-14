import json
import logging
from datetime import datetime, timezone
from pathlib import Path


def setup(log_path: str, level: str = "INFO") -> logging.Logger:
    Path(log_path).parent.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("sentinel")
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
        logger.addHandler(handler)
    return logger


def write_incident(log_path: str, event_type: str, ip: str, detail: str, action: str) -> None:
    record = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "type": event_type,
        "ip": ip,
        "detail": detail,
        "action": action,
    }
    Path(log_path).parent.mkdir(parents=True, exist_ok=True)
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")
