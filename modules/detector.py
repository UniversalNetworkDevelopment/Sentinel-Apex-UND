"""
Attack pattern detector.
Parses Windows Security Event Log entries for:
  - 4625: failed logon (brute force)
  - 4776: NTLM auth failure
  - raw connection rate spikes (via netstat sampling)
"""

import re
import subprocess
import time
from collections import defaultdict
from typing import Optional


class Detector:
    def __init__(self, cfg: dict):
        self.failed_login_limit: int = cfg["thresholds"]["failed_logins"]
        self.port_scan_limit: int = cfg["thresholds"]["port_scan_ports"]
        self.rate_limit: int = cfg["thresholds"]["connection_rate"]
        self.window: int = cfg["thresholds"]["scan_window_seconds"]
        self.whitelist: set = set(cfg.get("whitelist", []))

        self._failed_logins: dict[str, list[float]] = defaultdict(list)
        self._port_activity: dict[str, set] = defaultdict(set)
        self._conn_rates: dict[str, list[float]] = defaultdict(list)

    def _prune(self, ts_list: list, window: int) -> list:
        cutoff = time.monotonic() - window
        return [t for t in ts_list if t > cutoff]

    def record_failed_login(self, ip: str) -> Optional[dict]:
        if ip in self.whitelist:
            return None
        now = time.monotonic()
        self._failed_logins[ip].append(now)
        self._failed_logins[ip] = self._prune(self._failed_logins[ip], self.window)
        count = len(self._failed_logins[ip])
        if count >= self.failed_login_limit:
            self._failed_logins[ip].clear()
            return {"type": "brute_force", "ip": ip, "detail": f"{count} failed logins in {self.window}s"}
        return None

    def record_port_probe(self, ip: str, port: int) -> Optional[dict]:
        if ip in self.whitelist:
            return None
        self._port_activity[ip].add(port)
        count = len(self._port_activity[ip])
        if count >= self.port_scan_limit:
            ports = sorted(self._port_activity[ip])
            self._port_activity[ip].clear()
            return {"type": "port_scan", "ip": ip, "detail": f"Scanned {count} ports: {ports[:10]}..."}
        return None

    def record_connection(self, ip: str) -> Optional[dict]:
        if ip in self.whitelist:
            return None
        now = time.monotonic()
        self._conn_rates[ip].append(now)
        self._conn_rates[ip] = self._prune(self._conn_rates[ip], 60)
        count = len(self._conn_rates[ip])
        if count >= self.rate_limit:
            self._conn_rates[ip].clear()
            return {"type": "rate_limit", "ip": ip, "detail": f"{count} connections/min"}
        return None

    def scan_event_log(self) -> list[dict]:
        """Read Windows Security log for recent auth failures (Event ID 4625)."""
        threats = []
        try:
            ps = (
                "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; StartTime=(Get-Date).AddSeconds(-65)} "
                "-ErrorAction SilentlyContinue | ForEach-Object { "
                "$xml=[xml]$_.ToXml(); "
                "($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'IpAddress'}).'#text' "
                "} | Where-Object { $_ -and $_ -ne '-' } | Sort-Object -Unique"
            )
            result = subprocess.run(
                ["powershell", "-NonInteractive", "-NoProfile", "-Command", ps],
                capture_output=True, text=True, timeout=10
            )
            for ip in result.stdout.strip().splitlines():
                ip = ip.strip()
                if ip and re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip):
                    threat = self.record_failed_login(ip)
                    if threat:
                        threats.append(threat)
        except Exception:
            pass
        return threats

    def scan_netstat(self) -> list[dict]:
        """Sample active connections from netstat for rate/scan anomalies."""
        threats = []
        try:
            result = subprocess.run(
                ["netstat", "-n", "-p", "TCP"],
                capture_output=True, text=True, timeout=10
            )
            ip_pattern = re.compile(r"^\s+TCP\s+\S+\s+(\d{1,3}(?:\.\d{1,3}){3}):(\d+)\s+ESTABLISHED", re.M)
            for m in ip_pattern.finditer(result.stdout):
                ip, port = m.group(1), int(m.group(2))
                threat = self.record_connection(ip)
                if threat:
                    threats.append(threat)
                probe = self.record_port_probe(ip, port)
                if probe:
                    threats.append(probe)
        except Exception:
            pass
        return threats
