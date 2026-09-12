# Sentinel-Apex-UND

**Real-time network intrusion detection and automated response system developed by Universal Network Development LLC.**

Sentinel-Apex monitors incoming connections, detects attack patterns, automatically blocks malicious IPs via Windows Firewall, and alerts via Discord webhook — running silently as a background daemon with no console window.

---

## Features

- **Brute-force detection** — tracks failed login attempts per IP, auto-blocks after threshold
- **Port scan detection** — identifies rapid sequential port probing
- **DDoS rate limiting** — flags and blocks IPs exceeding connection rate limits
- **Windows Firewall integration** — blocks via `netsh advfirewall` (no third-party drivers)
- **Discord alerts** — real-time threat notifications to your webhook channel
- **Incident logging** — structured JSON logs at `logs/incidents.jsonl`
- **Auto-unblock** — configurable ban duration; IPs auto-expire
- **GitHub Actions hardening** — secret scanning + dependency audit on every push

---

## Requirements

- Windows 10/11 (administrator privileges for firewall rules)
- Python 3.10+
- `pip install -r requirements.txt`

---

## Setup

```powershell
# Clone
git clone https://github.com/UniversalNetworkDevelopment/Sentinel-Apex-UND.git
cd Sentinel-Apex-UND

# Install dependencies
pip install -r requirements.txt

# Configure (copy and edit)
copy config.example.yml config.yml
# Set SENTINEL_DISCORD_WEBHOOK in environment or config.yml

# Run (requires admin)
python sentinel.py
```

---

## Configuration

Edit `config.yml`:

```yaml
thresholds:
  failed_logins: 5        # block after N failed attempts
  port_scan_ports: 15     # block after scanning N ports in window
  connection_rate: 100    # connections/minute before rate-limit block

ban:
  duration_minutes: 60    # 0 = permanent

alerts:
  discord_webhook: ""     # set or use SENTINEL_DISCORD_WEBHOOK env var
  alert_on_block: true
  alert_on_unblock: false

logging:
  level: INFO
  path: logs/incidents.jsonl
```

---

## Architecture

```
sentinel.py              ← main daemon loop
modules/
  detector.py            ← attack pattern analysis
  blocker.py             ← Windows Firewall rule management
  discord_alert.py       ← webhook notifications
  logger.py              ← structured incident logging
.github/workflows/
  sentinel-scan.yml      ← secret scan + dependency audit (CI)
```

---

## Running as a Windows Service

```powershell
# Install as scheduled task (runs hidden, survives reboot)
schtasks /create /tn "UND-Sentinel-Apex" /tr "pythonw.exe C:\path\to\sentinel.py" /sc onstart /ru SYSTEM /f
```

---

## Security

See [SECURITY.md](SECURITY.md) for vulnerability reporting.

---

*Universal Network Development LLC — Building real security infrastructure.*
