# RT-HID

RT-HID is a local host intrusion detection agent for Windows and Linux. It collects host events, applies explainable rules, stores evidence in SQLite, and serves a password-protected dashboard at `http://127.0.0.1:5000`. It does not require a central server. The first scan establishes a baseline; later scans generate events and alerts.

## Requirements and privileges

- Python 3.10 or newer.
- **Run PowerShell/Terminal with high privileges when running RT-HID.** On Windows, open PowerShell **as Administrator**. On Linux, start the monitor with `sudo` or give its account read access to every configured log and protected path. Without those privileges, Security event logs, auth logs, protected files, and some process details may be unavailable. The Collectors view reports permission gaps.
- For desktop notifications, run from a signed-in graphical session. An elevated Windows PowerShell session must still be interactive. On Linux, use `sudo` from the signed-in desktop user's terminal; a headless systemd service cannot display desktop notifications.
- Optional Linux notification tools: `libnotify-bin`, `libglib2.0-bin`, and `dbus-bin`. Optional YARA scans require `yara-python`.

## Quick start

From the repository root, create an environment and install the project.

**Windows — in PowerShell opened as Administrator:**

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e .
.\.venv\Scripts\python.exe -m rt_hid.host.cli dashboard
```

**Linux — install into a virtual environment, then run the monitor with elevated privileges:**

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e .
sudo .venv/bin/python -m rt_hid.host.cli dashboard
```

Open `http://127.0.0.1:5000` on the same machine. For a new database, sign in as `admin` with password `admin`; the app immediately requires a new password of at least 12 characters. Protect the SQLite database because it contains authentication state and the session signing secret.

The dashboard command starts collection and the web server together. To run collection without the web UI, replace `dashboard` with `monitor`. Stop either with Ctrl+C. Only one monitor should use a database at a time.

## Configuration

Without `--config`, RT-HID uses platform defaults, the machine hostname as `host_id`, and `data/host_ids.sqlite3` as its database. The `data/` directory is ignored by Git. To customize collection, copy a sample JSON file, set a unique `host_id`, and pass it **before** the command:

```powershell
.\.venv\Scripts\python.exe -m rt_hid.host.cli --config config\host_ids.json dashboard
```

`config/host_ids.json` shows the main settings and Linux log paths. `config/advanced.example.json` shows optional persistence, Sysmon, YARA, response, and retention settings. The examples are templates; changing a sample file does not affect a process started without `--config`. Restart the monitor after changing configuration.

Key settings:

| Setting | Effect |
| --- | --- |
| `enabled_collectors` | Selects auth, FTP, process, network, file integrity, system, and event log collectors. |
| `monitored_paths`, `auth_log_paths`, `windows_ftp_log_paths` | Limits file and log collection to configured paths. |
| `process_interval_seconds`, `network_interval_seconds` | Controls polling; short-lived activity between polls can be missed. |
| `executable_hashing_enabled`, `executable_hash_max_bytes`, `process_hashes_per_scan` | Bounds read-only executable hashing. |
| `threat_intelligence_enabled` | Enables matching against locally imported indicators. |
| `persistence_enabled`, `sysmon_enabled`, `yara_enabled` | Enables optional sources or scans when their dependencies and paths are configured. |
| `response_enabled`, `retention_enabled` | Opts into confirmed process termination or evidence retention jobs; both default to off. |
| `desktop_notifications_enabled` | Enables local alert notifications when a desktop notification service is available. |

The dashboard always binds to loopback. The CLI rejects a non-loopback `--host`. HTTP API access requires a signed-in session; write requests also need the CSRF token from `GET /api/session` in the `X-CSRF-Token` header.

## What it collects

| Area | Linux | Windows |
| --- | --- | --- |
| Authentication | SSH, sudo, vsftpd, and ProFTPD log outcomes | Security log and IIS FTP log outcomes |
| Processes | `psutil` start/stop snapshots, metadata, optional executable hashes | Same, subject to process access permissions |
| Network | Listeners and inferred remote socket snapshots | Same, with optional existing Sysmon Event ID 3 |
| File integrity | Configured sensitive paths | Configured sensitive paths |
| Persistence | Optional cron, systemd, SSH, shell, and sudoers snapshots | Optional startup/task files, registry, and service snapshots |
| System | CPU, memory, and boot information | Same, plus selected Security and System events |

Rules detect repeated failed authentication, success after failures, temporary-path execution, encoded PowerShell, new listeners, monitored file changes, selected security changes, suspicious process relationships, persistence changes, and locally imported indicators. Detections are leads for investigation, not proof of compromise. The initial scan does not raise retroactive alerts. Process and socket polling can miss short-lived activity.

Process command lines are stored with length limits and best-effort secret redaction. Paths and custom arguments may still expose sensitive values; grant dashboard and database access accordingly. RT-HID does not execute collected commands or upload telemetry.

## CLI and development

Run commands from the repository root with the environment's Python executable. Use the same `--config PATH` prefix for every command that should access a custom database.

```text
python -m rt_hid.host.cli [--config PATH] dashboard [--port PORT]
python -m rt_hid.host.cli [--config PATH] monitor
python -m rt_hid.host.cli [--config PATH] status
python -m rt_hid.host.cli [--config PATH] alerts
python -m rt_hid.host.cli [--config PATH] incidents
python -m rt_hid.host.cli [--config PATH] backup
python -m rt_hid.host.cli validate-backup PATH
python -m rt_hid.host.cli restore-backup SOURCE NEW_DESTINATION
```

A backup contains authentication secrets and needs the same protection as the live database. Restore requires a new destination. Stop the running monitor before switching to a restored database.

Repository layout:

| Path | Purpose |
| --- | --- |
| `src/rt_hid/host/agent.py` | Collector scheduling, event ingestion, and agent lifecycle |
| `src/rt_hid/host/collectors/` | OS telemetry and persistence collection |
| `src/rt_hid/host/detection/` | Rule registry and detection logic |
| `src/rt_hid/host/storage.py`, `migrations.py` | SQLite persistence and schema upgrades |
| `src/rt_hid/host/api.py`, `advanced_api.py`, `*.html` | Authenticated local dashboard and API |
| `tests/` | Unit and integration tests with fixture telemetry |
| `scripts/` | Synthetic benchmark and optional Chrome browser smoke test |
| `packaging/` | Example Linux installer and systemd unit |

The Linux unit in `packaging/systemd/rt-hid.service` assumes a checkout at `/opt/rt-hid` and a config at `/etc/rt-hid/host_ids.json`; edit both paths for your deployment. A systemd service has no signed-in desktop session for notifications.

Run the test suite after changing collectors, rules, storage, or API code:

```bash
python -m unittest discover -s tests -v
python -m compileall -q src tests
```

For optional checks, run `python scripts/benchmark_host.py` or `python scripts/browser_smoke.py --chrome PATH_TO_CHROME --width 1440`. The benchmark uses synthetic events and mocked sockets. The browser script needs a Chrome executable and uses a temporary SQLite database.

## Operational limits

- Linux auth parsing supports common SSH and sudo formats; systems using only journald or different formats need another collector or a readable configured log.
- Windows Security, service, and Sysmon collection depends on access and existing OS audit configuration. RT-HID does not install Sysmon or change audit policy.
- FTP collection supports native vsftpd/ProFTPD logs and IIS FTP W3C logs. Other server formats need a parser.
- File integrity and persistence inspect configured scopes; they do not scan the whole filesystem or prove which user changed a file.
- YARA scans are requested for configured file scopes. Process termination requires an explicit password and confirmation when response is enabled. There is no automatic quarantine, firewall change, or blocking.
- Retention is disabled by default. When enabled, it archives eligible resolved evidence before deletion; audit history and some graph records remain.
- Audit hashes and integrity exports can reveal changes, but they cannot protect evidence from someone who controls the host and database.
