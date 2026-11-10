# RT-HID: local host intrusion detection

RT-HID runs on an individual Ubuntu/Linux or Windows computer. It collects local security signals, applies explainable detection rules, stores evidence and incidents in a local SQLite database, and shows alerts on a dashboard bound to `127.0.0.1:5000`. It does not require a central server or send events elsewhere. The current detector does not use machine learning.

## What it monitors

| Signal | Linux | Windows |
| --- | --- | --- |
| Authentication | SSH and sudo entries from configured auth logs | Security log failed/successful local and remote logons |
| Processes | Newly started processes via `psutil` | Newly started processes via `psutil` |
| Network | Listeners and inferred outbound socket snapshots | Listeners and inferred outbound socket snapshots; optional Sysmon ID 3 |
| File integrity | Configured sensitive files | Configured sensitive files |
| Security changes | File modifications and permissions | Audit log clearing, account creation, service installation |
| System health | CPU, memory, boot snapshot | CPU, memory, boot snapshot |
| Persistence (opt in) | Cron, systemd, authorized_keys, shell startup and sudoers metadata | Startup/task files; optional Run/RunOnce and service configuration snapshots |
| Threat intelligence (opt in) | Local hash, IP and observed-domain IOC matching | Local hash, IP and observed-domain IOC matching |

Rules alert on repeated authentication failures, a successful login after failures, execution from temporary directories, encoded PowerShell commands, new listeners, monitored file changes, and the listed Windows security changes. The encoded PowerShell rule is high severity when a statically decoded command contains TCP client and command execution patterns; other encoded commands are medium severity because legitimate administration can use them. The decoded command is never executed or copied into alert evidence. These are indicators for investigation, not proof of compromise. The initial process, listener, file, and Windows Security log scans establish a baseline and do not raise retroactive alerts. Previously stored process events are not automatically reanalyzed when rules change.

## Process telemetry

Each process scan uses PID and creation time together to distinguish process instances, including PID reuse. The first scan establishes a baseline. Later scans emit start events for new instances and stop events for instances that disappear; an inaccessible process is retained for that scan so a permission error does not appear as a stop. Polling can miss processes that start and end between scans.

Start events include PID, name, parent PID and name, executable path, user, creation time, working directory, and a redacted command line when those fields are available. Unavailable fields are `null`. The incident detail view shows key process fields and the complete stored event evidence. Protected Windows processes, Linux `/proc` permissions, and processes that exit during inspection can leave fields unavailable. Collector health shows running state, last successful scan, duration, process counts, event counts, inaccessible counts, errors, and a sanitized error summary.

SHA-256 collection is enabled by default for newly observed accessible regular executables up to 16 MiB. The collector hashes at most two uncached executables per scan and caches 256 unchanged file signatures. It reads files only; it never executes them. Size, permission, deleted-file, and scan-budget failures leave the hash unavailable and are recorded with a short reason. A regular file on a slow or remote filesystem may still delay a scan; the size and per-scan limits bound the usual work, but do not impose a wall-clock timeout.

Command-line arguments are capped at 2,048 stored characters and obvious password, token, API-key, and secret flags are redacted. This is best-effort redaction: custom argument names, embedded secrets, and secrets in paths may remain visible. Do not grant dashboard access to users who should not see local process metadata. Environment variables and file contents are not collected.

The sample configuration in `config/host_ids.json` shows `process_interval_seconds`, `executable_hashing_enabled`, `process_command_line_max_length`, `executable_hash_max_bytes`, and `process_hashes_per_scan`. Existing configuration files can omit the new options and use these defaults. Set `executable_hashing_enabled` to `false` to skip executable hashing.

## Install

Use Python 3.10 or newer. From the repository root:

```bash
python -m venv .venv
```

On Ubuntu/Linux:

```bash
. .venv/bin/activate
pip install -e .
PYTHONPATH=src
```

On Windows PowerShell:

```powershell
.venv\Scripts\Activate.ps1
pip install -e .
```

```powershell
#for any powershell script blocking issues while activating the venv
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

The Windows dependency `pywin32` is installed automatically on Windows. Reading the Security log may require administrator or appropriate event log permissions and the corresponding Windows audit policies. Linux auth and FTP logs and protected files likewise require read access. Collectors report degraded status when permissions or dependencies are missing.

## Run on on

Start the monitor and local dashboard together:

```bash
python -m rt_hid.host.cli dashboard
```

On a new database, sign in with username `admin` and password `admin`. The first login sends you to a required password change. Choose a new password of at least 12 characters before the dashboard or API becomes available. After that, the default password no longer works.

Open `http://127.0.0.1:5000` on that same computer and sign in. The dashboard and all HTTP API endpoints require login. Sessions expire after eight hours, write actions require a CSRF token, and repeated failed logins are temporarily blocked. The dashboard only binds to loopback; use a local browser. The host's SQLite database contains the password hash and session signing secret, so protect the database file with operating-system permissions.

### Desktop notifications

The running monitor sends a native desktop notification when it saves a new incident, and a new-alert notification when another detection is added to an existing incident. The dashboard can be closed; the Python monitor process must remain running. Notification text contains only severity and rule ID, not IP addresses, command lines, usernames, paths, or stored evidence. Existing records are not replayed. Set `desktop_notifications_enabled` to `false` in a supplied config to turn this off. The Settings / About view reports whether the current process can reach a desktop notification service.

On Windows, install the project dependencies and run `dashboard` or `monitor` from a signed-in desktop session. RT-HID registers its own per-user Start menu notification identity and sends Windows toasts through the built-in Windows PowerShell process. The toast's click action is the local dashboard URL, separate from the Microsoft Store Python app identity. Each notification briefly starts a hidden PowerShell process, which can appear in process telemetry. Run the `dashboard` command to have the website available. Clear older Python-sender RT-HID notifications from Windows notification history after upgrading, because their original click action cannot be changed. A Windows service in Session 0 cannot show a notification on another user's desktop.

On Ubuntu/Linux, install `libnotify-bin` for `notify-send`, `libglib2.0-bin` for `gdbus`, and `dbus-bin` for `dbus-monitor`. Install a graphical web browser to open notifications. RT-HID tries the `x-www-browser` browser alternative first, then installed browser executables, including Falkon, Konqueror, and Midori; it does not pass the URL to a general file opener that may select a text editor. Run RT-HID while signed in to a graphical desktop. If RT-HID is started with `sudo`, notifications and their browser action run as the original sudo user through that user's desktop session; `runuser` and the user's `/run/user/<uid>/bus` socket must be available. RT-HID reads that user's graphical session environment for browser activation. RT-HID uses the freedesktop notification interface shared by GNOME, KDE Plasma, XFCE, and other compatible desktops. It sends actionable notifications directly over D-Bus and listens for clicks; this also handles GNOME Shell versions that omit the `actions` capability and cause `notify-send --action` to exit with an error. Clicking a new notification or its **Open RT-HID** action opens the local login URL when the desktop notification server supports actions; an existing browser session redirects to the dashboard. If the D-Bus path is unavailable, RT-HID falls back to `notify-send`. The Settings / About view and monitor log distinguish click listener and browser launch failures. A headless system service without a signed-in desktop session cannot display notifications.

HTTP API clients must keep the login session cookie and send the `csrf_token` from `GET /api/session` as the `X-CSRF-Token` header on all write requests (POST, PUT, PATCH and DELETE). Initial password setup must be completed in a browser before API access. Use the same `--config` option for all commands when using a custom configuration.

The console has Overview, Alerts, Incidents, Processes, Network, File integrity, Persistence, Intelligence, Rules / ATT&CK, Operations, Collectors, and Settings / About views. The Overview is an analyst workspace with an open incident queue, recent alerts, collector coverage, seven UTC days of incident activity, severity and category breakdowns, and direct triage links. The search bar routes IPs, users, processes, rules, and paths to the selected evidence view; press `/` outside a form field to focus it. The collector center distinguishes healthy, degraded, unavailable, and stopped monitoring, including partial scan errors and unsupported optional sources.

Alerts, incidents, and event views support search, time windows (all time, 24 hours, 7 days, or 30 days), filters, sorting, pagination, and evidence review. The open incident filter excludes resolved incidents; the priority filter includes high and critical severity, and the alert status filter can exclude false positives. Incident investigation includes related alerts, correlation explanations, a chronological timeline, source events, affected assets, notes, JSON export with an integrity hash, acknowledgement, resolution, undo, and false-positive actions. Process, network, and file views show **stored events**, not complete live inventories. Process ancestry uses PID and creation time and leaves missing parents explicit. Remote socket direction is inferred by psutil polling; optional Sysmon provides native outbound indications on configured Windows hosts. The file view covers configured monitored paths, not the whole filesystem. Process command lines are stored with best-effort redaction and shown only in the protected dashboard.

The authenticated `GET /api/alert-page`, `GET /api/incident-page`, and `GET /api/event-page` endpoints return paginated `{items,total,limit,offset}` objects. `GET /api/settings` returns read-only configuration summary without authentication secrets. Existing `/api/alerts`, `/api/incidents`, `/api/overview`, incident actions, CSRF requirements, and session behavior remain available. Explorer requests accept `limit` (1–100), `offset` (0–1,000,000), `order` (`newest` or `oldest`), `since` (`all`, `24h`, `7d`, or `30d`), and up to 100 search characters. Incident pages accept `state=open`; alert and incident pages accept `severity=priority` for high and critical, and alert pages accept `status=active` to exclude false positives. Use `kind=process`, `kind=network`, `kind=file`, or `kind=persistence` for event pages.

To run without the web UI:

```bash
python -m rt_hid.host.cli monitor
```

Other commands are `status`, `alerts`, `incidents`, `backup`, `validate-backup PATH`, and `restore-backup SOURCE NEW_DESTINATION`. Pass `--config config/host_ids.json` before the command to use the sample Linux configuration. Without a config file, the agent uses the machine hostname as its host ID and chooses platform defaults, including IOC matching for enabled imported indicators. The sample config has a placeholder `host_id`; replace it with your actual host ID before using `--config` on an existing installation. Its database is `data/host_ids.sqlite3`; this runtime data is ignored by Git. If you start RT-HID directly with `python -m rt_hid.host.cli dashboard`, changing `config/host_ids.json` has no effect. Restart that Python process after updating RT-HID.

## Advanced monitoring capabilities

Behavioral rules detect suspicious interpreter parents, verified downloader chains, temporary scripts and misplaced system executable names. Rule settings persist in SQLite and support enablement, bounded thresholds and exact allowlists. Correlation requires a shared process instance, executable path or account SID within a configured window; timestamp proximity alone is insufficient. The ATT&CK view lists implemented active mappings and known gaps.

The Intelligence view imports validated local JSON/CSV indicators and STIX 2.1 JSON bundles with one exact IP, domain or SHA-256 comparison per indicator. It manages enablement, validity windows, removal and expiry. IP indicators match remote destinations in stored network events and remote client sources in SSH, FTP and Windows remote-login outcomes. IOC alerts for the same indicator share a group even when one event has a process identity and another has an authentication source IP. For inbound FTP, the indicator value must equal the client IP in the server log, not the FTP server address. With IOC matching enabled, native vsftpd `CONNECT` lines also provide inbound connection observations; they do not count as failed logins. Matching requires `threat_intelligence_enabled: true` and an indicator that is currently valid; direct Python runs without `--config` now enable IOC matching by default. A supplied config may explicitly disable it. Persistence monitoring requires `persistence_enabled: true`; registry and native service snapshots have separate opt-ins. `sysmon_enabled` optionally reads an existing Sysmon channel; RT-HID does not install Sysmon or change audit policy.

Operations includes a bounded background queue, optional YARA scanning, response audit history and database maintenance. Install YARA only when needed with `pip install -e ".[yara]"`, then configure rule files and allowed scan paths. Scanning, process response and retention deletion default to disabled. Process termination requires administrator password verification, a single-use confirmation and a verified live process identity. Firewall modification and persistence disablement are unsupported.

See [advanced host monitoring, API reference and validation](docs/advanced-host-monitoring.md) and [optional configuration example](config/advanced.example.json) for the full support matrix, rules, migrations, performance results, limitations and Windows/Linux validation steps.

Example Linux service files are in `packaging/`. The supplied systemd unit expects a checkout at `/opt/rt-hid` and config at `/etc/rt-hid/host_ids.json`; edit those paths for another location. The service runs the monitor and dashboard locally. Complete the first login in a browser on the host. The Linux sample sets `threat_intelligence_enabled` to `true` so enabled imported IPs can match collected events. If the service was installed earlier, edit `/etc/rt-hid/host_ids.json` to add `"threat_intelligence_enabled": true`, restart with `sudo systemctl restart rt-hid`, and confirm the Intelligence page says matching is enabled. Editing the repository sample alone does not change an already deployed service.

## Limits

- The Windows Security collector reads authentication, audit clearing, account/service creation, task change and group membership event IDs. Persistence adds System service events 7040/7045; optional Sysmon reads network ID 3. Channels need access and relevant audit configuration; RT-HID does not inspect every Windows attack technique.
- Linux auth parsing currently covers common SSH and sudo log lines. Some distributions use only journald or different log formats; configure a readable auth log path or add a collector for those sources.
- FTP brute-force detection reads native vsftpd and ProFTPD login outcomes on Linux. The default Linux paths include `/var/log/vsftpd.log` and `/var/log/proftpd/proftpd.log`; add a different location to `auth_log_paths`. On Windows, `windows_ftp` reads IIS FTP W3C logs under `C:\inetpub\logs\LogFiles`; set `windows_ftp_log_paths` for a custom directory. IIS logging must include client IP, method and FTP status. Only PASS 530/230 outcomes count; other Windows FTP servers need their own log parser. Existing log files are baselined on the first scan.
- SSH brute-force counting uses primary sshd password/keyboard-interactive result lines. PAM context, standalone invalid-user notices and aggregate summaries do not count as additional guesses. SSH records without a valid remote IP are excluded from brute-force grouping rather than assigned to the local host. Sudo summaries retain their local username.
- Process and portable socket collection polls at configured intervals, so short-lived activity can be missed. File integrity and persistence cover configured scopes. There is no automatic blocking, deletion or quarantine.
- Retention runs only when explicitly enabled. It archives old resolved incident evidence and unreferenced raw events before deletion, preserves active/shared evidence, and conservatively retains process graph history. Audit and graph growth still need operator review.
- Hash chaining detects changes to an export/history but cannot provide tamper-proof storage against an attacker controlling the host. Backups contain authentication secrets and must be protected like the live database.

## Tests

```bash
python -m unittest discover -s tests -v
python -m compileall -q src tests
```
