# RT-HID: local host intrusion detection

RT-HID runs on an individual Ubuntu/Linux or Windows computer. It collects local security signals, applies explainable detection rules, stores evidence and incidents in a local SQLite database, and shows alerts on a dashboard bound to `127.0.0.1`. It does not require a central server or send events elsewhere. The current detector does not use machine learning.

## What it monitors

| Signal | Linux | Windows |
| --- | --- | --- |
| Authentication | SSH and sudo entries from configured auth logs | Security log failed/successful local and remote logons |
| Processes | Newly started processes via `psutil` | Newly started processes via `psutil` |
| Network | New local listening services | New local listening services |
| File integrity | Configured sensitive files | Configured sensitive files |
| Security changes | File modifications and permissions | Audit log clearing, account creation, service installation |
| System health | CPU, memory, boot snapshot | CPU, memory, boot snapshot |

Rules alert on repeated authentication failures, a successful login after failures, execution from temporary directories, new listeners, monitored file changes, and the listed Windows security changes. These are indicators for investigation, not proof of compromise. The initial process, listener, file, and Windows Security log scans establish a baseline and do not raise retroactive alerts.

## Install

Use Python 3.10 or newer. From the repository root:

```bash
python -m venv .venv
```

On Ubuntu/Linux:

```bash
. .venv/bin/activate
pip install -e .
```

On Windows PowerShell:

```powershell
.venv\Scripts\Activate.ps1
pip install -e .
```

The Windows dependency `pywin32` is installed automatically on Windows. Reading the Security log may require administrator or appropriate event log permissions and the corresponding Windows audit policies. Linux auth logs and protected files likewise require read access. Collectors report degraded status when permissions or dependencies are missing.

## Run on one host

Start the monitor and local dashboard together:

```bash
python -m rt_hid.host.cli dashboard
```

On a new database, sign in with username `admin` and password `admin`. The first login sends you to a required password change. Choose a new password of at least 12 characters before the dashboard or API becomes available. After that, the default password no longer works.

Open `http://127.0.0.1:5000` on that same computer and sign in. The dashboard and all HTTP API endpoints require login. Sessions expire after eight hours, write actions require a CSRF token, and repeated failed logins are temporarily blocked. The dashboard only binds to loopback; use a local browser. The host's SQLite database contains the password hash and session signing secret, so protect the database file with operating-system permissions.

HTTP API clients must keep the login session cookie and send the `csrf_token` from `GET /api/session` as the `X-CSRF-Token` header on POST requests. Initial password setup must be completed in a browser before API access. Use the same `--config` option for all commands when using a custom configuration.

The dashboard shows incident totals, seven-day activity, alert severity, and collector health. Browse all incidents with pagination, search and filter by state, then open one to inspect affected files, related alerts, detection rationale, source events, and complete stored evidence. Add investigation notes, export an incident as JSON, mark an alert as a false positive, or acknowledge and resolve an incident from the detail view. Undo controls restore the previous incident state or reverse a false-positive mark, including after a dashboard restart. To run without the web UI:

```bash
python -m rt_hid.host.cli monitor
```

Other commands are `status`, `alerts`, and `incidents`. Pass `--config config/host_ids.json` before the command to use the sample Linux configuration. Without a config file, the agent uses the machine hostname as its host ID and chooses platform defaults. Its database is `data/host_ids.sqlite3`; this runtime data is ignored by Git.

Example Linux service files are in `packaging/`. The supplied systemd unit expects a checkout at `/opt/rt-hid` and config at `/etc/rt-hid/host_ids.json`; edit those paths for another location. The service runs the monitor and dashboard locally. Complete the first login in a browser on the host.

## Limits

- The Windows Security collector reads event IDs 4624, 4625, 1102, 4697, and 4720. It needs Security log access and relevant audit policies. It does not inspect every Windows attack technique.
- Linux auth parsing currently covers common SSH and sudo log lines. Some distributions use only journald or different log formats; configure a readable auth log path or add a collector for those sources.
- Process and listener collection polls at configured intervals, so short-lived activity can be missed. File integrity checks only configured paths. The program raises alerts; it does not block attacks or remove malware.
- The `retention_days` setting is reserved for a future retention job. No automatic database pruning is implemented yet.

## Tests

```bash
python -m unittest discover -s tests -v
```
