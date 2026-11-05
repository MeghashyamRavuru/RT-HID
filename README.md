# RT-NID-ML: local host intrusion detection

RT-NID-ML runs on an individual Ubuntu/Linux or Windows computer. It collects local security signals, applies explainable detection rules, stores evidence and incidents in a local SQLite database, and shows alerts on a dashboard bound to `127.0.0.1`. It does not require a central server or send events elsewhere. Despite the historical repository name, the current detector does not use machine learning.

The [project direction note](PROJECT_DIRECTION.md) explains the earlier network IDS work and why this repository now focuses on the host agent.

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
python -m rt_nid_ml.host.cli dashboard
```

Open `http://127.0.0.1:5000` on that same computer. The dashboard shows incident totals and collector health. Browse all incidents with pagination, search and filter by state, then open one to inspect its affected files, related alerts, detection rationale, source events, and complete stored evidence. Acknowledge or resolve an incident from its detail view. It is bound to loopback by default. To run without the web UI:

```bash
python -m rt_nid_ml.host.cli monitor
```

Other commands are `status`, `alerts`, and `incidents`. Pass `--config config/host_ids.json` before the command to use the sample Linux configuration. Without a config file, the agent uses the machine hostname as its host ID and chooses platform defaults. Its database is `data/host_ids.sqlite3`; this runtime data is ignored by Git.

Example Linux service files are in `packaging/`. The supplied systemd unit expects a checkout at `/opt/rt-nid-ml` and config at `/etc/rt-nid-ml/host_ids.json`; edit those paths for another location. The service runs the monitor and dashboard locally.

## Limits

- The Windows Security collector reads event IDs 4624, 4625, 1102, 4697, and 4720. It needs Security log access and relevant audit policies. It does not inspect every Windows attack technique.
- Linux auth parsing currently covers common SSH and sudo log lines. Some distributions use only journald or different log formats; configure a readable auth log path or add a collector for those sources.
- Process and listener collection polls at configured intervals, so short-lived activity can be missed. File integrity checks only configured paths. The program raises alerts; it does not block attacks or remove malware.
- The `retention_days` setting is reserved for a future retention job. No automatic database pruning is implemented yet.

## Tests

```bash
python -m unittest discover -s tests -v
```
