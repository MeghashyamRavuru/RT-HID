# Advanced host monitoring: architecture and validation

## Phase 1 — process relationships and behavioral rules

SQLite migration 2 adds process instances and persistent rule settings. Relationships use host, PID and creation time. Parent creation time is collected when readable; missing or reused parent PIDs never produce an inferred tree. Initial process baselines still do not create historical start events.

Rules HIDS-BEH-001 through 007 cover Office/interpreter, web server/shell, browser/interpreter, service/temporary executable, interpreter/downloader/temporary executable ancestry, misplaced Windows system executable names, and interpreters running temporary scripts. These are explainable indicators with configurable exact allowlists, severity, confidence and enablement. The existing rules retain their IDs. Listener, temporary-executable and unusual-service-child heuristics have no ATT&CK technique where telemetry alone cannot establish one.

Authenticated APIs expose `/api/processes/<event_id>/relationships`, `/api/rules`, `PATCH /api/rules/<id>`, `POST /api/rules/test`, and `/api/mitre/coverage`. Rule tests do not persist events or execute scripts. Writes retain CSRF protection. Threshold and allowlist configuration accepts data only.

Tests use fabricated process identities and temporary SQLite databases; no production processes are launched or modified.

Phase 1 validation: the full suite passed 46 tests.

## Phase 2 — network snapshots and local IOC matching

The portable psutil collector now emits `network_connection` as well as existing listener events. Established socket direction is explicitly inferred after excluding observed local listeners; only SYN_SENT provides a direct outbound indication. Events include local port, remote endpoint, state, PID, process creation time and readable ownership. Identity includes the process instance and endpoints. Polling misses short-lived sockets and can lose visibility under OS permission restrictions. With `sysmon_enabled`, Windows additionally reads Event ID 3 from an existing Sysmon Operational channel, uses Initiated=true for outbound direction, and preserves observed destination domains. A late log record is not attached to a replacement process with a newer creation time. RT-HID does not install/configure Sysmon. Native auditd, journald and eBPF adapters are not implemented and are reported as unconfigured.

Rules HIDS-NET-002/003/004 detect configured unusual ports, repeated observations, and interpreters using unusual ports. Destination CIDR allowlists suppress these heuristics. Rule HIDS-IOC-001 matches local hash, exact IP and observed domain indicators. Matching is disabled by default (`threat_intelligence_enabled`). No DNS lookup, feed download or telemetry upload occurs. JSON and CSV imports validate all records before committing, normalize and upsert by type/value, preserve original first_seen, and ignore disabled/expired indicators. Source, confidence, severity and tags remain in match evidence.

Migration 3 adds indicators and persistence baseline storage. `/api/intelligence` supports pagination; `/import` supports local JSON/CSV records and STIX 2.1 JSON bundles; PATCH toggles enablement and DELETE removes a record. These routes share authentication and CSRF protections with the existing app.

Phase 2 validation: the full suite passed 48 tests.

## Phase 3 — persistence

Enable `persistence_enabled` to add bounded file snapshots of platform startup locations, or provide explicit `persistence_paths`. Linux defaults cover cron, systemd units/timers, current-user authorized_keys and shell profiles, and sudoers. Windows defaults cover scheduled task files and startup folders. Maximum file count, per-file hash size, total bytes and elapsed time bound each snapshot; unchanged metadata normally reuses hashes. The first scan after restart and every `persistence_verify_every_scans` scans (default 10) rehash within the same limits, to catch changes with preserved size/mtime. Filesystem I/O itself cannot always be interrupted. Symlinks and known private key/credential filenames are excluded. Inaccessible scopes retain their previous baseline. Baselines advance only after delivery succeeds, and retries retain event identity. The scheduler runs file persistence snapshots in a separate bounded thread.

Optional `persistence_registry_enabled` uses native winreg for HKCU/HKLM Run/RunOnce views. Optional `persistence_services_enabled` uses native service query APIs. Registry/service arguments are never stored: evidence retains hashes and executable paths. Unsupported modules and permissions produce sanitized health errors. No system-wide elevation is required by the app.

Security events 4698/4699/4702 add task changes; 4728/4732/4756 add group membership changes. Task arguments and raw XML are omitted. With persistence enabled, a separate System channel collector observes service events 7040/7045. Existing Security checkpoints and event IDs remain compatible. All initial snapshot baselines are silent.

Rules HIDS-PER-001 through 011 cover generic changes, temporary persistence executables, scheduled tasks, privileged group additions, Run/startup locations, cron, systemd services/timers, authorized_keys, shell profiles and Windows services. Privileged group rules check known group SIDs/names instead of treating every Users-group addition as high severity. Events preserve previous/current hashes and metadata, never file contents. File snapshots do not attribute a modifying process or user when the source lacks that information.

Phase 3 validation: the full suite passed 51 tests with temporary Linux directories and native Windows API mocks.

## Phase 4 — correlation and timelines

The persisted correlation layer searches a bounded recent detection window on the same host. HIDS-CORR-001 requires the same PID/creation-time instance for suspicious execution followed by a network observation. HIDS-CORR-002 requires an exact persistence executable path; HIDS-CORR-003 requires a monitored changed file matching a suspicious executable; HIDS-CORR-004 requires the same account SID for account creation and group membership addition. Nearby timestamps alone do not group events. False-positive detections are excluded. Existing authentication failure/success correlation remains supported.

Correlation incidents retain all source event and related detection IDs, explain the grouping, and accumulate subsequent matching evidence. Stable detection IDs and durable alert checks prevent duplicate delivery from creating duplicate incidents. Existing individual detections remain separately available for review. Incident detail adds a chronological timeline including notes and lifecycle changes, and coverage is generated from enabled registry rules and their versioned mappings, with explicit coverage gaps.

Phase 4 validation: the full suite passed 53 tests, including PID reuse, different-host and time-window exclusions.

## Phase 5 — optional YARA and rule tuning

Install `.[yara]` only when needed. `yara_enabled` defaults to false. Configure `yara_rule_paths` and `yara_scan_paths`, then request an individual file through `/api/scans`. Resolved paths must stay within configured scope, private-key paths and symlinks are rejected, and file sizes are bounded. User-provided rules compile with includes disabled. One worker handles scans and at most four queued jobs. Native YARA matching uses a configured timeout. Cancellation is cooperative; running native matches can take up to that timeout. Rule compilation itself has no native timeout and should use trusted local rules.

The worker reads a bounded file snapshot, scans those same bytes, records only its hash, path and rule names, and emits `file_scan`. HIDS-YARA-001 is an indicator, not a malware verdict. `/api/scans/status` reports disabled/unavailable states, and `/api/jobs` exposes queue capacity, job state and sanitized failures. Migration 5 adds durable job history. No scans run automatically on unrelated files.

Rule tuning supports bounded authentication/repeated-connection thresholds, disablement, severity, confidence and exact-match allowlists. Unknown fields, arbitrary code and unsupported thresholds are rejected.

Phase 5 validation: the full suite passed 55 tests; YARA behavior was validated with a mock module, without requiring the optional package.

## Phase 6 — response, audit and maintenance

`response_enabled` defaults to false. The supported action is selected-process termination, with administrator password verification, a 60-second single-use confirmation bound to the authenticated password version, and a second explicit confirmation. The live process PID/creation time is checked before termination. PID 0/1/4, the agent and its ancestors, and protected OS process names are rejected. Permission and process-exit failures are audited and sanitized. No action is automatic. Firewall modification and persistence disablement are explicitly unsupported. Process termination is irreversible; approved software must be restarted through its normal launcher/service manager.

Migration 6 adds append-only audit history with hash chaining and expiring response confirmations. SQLite triggers reject audit updates/deletes. Audit entries record actor, action, target, timestamp, reason and result, and never passwords or confirmation tokens. API writes, rule/IOC changes, response requests/results and maintenance actions are audited. This helps detect changes but cannot defeat an attacker controlling the host/database.

Database backup uses SQLite's online backup API from a separate connection. Backups retain authentication state and require the same protection as the live database. Integrity and schema validation precede restore. CLI commands: `backup`, `validate-backup PATH`, and `restore-backup SOURCE NEW_DESTINATION`. Restore refuses existing destinations and the configured live path; stop RT-HID before switching configuration to the restored copy.

`retention_enabled` defaults to false. When explicitly enabled, a bounded background job archives old resolved incident bundles before deletion and removes only unreferenced old raw events. Shared detections/events and active incident evidence are preserved. Process graph records are conservatively retained. Batches contain at most 25 resolved incidents and 250 unreferenced raw events. Archives include a SHA-256 manifest; audit, auth settings, indicators and configuration are never removed. No VACUUM or long exclusive write lock is used. Disk space may not shrink until an operator performs offline compaction. Failed/limited archival leaves evidence intact.

`/api/response/status`, `/prepare`, `/execute`, `/history`, `/api/maintenance/status`, `/api/maintenance/{backup,integrity,retention}` and incident `/integrity-export` integrate these functions with existing auth and CSRF. Retention requested through the API also requires password verification and confirmation.

Phase 6 validation covers response authorization, identity changes, audit immutability, database backup/restore, retention protection of shared active evidence, legacy schema upgrades and idle persistence writes. Final verification: **65 tests passed** with `python -m unittest discover -s tests -v`; compilation passed for source, tests and validation scripts; dashboard JavaScript syntax and `git diff --check` passed. The repository has no configured linter or type checker.

### SSH authentication parsing correction

The authentication parser counts primary OpenSSH authentication outcome records instead of also counting PAM context and standalone invalid-user notices. Otherwise one failed login can contribute both an IP-attributed failure and an unattributed failure, producing a second host-only brute-force incident. Supported daemon tags include sshd, sshd-session and sshd-auth, and direct sshd log output remains supported. Usernames are parsed from the outcome record, IP addresses are validated/canonicalized, and unattributed SSH/FTP records cannot fall back to a local-host brute-force group. Sudo summaries retain their local username. Identical primary records still count individually because distinct guesses can have identical log text within the same second.

The additional regression tests are in `tests/test_auth_telemetry.py`. Restart the agent to load the new parser. Historical duplicate alerts can be marked false positive through the existing investigation workflow.

### FTP authentication collection

The FTP rule previously accepted normalized `ftp_login` events, but no collector emitted them. Linux collection now reads every configured auth log path and recognizes native vsftpd `FAIL LOGIN`/`OK LOGIN` and ProFTPD `USER ... (Login failed)`/`Login successful` outcomes. Connection records and PAM context are ignored so each primary login result counts once. The default Linux paths include `/var/log/vsftpd.log` and `/var/log/proftpd/proftpd.log`; custom service paths must be added to `auth_log_paths`. FTP raw log lines are not stored because they may contain password material.

On Windows, the `windows_ftp` collector reads IIS FTP W3C site logs beneath `windows_ftp_log_paths` (default `C:\inetpub\logs\LogFiles`). It counts `PASS` status 530 as a failure and 230 as success, using the `#Fields` header to locate the source IP, username, method and status. Other FTP commands are ignored. Windows Security logon events are separate and may also fire for the underlying Windows account; the IIS FTP collector does not reinterpret them as FTP. A first scan establishes file offsets; newly rotated files are read from the start. This Windows path has fixture tests only; a live IIS FTP server was not available for validation.

Verification for the SSH and FTP corrections: `python -m unittest discover -s tests -v` passed 79 tests, and `python -m compileall -q src tests` passed. The supplied vsftpd lines were represented with documentation-only IPs in the tests; a live Linux FTP server was not available here.

## Architecture and schema reference

| Module | Responsibility |
| --- | --- |
| `identity.py`, `processes.py` | Verified process instance keys and persisted ancestry |
| `detection/registry.py`, `behavior.py`, `network_rules.py`, `persistence_rules.py` | Versioned definitions, tuning, allowlists and detection logic |
| `correlation.py` | Same-host, time-bounded correlations with explicit evidence links |
| `collectors/network.py`, `collectors/persistence.py`, `collectors/windows.py` | Portable snapshots and optional native Windows sources |
| `intelligence.py` | Local IOC normalization, import, expiry and matching |
| `jobs.py`, `scanning.py` | Bounded background work and optional YARA snapshots |
| `response.py`, `audit.py`, `maintenance.py` | Confirmed response, action history, exports, backups and retention |
| `advanced_api.py` | New authenticated API groups; existing Flask protections apply |

Migrations are additive and explicitly versioned in `migrations.py`; unknown future schema versions are rejected. Original tables and auth settings remain intact. Migration 2 adds `process_instances` and `rule_settings`; 3 adds `indicators` and `persistence_baselines`; 4 adds correlation/query indexes; 5 adds `background_jobs`; 6 adds `audit_history`, append-only triggers and `response_requests`; 7 adds indexed `detection_events`, `incident_detections` and `incident_events` links, backfilled from existing JSON. These links avoid repeated JSON scans for related-incident and retention queries. Retention rechecks references while holding the ingestion lock before deleting evidence.

Ancestry uses a bounded recursive query; child records and legacy incident summaries are fetched in bulk. Unchanged persistence snapshots perform no baseline writes, and changed snapshots update only affected entries plus the generation marker.

Run one monitor per database. Multiple independent monitors sharing one file are not supported. Existing database files migrate at startup; make a validated backup before an upgrade. The event envelope schema remains compatible; RT-HID application version is 0.2.0.

## API reference

Every route below requires an authenticated administrator session. Writes require `X-CSRF-Token`. List endpoints accept `limit` 1–100 and `offset` 0–1,000,000; the small static rule registry is returned as a bounded list. Error responses are JSON and never include raw internal exception messages.

| Method and route | Purpose |
| --- | --- |
| GET `/api/processes/<event_id>/relationships` | Recorded ancestry and children, with missing-parent information |
| GET `/api/event-page?kind=network` | Existing explorer, now includes connection and listener events |
| GET `/api/event-page?kind=persistence` | Searchable/paginated persistence evidence |
| GET `/api/intelligence` | Normalized indicators, enablement and expiry |
| POST `/api/intelligence/import` | `{format: "json" or "csv", content: "..."}`; validates the complete import before writing |
| PATCH / DELETE `/api/intelligence/<id>` | Toggle `{enabled: true/false}` or remove an indicator |
| GET `/api/rules` | Implemented rules, versions and effective settings |
| PATCH `/api/rules/<rule_id>` | Replace supported settings; `{}` restores defaults |
| POST `/api/rules/test` | Validate and test a sanitized event without ingestion |
| GET `/api/mitre/coverage` | Active rule mappings and explicit gaps |
| GET `/api/scans/status` | Optional dependency and configured scope status |
| POST `/api/scans` | Queue `{path: "configured/file"}` |
| GET `/api/jobs` | Job history, queue capacity and oldest queued age |
| POST `/api/jobs/<id>/cancel` | Cooperative cancellation |
| GET `/api/response/status` | Supported/unsupported actions and enabled state |
| POST `/api/response/prepare` | `{instance_id, reason, password}` creates a short-lived confirmation |
| POST `/api/response/execute` | `{confirmation_token, confirm: true}` checks live identity and requests termination |
| GET `/api/response/history` | Append-only audit history |
| GET `/api/maintenance/status` | Storage size, schema, retention policy and last integrity/retention results |
| POST `/api/maintenance/backup` or `/integrity` | Queue backup or integrity work |
| POST `/api/maintenance/retention` | Queue enabled policy with `{confirm: true, password}` |
| GET `/api/incidents/<id>/integrity-export` | Evidence bundle plus a SHA-256 integrity manifest |

Example IOC JSON:

```json
[{"type":"sha256","value":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","source":"local-lab","description":"Synthetic test indicator","confidence":0.5,"severity":"medium","expires_at":"2027-01-01T00:00:00Z","tags":["test"],"enabled":true}]
```

CSV uses the same column names; tags use semicolons. IP indicators accept `ip`, `ipv4` or `ipv6` and normalize to exact compressed addresses. Domain matching requires an observed destination hostname (for example from Sysmon); it does not perform DNS enrichment. JSON/CSV imports are limited to 1 MiB and 5,000 records. Rule settings accept `enabled`, `severity`, `confidence`, `allowlist` and supported `threshold` values. Allowlists are arrays of exact conditions over executable_path, file_path, username, parent_name and destination_ip; all fields in one condition must match.

STIX 2.1 bundles can be pasted into the Intelligence form with JSON selected. The importer reads indicator objects with a single exact equality for `ipv4-addr:value`, `ipv6-addr:value`, `domain-name:value` or `file:hashes.'SHA-256'`. Other bundle objects are ignored; unsupported indicator patterns cause the entire import to fail before any records are saved. STIX confidence from 0 to 100 is converted to local confidence from 0 to 1. The STIX indicator ID is retained as its source, indicator types become tags, `valid_from` delays matching, `valid_until` sets expiry, and revoked indicators are disabled. This is a limited STIX pattern subset, not a general STIX pattern evaluator.

## Platform support and validation limits

| Capability | Windows | Linux |
| --- | --- | --- |
| Process metadata / identity / ancestry | psutil; permission gaps explicit | psutil; `/proc` permission gaps explicit |
| Remote sockets | psutil inference; optional configured Sysmon ID 3 | psutil inference |
| Persistence files | Configured startup/task locations | Configured cron/systemd/SSH/profile/sudoers locations |
| Registry / service snapshots | Native optional winreg/pywin32 | Unsupported; explicit state if configured |
| Security / service events | Security log; optional System service channel | Existing auth log parser; native auditd/journald not implemented |
| IOC / rules / correlation / backups | Supported | Supported |
| YARA | Optional package, configured file scope | Optional package, configured file scope |
| Selected-process termination | Opt in; identity, password, confirmation and OS permissions | Same safeguards; OS permissions apply |
| Persistence disabling / firewall changes | Unsupported | Unsupported |

Tests ran on Windows using Python 3.13.14. Native registry, service/Sysmon event parsing, process responses and YARA use fixtures/mocks. No real service, registry entry, firewall rule or production process was modified. Linux persistence behavior was exercised with temporary directories; **a live Linux host and a configured native Windows Sysmon/service deployment have not been runtime validated**.

Read-only live Windows process and network baselines were also exercised. After limiting expensive process metadata retrieval to new instances, process scans inspected 301 processes with zero errors in 2.5974 s (baseline) and 2.2666 s (next scan), compared with 9.5884 s for the original full-metadata baseline in this environment. Network baseline collection took 0.1471 s, with 12 inaccessible owners and zero collection errors. No events were persisted by those checks. These one-off timings depend on host load and permissions.

The authenticated Flask browser smoke test passed 16 checks each at actual viewport widths 1424 px and 500 px. Chrome imposed a 500 px minimum for the requested narrow window; a 390 px viewport is not claimed. Checks cover all 12 views, process ancestry, disabled response defaults, IOC import through the UI, rule editor/coverage, safe sample testing, responsive overflow and the navigation drawer. The test uses real Flask endpoints and a temporary SQLite database, without production authentication bypasses.

## Performance and reliability

One isolated synthetic benchmark on this Windows environment ingested 500 events in 4.0874 s (122.33 events/s), consuming 0.8438 CPU seconds (20.64% of one core during that interval). Final RSS was 51,441,664 bytes; the RSS delta was -241,664 bytes, which reflects working-set noise rather than a claim about long-term memory stability. A mocked 1,000-socket collection took 0.0433 s. These are synthetic measurements, not production or long-duration load guarantees.

Reproduce with `python scripts/benchmark_host.py`. Browser validation is optional: `python scripts/browser_smoke.py --chrome "PATH_TO_CHROME" --width 1440` and `--width 390`. Both scripts use temporary databases and fixture telemetry.

Runtime state is bounded: 10,000 recent event IDs/listener keys, 2,048 auth/network groups with capped histories, 20,000 socket records per snapshot, a 256-entry executable hash cache, bounded persistence scopes, one background job worker and four pending jobs. Correlation queries use indexed host/time windows and at most 256 recent detections. Collector health exposes unavailable locations/capabilities and time since success. Jobs expose queue age/capacity and sanitized failure types. Interrupted jobs are marked on monitor restart. Native I/O and YARA compilation can still exceed a desired wall-clock budget; rule compilation should use trusted local rules.

Remaining limits: polling can miss short-lived processes/sockets; ancestry is incomplete when start/parent records are absent; psutil cannot always prove connection direction; a missed hash due to budget/permissions cannot match a hash IOC; persistence snapshots do not prove who changed a file; no arbitrary-domain visibility exists without domain telemetry. Conservative retention can leave graph history and detections not selected by the resolved-incident policy. Audit history is deliberately not pruned. No automatic quarantine, deletion, blocking or full ATT&CK coverage is claimed.

## Manual validation on Windows and Linux

1. Back up the existing database and stop the previous monitor. Install/update with `pip install -e .`, then run `python -m rt_hid.host.cli dashboard` or use a copied configuration via `--config PATH` before `dashboard`. Complete normal login/first-password setup and verify unauthenticated APIs and missing-CSRF writes are rejected.
2. Use a separate lab config/database for new collection tests. Enable persistence with a dedicated temporary directory; establish a baseline, then create, modify and delete a harmless marker. Verify hashes/actions, related incidents and inaccessible-scope health. Restart and confirm unchanged entries do not generate retroactive alerts. Avoid pointing test changes at real cron, systemd, registry or service entries.
3. On Windows, read optional registry/service snapshots with suitable permissions; confirm graceful degraded status without those permissions. If Sysmon is already installed/configured for network ID 3, opt in and verify channel health, remote endpoint fields and native direction. RT-HID must not install Sysmon or change audit policy.
4. On Linux, verify readable auth logs and configured startup paths. Check that unauthorized roots degrade independently. Native auditd/journald/eBPF must remain reported as unconfigured. Test network snapshots with a harmless local TCP server/client held open across a poll; loopback traffic should appear as telemetry without unusual-destination alerts.
5. In Rules, test the documented harmless Office/PowerShell sample; check rationale and ATT&CK mapping, then add a narrow allowlist and retest. In Intelligence, import a synthetic test indicator, enable matching only in the lab config, and verify duplicate imports, disabling and expiry. Never use real malware to validate these features.
6. If YARA is desired, install `.[yara]`, provide a local rule matching a harmless test marker and restrict scope to the test directory. Verify queued/completed/cancelled jobs, matched rule/hash evidence, size limits, outside-scope rejection and unavailable status without YARA.
7. Keep response disabled in normal validation. In an isolated lab only, enable it for a disposable process owned by the test user: verify password/confirmation, cancel first, check audit history, then test a deliberate termination and PID identity mismatch. Protected/system processes must remain rejected. There is no automatic response.
8. Create and validate a backup, restore to a new path, and inspect the copy. Test retention only on the lab database with old resolved and active/shared evidence; verify archives before deletion and preservation of active links. Confirm application integrity export hashes independently if desired.

## Primary implementation references

- [psutil socket/process API](https://psutil.readthedocs.io/stable/)
- [Microsoft audited event reference](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/Appendix-L--Events-to-Monitor)
- [YARA Python API and match timeouts](https://yara.readthedocs.io/en/latest/yarapython.html)
- [MITRE SSH authorized keys](https://attack.mitre.org/techniques/T1098/004/), [systemd service](https://attack.mitre.org/techniques/T1543/002/), [systemd timers](https://attack.mitre.org/techniques/T1053/006/), [shell configuration](https://attack.mitre.org/techniques/T1546/004/)
