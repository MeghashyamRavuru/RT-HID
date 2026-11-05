from __future__ import annotations

import json
import os
import secrets
import sqlite3
import threading
import uuid
from pathlib import Path
from typing import Any

from werkzeug.security import check_password_hash, generate_password_hash

from .models import CollectorStatus, Detection, HostEvent, utc_now


class HostDatabase:
    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self.connection = sqlite3.connect(self.path, check_same_thread=False)
        if os.name == "posix":
            os.chmod(self.path, 0o600)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA journal_mode=WAL")
        self.connection.execute("PRAGMA busy_timeout=5000")
        self._initialize()

    def _initialize(self) -> None:
        with self._lock, self.connection:
            self.connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS schema_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS host_events (
                    event_id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, host_id TEXT NOT NULL,
                    event_type TEXT NOT NULL, source TEXT NOT NULL, payload TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_events_time ON host_events(timestamp);
                CREATE INDEX IF NOT EXISTS idx_events_type ON host_events(event_type);
                CREATE TABLE IF NOT EXISTS detections (
                    detection_id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, host_id TEXT NOT NULL,
                    rule_id TEXT NOT NULL, category TEXT NOT NULL, severity TEXT NOT NULL,
                    payload TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_detections_time ON detections(timestamp);
                CREATE TABLE IF NOT EXISTS alerts (
                    alert_id TEXT PRIMARY KEY, incident_id TEXT NOT NULL, first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL, severity TEXT NOT NULL, status TEXT NOT NULL,
                    payload TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
                CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
                CREATE INDEX IF NOT EXISTS idx_alerts_incident ON alerts(incident_id);
                CREATE TABLE IF NOT EXISTS incidents (
                    incident_id TEXT PRIMARY KEY, state TEXT NOT NULL, first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL, payload TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS collector_status (
                    collector_id TEXT PRIMARY KEY, updated_at TEXT NOT NULL, payload TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS file_baselines (
                    path TEXT PRIMARY KEY, sha256 TEXT NOT NULL, mode TEXT NOT NULL,
                    size INTEGER NOT NULL, updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS checkpoints (
                    checkpoint_id TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS auth_settings (
                    key TEXT PRIMARY KEY, value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS incident_notes (
                    note_id TEXT PRIMARY KEY, incident_id TEXT NOT NULL,
                    created_at TEXT NOT NULL, author TEXT NOT NULL, body TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_incident_notes_incident ON incident_notes(incident_id, created_at);
                INSERT OR IGNORE INTO schema_meta(key, value) VALUES ('schema_version', '1');
                """
            )

    def save_event(self, event: HostEvent) -> bool:
        with self._lock, self.connection:
            cursor = self.connection.execute(
                "INSERT OR IGNORE INTO host_events(event_id, timestamp, host_id, event_type, source, payload) VALUES (?, ?, ?, ?, ?, ?)",
                (event.event_id, event.timestamp, event.host_id, event.event_type, event.source, json.dumps(event.to_dict())),
            )
            return cursor.rowcount == 1

    def save_detection(self, detection: Detection) -> None:
        with self._lock, self.connection:
            self.connection.execute(
                "INSERT OR REPLACE INTO detections(detection_id, timestamp, host_id, rule_id, category, severity, payload) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (detection.detection_id, detection.timestamp, detection.host_id, detection.rule_id, detection.category, detection.severity, json.dumps(detection.to_dict())),
            )

    def save_alert(self, alert: dict[str, Any]) -> None:
        with self._lock, self.connection:
            self.connection.execute(
                "INSERT OR REPLACE INTO alerts(alert_id, incident_id, first_seen, last_seen, severity, status, payload) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (alert["alert_id"], alert["incident_id"], alert["first_seen"], alert["last_seen"], alert["severity"], alert.get("status", "new"), json.dumps(alert)),
            )

    def save_incident(self, incident: dict[str, Any]) -> None:
        with self._lock, self.connection:
            self.connection.execute(
                "INSERT OR REPLACE INTO incidents(incident_id, state, first_seen, last_seen, payload) VALUES (?, ?, ?, ?, ?)",
                (incident["incident_id"], incident["state"], incident["first_seen"], incident["last_seen"], json.dumps(incident)),
            )

    def save_collector_status(self, status: CollectorStatus) -> None:
        with self._lock, self.connection:
            self.connection.execute(
                "INSERT OR REPLACE INTO collector_status(collector_id, updated_at, payload) VALUES (?, ?, ?)",
                (status.collector_id, utc_now(), json.dumps(status.to_dict())),
            )

    def save_baseline(self, path: str, sha256: str, mode: str, size: int) -> None:
        with self._lock, self.connection:
            self.connection.execute(
                "INSERT OR REPLACE INTO file_baselines(path, sha256, mode, size, updated_at) VALUES (?, ?, ?, ?, ?)",
                (path, sha256, mode, size, utc_now()),
            )

    def get_baseline(self, path: str) -> sqlite3.Row | None:
        return self.connection.execute("SELECT * FROM file_baselines WHERE path = ?", (path,)).fetchone()

    def delete_baseline(self, path: str) -> None:
        with self._lock, self.connection:
            self.connection.execute("DELETE FROM file_baselines WHERE path = ?", (path,))

    def set_alert_status(self, alert_id: str, status: str) -> None:
        with self._lock, self.connection:
            row = self.connection.execute("SELECT payload FROM alerts WHERE alert_id = ?", (alert_id,)).fetchone()
            if row is None:
                raise KeyError(alert_id)
            payload = json.loads(row["payload"])
            if payload.get("status", "new") == status:
                return
            history = payload.get("status_history", [])
            history.append(payload.get("status", "new"))
            payload["status_history"] = history[-20:]
            payload["status"] = status
            self.connection.execute("UPDATE alerts SET status = ?, payload = ? WHERE alert_id = ?", (status, json.dumps(payload), alert_id))

    def undo_alert_status(self, alert_id: str) -> str:
        with self._lock, self.connection:
            row = self.connection.execute("SELECT payload FROM alerts WHERE alert_id = ?", (alert_id,)).fetchone()
            if row is None:
                raise KeyError(alert_id)
            payload = json.loads(row["payload"])
            if payload.get("status") != "false_positive":
                raise ValueError("alert is not marked false positive")
            history = payload.get("status_history", [])
            previous = history.pop() if history else "new"  # legacy false positives had no history
            payload["status_history"] = history
            payload["status"] = previous
            self.connection.execute(
                "UPDATE alerts SET status = ?, payload = ? WHERE alert_id = ?",
                (previous, json.dumps(payload), alert_id),
            )
            return previous

    def set_incident_state(self, incident_id: str, state: str) -> None:
        with self._lock, self.connection:
            row = self.connection.execute("SELECT payload FROM incidents WHERE incident_id = ?", (incident_id,)).fetchone()
            if row is None:
                raise KeyError(incident_id)
            payload = json.loads(row["payload"])
            if payload["state"] == state:
                return
            history = payload.get("state_history", [])
            history.append(payload["state"])
            payload["state_history"] = history[-20:]
            payload["state"] = state
            self.connection.execute("UPDATE incidents SET state = ?, payload = ? WHERE incident_id = ?", (state, json.dumps(payload), incident_id))

    def undo_incident_state(self, incident_id: str) -> str:
        with self._lock, self.connection:
            row = self.connection.execute("SELECT payload FROM incidents WHERE incident_id = ?", (incident_id,)).fetchone()
            if row is None:
                raise KeyError(incident_id)
            payload = json.loads(row["payload"])
            history = payload.get("state_history", [])
            if not history:
                raise ValueError("incident has no state change to undo")
            previous = history.pop()
            payload["state_history"] = history
            payload["state"] = previous
            self.connection.execute(
                "UPDATE incidents SET state = ?, payload = ? WHERE incident_id = ?",
                (previous, json.dumps(payload), incident_id),
            )
            return previous

    def set_checkpoint(self, checkpoint_id: str, value: str) -> None:
        with self._lock, self.connection:
            self.connection.execute(
                "INSERT OR REPLACE INTO checkpoints(checkpoint_id, value, updated_at) VALUES (?, ?, ?)",
                (checkpoint_id, value, utc_now()),
            )

    def get_checkpoint(self, checkpoint_id: str) -> str | None:
        row = self.connection.execute("SELECT value FROM checkpoints WHERE checkpoint_id = ?", (checkpoint_id,)).fetchone()
        return None if row is None else str(row["value"])

    def session_secret(self) -> str:
        with self._lock, self.connection:
            row = self.connection.execute("SELECT value FROM auth_settings WHERE key = 'session_secret'").fetchone()
            if row:
                return str(row["value"])
            secret = secrets.token_hex(32)
            self.connection.execute("INSERT OR IGNORE INTO auth_settings(key, value) VALUES ('session_secret', ?)", (secret,))
            return str(self.connection.execute(
                "SELECT value FROM auth_settings WHERE key = 'session_secret'"
            ).fetchone()["value"])

    def has_admin_password(self) -> bool:
        with self._lock:
            return self.connection.execute(
                "SELECT 1 FROM auth_settings WHERE key = 'admin_password_hash'"
            ).fetchone() is not None

    def set_admin_password(self, password: str) -> None:
        if not 12 <= len(password) <= 1024:
            raise ValueError("admin password must be between 12 and 1024 characters")
        password_hash = generate_password_hash(password, method="scrypt")
        with self._lock, self.connection:
            self.connection.execute(
                "INSERT OR REPLACE INTO auth_settings(key, value) VALUES ('admin_password_hash', ?)",
                (password_hash,),
            )
            self.connection.execute(
                "INSERT OR REPLACE INTO auth_settings(key, value) VALUES ('auth_version', ?)",
                (secrets.token_hex(16),),
            )

    def verify_admin_password(self, password: str) -> bool:
        if len(password) > 1024:
            return False
        with self._lock:
            row = self.connection.execute(
                "SELECT value FROM auth_settings WHERE key = 'admin_password_hash'"
            ).fetchone()
        return bool(row) and check_password_hash(str(row["value"]), password)

    def auth_version(self) -> str | None:
        with self._lock:
            row = self.connection.execute("SELECT value FROM auth_settings WHERE key = 'auth_version'").fetchone()
        return str(row["value"]) if row else None

    def add_incident_note(self, incident_id: str, body: str, author: str = "admin") -> dict[str, str]:
        body = body.strip()
        if not body or len(body) > 2000:
            raise ValueError("note must be between 1 and 2000 characters")
        note = {"note_id": uuid.uuid4().hex, "incident_id": incident_id,
                "created_at": utc_now(), "author": author, "body": body}
        with self._lock, self.connection:
            if self.connection.execute(
                "SELECT 1 FROM incidents WHERE incident_id = ?", (incident_id,)
            ).fetchone() is None:
                raise KeyError(incident_id)
            self.connection.execute(
                "INSERT INTO incident_notes(note_id, incident_id, created_at, author, body) VALUES (?, ?, ?, ?, ?)",
                (note["note_id"], note["incident_id"], note["created_at"], note["author"], note["body"]),
            )
        return note

    def list_alerts(self, limit: int = 100) -> list[dict[str, Any]]:
        rows = self.connection.execute("SELECT payload FROM alerts ORDER BY last_seen DESC LIMIT ?", (max(1, min(limit, 1000)),)).fetchall()
        return [json.loads(row["payload"]) for row in rows]

    def list_incidents(self, limit: int = 100) -> list[dict[str, Any]]:
        rows = self.connection.execute("SELECT payload FROM incidents ORDER BY last_seen DESC LIMIT ?", (max(1, min(limit, 1000)),)).fetchall()
        return [json.loads(row["payload"]) for row in rows]

    def page_incidents(
        self, limit: int = 25, offset: int = 0, state: str = "all", query: str = ""
    ) -> dict[str, Any]:
        limit = max(1, min(limit, 100))
        offset = max(0, offset)
        clauses: list[str] = []
        params: list[Any] = []
        if state != "all":
            clauses.append("state = ?")
            params.append(state)
        if query:
            clauses.append("(payload LIKE ? ESCAPE '\\' OR EXISTS ("
                           "SELECT 1 FROM alerts WHERE alerts.incident_id = incidents.incident_id "
                           "AND alerts.payload LIKE ? ESCAPE '\\'))")
            escaped = query[:100].replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            params.extend((f"%{escaped}%", f"%{escaped}%"))
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        with self._lock:
            total = self.connection.execute("SELECT COUNT(*) FROM incidents" + where, params).fetchone()[0]
            rows = self.connection.execute(
                "SELECT payload FROM incidents" + where + " ORDER BY last_seen DESC LIMIT ? OFFSET ?",
                (*params, limit, offset),
            ).fetchall()
            items = []
            for row in rows:
                incident = json.loads(row["payload"])
                if not incident.get("title") or not incident.get("severity"):
                    latest = self.connection.execute(
                        "SELECT payload FROM alerts WHERE incident_id = ? ORDER BY last_seen DESC LIMIT 1",
                        (incident["incident_id"],),
                    ).fetchone()
                    if latest:
                        alert = json.loads(latest["payload"])
                        incident.setdefault("title", alert.get("title"))
                        incident.setdefault("severity", alert.get("severity"))
                        incident.setdefault("subject", alert.get("file_path") or alert.get("source_ip")
                                            or alert.get("evidence", {}).get("username"))
                items.append(incident)
        return {"items": items, "total": total,
                "limit": limit, "offset": offset}

    def incident_counts(self) -> dict[str, Any]:
        with self._lock:
            rows = self.connection.execute(
                "SELECT state, COUNT(*) AS count FROM incidents GROUP BY state"
            ).fetchall()
            alerts = self.connection.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
            high_alerts = self.connection.execute(
                "SELECT COUNT(*) FROM alerts WHERE severity IN ('high', 'critical') AND status != 'false_positive'"
            ).fetchone()[0]
            severity_rows = self.connection.execute(
                "SELECT severity, COUNT(*) AS count FROM alerts WHERE status != 'false_positive' GROUP BY severity"
            ).fetchall()
            activity_rows = self.connection.execute(
                "SELECT substr(first_seen, 1, 10) AS day, COUNT(*) AS count FROM incidents "
                "WHERE first_seen >= date('now', '-6 days') GROUP BY day ORDER BY day"
            ).fetchall()
        states = {row["state"]: row["count"] for row in rows}
        return {"incidents": sum(states.values()), "open_incidents": sum(
            count for state, count in states.items() if state != "resolved"),
            "alerts": alerts, "high_alerts": high_alerts,
            "severity_counts": {row["severity"]: row["count"] for row in severity_rows},
            "activity": [{"day": row["day"], "count": row["count"]} for row in activity_rows]}

    def get_incident(self, incident_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self.connection.execute(
                "SELECT payload FROM incidents WHERE incident_id = ?", (incident_id,)
            ).fetchone()
        return json.loads(row["payload"]) if row else None

    def get_incident_detail(self, incident_id: str) -> dict[str, Any] | None:
        incident = self.get_incident(incident_id)
        if incident is None:
            return None
        with self._lock:
            alert_rows = self.connection.execute(
                "SELECT payload FROM alerts WHERE incident_id = ? ORDER BY last_seen DESC", (incident_id,)
            ).fetchall()
            alerts = [json.loads(row["payload"]) for row in alert_rows]
            detections = self._records_by_ids("detections", "detection_id", incident.get("detection_ids", []))
            event_ids = list(dict.fromkeys(
                event_id for detection in detections for event_id in detection.get("event_ids", [])
            ))
            events = self._records_by_ids("host_events", "event_id", event_ids)
            note_rows = self.connection.execute(
                "SELECT note_id, incident_id, created_at, author, body FROM incident_notes "
                "WHERE incident_id = ? ORDER BY created_at DESC", (incident_id,)
            ).fetchall()
            notes = [dict(row) for row in note_rows]
        paths = [alert.get("file_path") for alert in alerts]
        paths.extend(event.get("file_path") for event in events)
        affected_files = sorted({path for path in paths if path})
        return {"incident": incident, "alerts": alerts, "detections": detections,
                "events": events, "affected_files": affected_files, "notes": notes}

    def _records_by_ids(self, table: str, id_column: str, ids: list[str]) -> list[dict[str, Any]]:
        # Table and column names are fixed by the callers; IDs remain bound parameters.
        records: dict[str, dict[str, Any]] = {}
        for start in range(0, len(ids), 500):
            chunk = ids[start:start + 500]
            placeholders = ",".join("?" for _ in chunk)
            rows = self.connection.execute(
                f"SELECT {id_column}, payload FROM {table} WHERE {id_column} IN ({placeholders})", chunk
            ).fetchall()
            records.update({row[id_column]: json.loads(row["payload"]) for row in rows})
        return [records[item_id] for item_id in ids if item_id in records]

    def close(self) -> None:
        with self._lock:
            self.connection.close()
