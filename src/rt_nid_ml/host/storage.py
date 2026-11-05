from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any

from .models import CollectorStatus, Detection, HostEvent, utc_now


class HostDatabase:
    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self.connection = sqlite3.connect(self.path, check_same_thread=False)
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
            payload["status"] = status
            self.connection.execute("UPDATE alerts SET status = ?, payload = ? WHERE alert_id = ?", (status, json.dumps(payload), alert_id))

    def set_incident_state(self, incident_id: str, state: str) -> None:
        with self._lock, self.connection:
            row = self.connection.execute("SELECT payload FROM incidents WHERE incident_id = ?", (incident_id,)).fetchone()
            if row is None:
                raise KeyError(incident_id)
            payload = json.loads(row["payload"])
            payload["state"] = state
            self.connection.execute("UPDATE incidents SET state = ?, payload = ? WHERE incident_id = ?", (state, json.dumps(payload), incident_id))

    def set_checkpoint(self, checkpoint_id: str, value: str) -> None:
        with self._lock, self.connection:
            self.connection.execute(
                "INSERT OR REPLACE INTO checkpoints(checkpoint_id, value, updated_at) VALUES (?, ?, ?)",
                (checkpoint_id, value, utc_now()),
            )

    def get_checkpoint(self, checkpoint_id: str) -> str | None:
        row = self.connection.execute("SELECT value FROM checkpoints WHERE checkpoint_id = ?", (checkpoint_id,)).fetchone()
        return None if row is None else str(row["value"])

    def list_alerts(self, limit: int = 100) -> list[dict[str, Any]]:
        rows = self.connection.execute("SELECT payload FROM alerts ORDER BY last_seen DESC LIMIT ?", (max(1, min(limit, 1000)),)).fetchall()
        return [json.loads(row["payload"]) for row in rows]

    def list_incidents(self, limit: int = 100) -> list[dict[str, Any]]:
        rows = self.connection.execute("SELECT payload FROM incidents ORDER BY last_seen DESC LIMIT ?", (max(1, min(limit, 1000)),)).fetchall()
        return [json.loads(row["payload"]) for row in rows]

    def close(self) -> None:
        with self._lock:
            self.connection.close()
