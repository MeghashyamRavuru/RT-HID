"""Additive migrations. Existing event and authentication tables remain intact."""
from __future__ import annotations

import sqlite3

MIGRATIONS = {
    2: """
        CREATE TABLE process_instances (
            instance_id TEXT PRIMARY KEY, host_id TEXT NOT NULL, pid INTEGER NOT NULL,
            created REAL NOT NULL, parent_id TEXT, first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL, stopped_at TEXT, event_id TEXT NOT NULL, payload TEXT NOT NULL
        );
        CREATE INDEX idx_process_host_pid ON process_instances(host_id, pid, created);
        CREATE INDEX idx_process_parent ON process_instances(parent_id);
        CREATE TABLE rule_settings (rule_id TEXT PRIMARY KEY, updated_at TEXT NOT NULL, payload TEXT NOT NULL);
    """,
    3: """
        CREATE TABLE indicators (
            indicator_id TEXT PRIMARY KEY, type TEXT NOT NULL, value TEXT NOT NULL,
            enabled INTEGER NOT NULL, expires_at TEXT, payload TEXT NOT NULL,
            UNIQUE(type, value)
        );
        CREATE INDEX idx_ioc_match ON indicators(type,value,enabled,expires_at);
        CREATE TABLE persistence_baselines (
            scope TEXT NOT NULL, entry TEXT NOT NULL, payload TEXT NOT NULL,
            PRIMARY KEY(scope,entry)
        );
    """,
    4: """
        CREATE INDEX idx_detections_host_time ON detections(host_id,timestamp);
        CREATE INDEX idx_events_host_time ON host_events(host_id,timestamp);
        CREATE INDEX idx_alerts_detection ON alerts(json_extract(payload,'$.detection_id'));
    """,
    5: """
        CREATE TABLE background_jobs (
            job_id TEXT PRIMARY KEY, kind TEXT NOT NULL, status TEXT NOT NULL,
            created_at TEXT NOT NULL, updated_at TEXT NOT NULL, payload TEXT NOT NULL
        );
        CREATE INDEX idx_jobs_time ON background_jobs(created_at);
    """,
    6: """
        CREATE TABLE audit_history (
            sequence INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL,
            actor TEXT NOT NULL, action TEXT NOT NULL, target TEXT NOT NULL,
            result TEXT NOT NULL, reason TEXT NOT NULL, previous_hash TEXT NOT NULL, entry_hash TEXT NOT NULL
        );
        CREATE TRIGGER audit_no_update BEFORE UPDATE ON audit_history BEGIN SELECT RAISE(ABORT,'audit history is append only'); END;
        CREATE TRIGGER audit_no_delete BEFORE DELETE ON audit_history BEGIN SELECT RAISE(ABORT,'audit history is append only'); END;
        CREATE TABLE response_requests (
            token_hash TEXT PRIMARY KEY, actor_version TEXT NOT NULL, expires_at REAL NOT NULL,
            used INTEGER NOT NULL, payload TEXT NOT NULL
        );
    """,
    7: """
        CREATE TABLE detection_events(detection_id TEXT NOT NULL,event_id TEXT NOT NULL,PRIMARY KEY(detection_id,event_id));
        CREATE INDEX idx_detection_events_event ON detection_events(event_id);
        CREATE TABLE incident_detections(incident_id TEXT NOT NULL,detection_id TEXT NOT NULL,PRIMARY KEY(incident_id,detection_id));
        CREATE INDEX idx_incident_detections_detection ON incident_detections(detection_id);
        CREATE TABLE incident_events(incident_id TEXT NOT NULL,event_id TEXT NOT NULL,PRIMARY KEY(incident_id,event_id));
        CREATE INDEX idx_incident_events_event ON incident_events(event_id);
        INSERT OR IGNORE INTO detection_events SELECT detection_id,ids.value FROM detections,json_each(detections.payload,'$.event_ids') AS ids;
        INSERT OR IGNORE INTO incident_detections SELECT incident_id,ids.value FROM incidents,json_each(incidents.payload,'$.detection_ids') AS ids;
        INSERT OR IGNORE INTO incident_events SELECT incident_id,ids.value FROM incidents,json_each(incidents.payload,'$.event_ids') AS ids;
        CREATE INDEX idx_process_event ON process_instances(event_id);
        CREATE INDEX idx_detections_host_epoch ON detections(host_id,julianday(timestamp));
    """,
}


def migrate(connection: sqlite3.Connection) -> None:
    current = int(connection.execute("SELECT value FROM schema_meta WHERE key='schema_version'").fetchone()[0])
    if current > max(MIGRATIONS):
        raise ValueError("database schema is newer than this RT-HID version")
    for version, script in sorted(MIGRATIONS.items()):
        if version <= current:
            continue
        try:
            connection.executescript("BEGIN IMMEDIATE;\n" + script +
                                     f"\nUPDATE schema_meta SET value='{version}' WHERE key='schema_version'; COMMIT;")
        except Exception:
            connection.rollback()
            raise
