from __future__ import annotations

import threading
import uuid
from collections import deque
from datetime import datetime, timedelta, timezone
from typing import Any

from ..config import HostConfig
from ..models import Detection
from ..storage import HostDatabase


class HostAlertManager:
    def __init__(self, database: HostDatabase, config: HostConfig) -> None:
        self.database = database
        self.config = config
        self._lock = threading.RLock()
        self._seen: set[str] = set()
        self._seen_order: deque[str] = deque(maxlen=10_000)
        self._last_by_group: dict[str, datetime] = {}

    def consume(self, detection: Detection) -> dict[str, Any] | None:
        with self._lock:
            if detection.detection_id in self._seen:
                return None
            self._remember(detection.detection_id)
            subject = (detection.evidence.get("source_ip") or detection.evidence.get("file_path")
                       or detection.evidence.get("target_account") or detection.evidence.get("service_name")
                       or detection.evidence.get("username") or detection.evidence.get("port") or "host")
            group = f"{detection.host_id}|{detection.rule_id}|{subject}"
            now = _timestamp(detection.timestamp)
            previous = self._last_by_group.get(group)
            if previous and now - previous < timedelta(seconds=self.config.alert_cooldown_seconds):
                return None
            self._last_by_group[group] = now
            incident_id = self._incident_id(group)
            existing = self.database.get_incident(incident_id)
            state = "updated" if existing else "new"
            state_history = list(existing.get("state_history", [])) if existing else []
            if existing and existing.get("state") != state:
                state_history.append(existing["state"])
            alert = {
                "alert_id": uuid.uuid4().hex,
                "incident_id": incident_id,
                "hostname": detection.evidence.get("hostname", ""),
                "host_id": detection.host_id,
                "detection_id": detection.detection_id,
                "rule_id": detection.rule_id,
                "title": detection.rule_name,
                "description": detection.reason,
                "category": detection.category,
                "severity": detection.severity,
                "confidence": detection.confidence,
                "first_seen": existing.get("first_seen", detection.timestamp) if existing else detection.timestamp,
                "last_seen": detection.timestamp,
                "event_count": len(detection.event_ids),
                "source_ip": detection.evidence.get("source_ip"),
                "process_name": detection.evidence.get("process_name"),
                "file_path": detection.evidence.get("file_path"),
                "evidence": detection.evidence,
                "investigation_recommendation": detection.investigation,
                "status": "new",
                "state": state,
                "state_history": state_history[-20:],
                "tactic": detection.tactic,
                "technique_id": detection.technique_id,
            }
            incident = {
                "incident_id": incident_id,
                "state": state,
                "first_seen": existing.get("first_seen", detection.timestamp) if existing else detection.timestamp,
                "last_seen": detection.timestamp,
                "host_id": detection.host_id,
                "rule_id": detection.rule_id,
                "title": detection.rule_name,
                "severity": detection.severity,
                "category": detection.category,
                "subject": str(subject),
                "file_path": detection.evidence.get("file_path"),
                "source_ip": detection.evidence.get("source_ip"),
                "alert_ids": (existing.get("alert_ids", []) if existing else []) + [alert["alert_id"]],
                "detection_ids": (existing.get("detection_ids", []) if existing else []) + [detection.detection_id],
            }
            self.database.save_detection(detection)
            self.database.save_alert(alert)
            self.database.save_incident(incident)
            return alert

    def acknowledge(self, incident_id: str) -> None:
        self.database.set_incident_state(incident_id, "acknowledged")

    def resolve(self, incident_id: str) -> None:
        self.database.set_incident_state(incident_id, "resolved")

    def false_positive(self, alert_id: str) -> None:
        self.database.set_alert_status(alert_id, "false_positive")

    def shutdown(self) -> None:
        with self._lock:
            self._seen.clear()
            self._seen_order.clear()
            self._last_by_group.clear()

    def _remember(self, detection_id: str) -> None:
        if len(self._seen_order) == self._seen_order.maxlen:
            self._seen.discard(self._seen_order.popleft())
        self._seen.add(detection_id)
        self._seen_order.append(detection_id)

    @staticmethod
    def _incident_id(group: str) -> str:
        return uuid.uuid5(uuid.NAMESPACE_URL, f"rt-nid-ml:{group}").hex


def _timestamp(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
