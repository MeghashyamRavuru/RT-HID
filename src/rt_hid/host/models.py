from __future__ import annotations

import json
import math
import socket
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Mapping

from . import HOST_SCHEMA_VERSION

EVENT_TYPES = {
    "auth",
    "process_start",
    "process_stop",
    "network_listen",
    "network_connection",
    "file_change",
    "system_snapshot",
    "collector_status",
    "security_change",
    "persistence_change",
    "file_scan",
}
SEVERITIES = {"informational", "low", "medium", "high", "critical"}
OUTCOMES = {"success", "failure", "observed", "unknown"}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class HostEvent:
    event_id: str
    timestamp: str
    hostname: str
    host_id: str
    event_type: str
    source: str
    severity: str = "informational"
    username: str | None = None
    process_id: int | None = None
    parent_process_id: int | None = None
    process_name: str | None = None
    executable_path: str | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    destination_port: int | None = None
    protocol: str | None = None
    file_path: str | None = None
    action: str | None = None
    outcome: str = "unknown"
    evidence: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def create(cls, host_id: str, event_type: str, source: str, **kwargs: Any) -> "HostEvent":
        return cls(
            event_id=kwargs.pop("event_id", uuid.uuid4().hex),
            timestamp=kwargs.pop("timestamp", utc_now()),
            hostname=kwargs.pop("hostname", socket.gethostname()),
            host_id=host_id,
            event_type=event_type,
            source=source,
            **kwargs,
        )

    def __post_init__(self) -> None:
        if not self.event_id or not self.host_id or not self.hostname or not self.source:
            raise ValueError("event_id, host_id, hostname, and source are required")
        if self.event_type not in EVENT_TYPES:
            raise ValueError(f"unsupported host event type: {self.event_type}")
        if self.severity not in SEVERITIES:
            raise ValueError(f"unsupported severity: {self.severity}")
        if self.outcome not in OUTCOMES:
            raise ValueError(f"unsupported outcome: {self.outcome}")
        if self.destination_port is not None and not 0 <= self.destination_port <= 65535:
            raise ValueError("destination_port must be between 0 and 65535")
        if self.process_id is not None and self.process_id < 0:
            raise ValueError("process_id must be non-negative")
        if self.parent_process_id is not None and self.parent_process_id < 0:
            raise ValueError("parent_process_id must be non-negative")
        json.dumps(self.evidence)
        json.dumps(self.metadata)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class CollectorStatus:
    collector_id: str
    platform: str
    available: bool
    enabled: bool
    last_success: str | None = None
    last_error: str | None = None
    detail: str = ""
    state: str = "stopped"
    last_duration_seconds: float | None = None
    processes_inspected: int = 0
    events_generated: int = 0
    inaccessible_processes: int = 0
    collection_errors: int = 0
    capabilities: dict[str, Any] = field(default_factory=dict)
    unavailable_locations: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class Detection:
    detection_id: str
    rule_id: str
    rule_name: str
    category: str
    tactic: str
    technique_id: str | None
    severity: str
    confidence: float
    timestamp: str
    event_ids: tuple[str, ...]
    reason: str
    evidence: dict[str, Any]
    investigation: str
    host_id: str
    rule_version: str = "1.0.0"
    related_detection_ids: tuple[str, ...] = ()

    @classmethod
    def create(cls, **kwargs: Any) -> "Detection":
        return cls(detection_id=uuid.uuid4().hex, **kwargs)

    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES:
            raise ValueError(f"unsupported detection severity: {self.severity}")
        if not 0.0 <= self.confidence <= 1.0 or not math.isfinite(self.confidence):
            raise ValueError("confidence must be finite and between 0 and 1")
        if not self.event_ids:
            raise ValueError("detections require event evidence")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
