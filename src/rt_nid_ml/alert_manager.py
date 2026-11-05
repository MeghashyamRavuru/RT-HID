"""False-positive controls, alert correlation, and incident lifecycle management."""

from __future__ import annotations

import math
import threading
import uuid
from collections import Counter, defaultdict, deque
from dataclasses import asdict, dataclass, field
from typing import Any, Iterable

from .flow_extractor import LIVE_FLOW_FEATURE_COLUMNS
from .live_detector import DetectionResult

SEVERITIES = {"informational", "low", "medium", "high", "critical"}
INCIDENT_STATES = {"new", "updated", "acknowledged", "resolved"}


class AlertManagerError(ValueError):
    """Raised when a detection result or manager configuration is invalid."""


@dataclass(frozen=True)
class AlertManagerConfig:
    sensor_id: str
    correlation_window_seconds: float = 60.0
    port_scan_min_distinct_ports: int = 5
    brute_force_min_events: int = 5
    dos_min_events: int = 20
    dos_min_rate_per_second: float = 10.0
    alert_cooldown_seconds: float = 60.0
    source_rate_limit: int = 30
    source_rate_window_seconds: float = 60.0
    incident_retention_seconds: float = 3600.0
    max_events: int = 10_000
    max_alerts: int = 10_000
    max_incidents: int = 2_000
    allowlisted_sources: frozenset[str] = frozenset()
    allowlisted_destinations: frozenset[str] = frozenset()
    allowlisted_services: frozenset[int] = frozenset()
    sensitive_services: frozenset[int] = frozenset({21, 22, 23, 445, 3389})

    def __post_init__(self) -> None:
        if not self.sensor_id:
            raise AlertManagerError("sensor_id is required")
        for name in (
            "correlation_window_seconds",
            "dos_min_rate_per_second",
            "alert_cooldown_seconds",
            "source_rate_window_seconds",
            "incident_retention_seconds",
        ):
            if getattr(self, name) <= 0:
                raise AlertManagerError(f"{name} must be positive")
        for name in (
            "port_scan_min_distinct_ports",
            "brute_force_min_events",
            "dos_min_events",
            "source_rate_limit",
            "max_events",
            "max_alerts",
            "max_incidents",
        ):
            if getattr(self, name) < 1:
                raise AlertManagerError(f"{name} must be positive")


@dataclass(frozen=True)
class SecurityAlert:
    alert_id: str
    incident_id: str
    first_seen: float
    last_seen: float
    source_ip: str
    destination_ip: str
    destination_ports: tuple[int, ...]
    protocol: str
    attack_category: str
    severity: str
    confidence: float
    related_event_count: int
    correlation_rule: str
    evidence_summary: str
    original_detection_references: tuple[str, ...]
    raw_detection_evidence: tuple[dict[str, Any], ...]
    suppression_status: str
    suppression_reason: str
    sensor_id: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Incident:
    incident_id: str
    grouping_key: str
    state: str
    first_seen: float
    last_seen: float
    source_ip: str
    destination_ip: str
    attack_category: str
    alert_ids: list[str] = field(default_factory=list)
    event_ids: list[str] = field(default_factory=list)
    related_event_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AlertManagerMetrics:
    detections_seen: int = 0
    benign_events: int = 0
    unknown_events: int = 0
    alerts_created: int = 0
    alerts_updated: int = 0
    alerts_suppressed: int = 0
    correlated_events: int = 0
    incidents_created: int = 0
    incidents_updated: int = 0
    incidents_expired: int = 0
    invalid_detections: int = 0


@dataclass(frozen=True)
class _Event:
    detection: DetectionResult
    received_at: float


class AlertManager:
    """Consume immutable detections and produce bounded security alerts."""

    def __init__(self, config: AlertManagerConfig) -> None:
        self.config = config
        self.metrics = AlertManagerMetrics()
        self._lock = threading.RLock()
        self._events: deque[_Event] = deque(maxlen=config.max_events)
        self._alerts: deque[SecurityAlert] = deque(maxlen=config.max_alerts)
        self._incidents: dict[str, Incident] = {}
        self._event_ids: set[str] = set()
        self._event_id_order: deque[str] = deque(maxlen=config.max_events)
        self._source_alert_times: dict[str, deque[float]] = defaultdict(deque)
        self._last_alert_by_group: dict[str, float] = {}

    def consume(self, detection: DetectionResult) -> SecurityAlert | None:
        """Process a detection without changing its original evidence."""
        with self._lock:
            self._validate_detection(detection)
            self.metrics.detections_seen += 1
            now = float(detection.event_timestamp)
            self._cleanup(now)
            if detection.event_id in self._event_ids:
                self.metrics.alerts_suppressed += 1
                return self._store_alert(self._make_suppressed(detection, "duplicate_detection"))
            self._event_ids.add(detection.event_id)
            if len(self._event_id_order) == self._event_id_order.maxlen:
                self._event_ids.discard(self._event_id_order.popleft())
            self._event_id_order.append(detection.event_id)
            self._events.append(_Event(detection, now))

            if detection.decision_status == "benign":
                self.metrics.benign_events += 1
                return None
            if detection.decision_status != "detected":
                self.metrics.unknown_events += 1
                return self._store_alert(self._make_informational_unknown(detection))

            suppression = self._suppression_reason(detection, now)
            if suppression:
                self.metrics.alerts_suppressed += 1
                return self._store_alert(self._make_suppressed(detection, suppression))

            related = self._related_events(detection, now)
            rule, category = self._correlation_rule(detection, related, now)
            if len(related) > 1:
                self.metrics.correlated_events += len(related) - 1
            group = self._grouping_key(detection, category)
            cooldown_reason = self._cooldown_reason(group, now)
            if cooldown_reason:
                self.metrics.alerts_suppressed += 1
                return self._store_alert(self._make_suppressed(
                    detection, cooldown_reason, related=related, category=category
                ))

            incident = self._get_or_create_incident(group, detection, category, now)
            severity = self._severity(detection, category, related, now)
            confidence = self._confidence(related)
            alert = self._build_alert(
                detection=detection,
                incident=incident,
                related=related,
                category=category,
                severity=severity,
                confidence=confidence,
                rule=rule,
            )
            self._alerts.append(alert)
            self._last_alert_by_group[group] = now
            self._source_alert_times[detection.source_ip].append(now)
            incident.alert_ids.append(alert.alert_id)
            incident.event_ids.extend(event.detection.event_id for event in related)
            incident.related_event_count = max(incident.related_event_count, len(related))
            self.metrics.alerts_created += 1
            return alert

    def acknowledge_incident(self, incident_id: str) -> Incident:
        with self._lock:
            incident = self._require_incident(incident_id)
            if incident.state != "resolved":
                incident.state = "acknowledged"
            return incident

    def resolve_incident(self, incident_id: str) -> Incident:
        with self._lock:
            incident = self._require_incident(incident_id)
            incident.state = "resolved"
            return incident

    def get_incident(self, incident_id: str) -> Incident | None:
        with self._lock:
            return next(
                (
                    incident
                    for incident in self._incidents.values()
                    if incident.incident_id == incident_id
                ),
                None,
            )

    def incidents(self) -> list[Incident]:
        with self._lock:
            return list(self._incidents.values())

    def alerts(self) -> list[SecurityAlert]:
        with self._lock:
            return list(self._alerts)

    def shutdown(self) -> None:
        with self._lock:
            self._events.clear()
            self._source_alert_times.clear()

    def _validate_detection(self, detection: DetectionResult) -> None:
        if not isinstance(detection, DetectionResult):
            self.metrics.invalid_detections += 1
            raise AlertManagerError("expected a DetectionResult")
        if not detection.event_id or not detection.flow_id:
            self.metrics.invalid_detections += 1
            raise AlertManagerError("detection event_id and flow_id are required")
        if not math.isfinite(detection.event_timestamp):
            self.metrics.invalid_detections += 1
            raise AlertManagerError("detection timestamp must be finite")
        if detection.calibrated_probability is not None and not 0.0 <= detection.calibrated_probability <= 1.0:
            self.metrics.invalid_detections += 1
            raise AlertManagerError("detection probability must be between 0 and 1")
        if detection.decision_status not in {"benign", "detected", "unknown"}:
            self.metrics.invalid_detections += 1
            raise AlertManagerError("invalid detection decision status")
        if set(detection.features) != set(LIVE_FLOW_FEATURE_COLUMNS):
            self.metrics.invalid_detections += 1
            raise AlertManagerError("detection feature schema is invalid")
        if detection.decision_status == "detected" and any(
            value is None
            or not isinstance(value, (int, float))
            or not math.isfinite(float(value))
            for value in detection.features.values()
        ):
            self.metrics.invalid_detections += 1
            raise AlertManagerError("detected result contains invalid features")

    def _suppression_reason(self, detection: DetectionResult, now: float) -> str:
        if detection.source_ip in self.config.allowlisted_sources:
            return "allowlisted_source"
        if detection.destination_ip in self.config.allowlisted_destinations:
            return "allowlisted_destination"
        if detection.destination_port in self.config.allowlisted_services:
            return "allowlisted_service"
        times = self._source_alert_times[detection.source_ip]
        while times and now - times[0] > self.config.source_rate_window_seconds:
            times.popleft()
        if len(times) >= self.config.source_rate_limit:
            return "source_alert_rate_limit"
        return ""

    def _is_allowlisted(self, detection: DetectionResult) -> bool:
        return (
            detection.source_ip in self.config.allowlisted_sources
            or detection.destination_ip in self.config.allowlisted_destinations
            or detection.destination_port in self.config.allowlisted_services
        )

    def _related_events(self, detection: DetectionResult, now: float) -> list[_Event]:
        lower = now - self.config.correlation_window_seconds
        return [
            event
            for event in self._events
            if lower <= event.detection.event_timestamp <= now
            and event.detection.decision_status == "detected"
            and event.detection.source_ip == detection.source_ip
            and not self._is_allowlisted(event.detection)
        ]

    def _correlation_rule(
        self, detection: DetectionResult, related: list[_Event], now: float
    ) -> tuple[str, str]:
        category = detection.predicted_label
        if category in {"port_scan", "suspicious"}:
            ports = {
                event.detection.destination_port
                for event in related
                if event.detection.predicted_label in {"port_scan", "suspicious"}
            }
            if len(ports) >= self.config.port_scan_min_distinct_ports:
                return "port_scan_distinct_ports", "port_scan"
        if category in {"brute_force", "suspicious"}:
            brute_events = [
                event for event in related
                if event.detection.predicted_label in {"brute_force", "suspicious"}
                and event.detection.destination_ip == detection.destination_ip
                and event.detection.destination_port == detection.destination_port
            ]
            if len(brute_events) >= self.config.brute_force_min_events:
                return "brute_force_repeated_service", "brute_force"
        if category in {"dos", "suspicious"}:
            dos_events = [
                event for event in related
                if event.detection.predicted_label in {"dos", "suspicious"}
                and event.detection.destination_ip == detection.destination_ip
            ]
            elapsed = max(now - min((event.detection.event_timestamp for event in dos_events), default=now), 1e-9)
            if len(dos_events) >= self.config.dos_min_events and len(dos_events) / elapsed >= self.config.dos_min_rate_per_second:
                return "dos_repeated_target_rate", "dos"
        return "single_detected_event", category

    def _grouping_key(self, detection: DetectionResult, category: str) -> str:
        if category == "port_scan":
            return f"port_scan|{detection.source_ip}"
        return f"{category}|{detection.source_ip}|{detection.destination_ip}"

    def _cooldown_reason(self, group: str, now: float) -> str:
        previous = self._last_alert_by_group.get(group)
        if previous is not None and now - previous < self.config.alert_cooldown_seconds:
            return "alert_cooldown"
        return ""

    def _get_or_create_incident(
        self, group: str, detection: DetectionResult, category: str, now: float
    ) -> Incident:
        incident = self._incidents.get(group)
        if incident is not None:
            incident.last_seen = now
            if incident.state == "new":
                incident.state = "updated"
            elif incident.state == "resolved":
                incident.state = "updated"
            self.metrics.incidents_updated += 1
            self.metrics.alerts_updated += 1
            return incident
        if len(self._incidents) >= self.config.max_incidents:
            oldest_key = min(self._incidents, key=lambda key: self._incidents[key].last_seen)
            del self._incidents[oldest_key]
        incident = Incident(
            incident_id=uuid.uuid4().hex,
            grouping_key=group,
            state="new",
            first_seen=now,
            last_seen=now,
            source_ip=detection.source_ip,
            destination_ip=detection.destination_ip,
            attack_category=category,
        )
        self._incidents[group] = incident
        self.metrics.incidents_created += 1
        return incident

    def _severity(
        self, detection: DetectionResult, category: str, related: list[_Event], now: float
    ) -> str:
        if category == "dos":
            severity = "high"
        elif category == "brute_force":
            severity = "medium"
        elif category == "port_scan":
            severity = "medium" if len(related) >= self.config.port_scan_min_distinct_ports else "low"
        else:
            severity = "low"
        if detection.destination_port in self.config.sensitive_services and severity == "low":
            severity = "medium"
        if len(related) >= max(self.config.dos_min_events * 2, 2) and category == "dos":
            severity = "critical"
        return severity

    @staticmethod
    def _confidence(related: list[_Event]) -> float:
        probabilities = [
            event.detection.calibrated_probability
            for event in related
            if event.detection.calibrated_probability is not None
        ]
        return round(sum(probabilities) / len(probabilities), 6) if probabilities else 0.0

    def _build_alert(
        self,
        detection: DetectionResult,
        incident: Incident,
        related: list[_Event],
        category: str,
        severity: str,
        confidence: float,
        rule: str,
    ) -> SecurityAlert:
        ports = tuple(sorted({event.detection.destination_port for event in related}))
        references = tuple(event.detection.event_id for event in related)
        evidence = tuple(event.detection.to_dict() for event in related)
        return SecurityAlert(
            alert_id=uuid.uuid4().hex,
            incident_id=incident.incident_id,
            first_seen=min(event.detection.event_timestamp for event in related),
            last_seen=max(event.detection.event_timestamp for event in related),
            source_ip=detection.source_ip,
            destination_ip=detection.destination_ip,
            destination_ports=ports,
            protocol=detection.protocol,
            attack_category=category,
            severity=severity,
            confidence=confidence,
            related_event_count=len(related),
            correlation_rule=rule,
            evidence_summary=f"{len(related)} detected event(s); category={category}",
            original_detection_references=references,
            raw_detection_evidence=evidence,
            suppression_status="not_suppressed",
            suppression_reason="",
            sensor_id=self.config.sensor_id,
        )

    def _make_suppressed(
        self,
        detection: DetectionResult,
        reason: str,
        related: list[_Event] | None = None,
        category: str | None = None,
    ) -> SecurityAlert:
        related = related or [_Event(detection, detection.event_timestamp)]
        return SecurityAlert(
            alert_id=uuid.uuid4().hex,
            incident_id="",
            first_seen=detection.event_timestamp,
            last_seen=detection.event_timestamp,
            source_ip=detection.source_ip,
            destination_ip=detection.destination_ip,
            destination_ports=(detection.destination_port,),
            protocol=detection.protocol,
            attack_category=category or detection.predicted_label,
            severity="informational",
            confidence=float(detection.calibrated_probability or 0.0),
            related_event_count=len(related),
            correlation_rule="suppressed_event",
            evidence_summary=f"suppressed event retained: {reason}",
            original_detection_references=tuple(event.detection.event_id for event in related),
            raw_detection_evidence=tuple(event.detection.to_dict() for event in related),
            suppression_status="suppressed",
            suppression_reason=reason,
            sensor_id=self.config.sensor_id,
        )

    def _make_informational_unknown(self, detection: DetectionResult) -> SecurityAlert:
        return SecurityAlert(
            alert_id=uuid.uuid4().hex,
            incident_id="",
            first_seen=detection.event_timestamp,
            last_seen=detection.event_timestamp,
            source_ip=detection.source_ip,
            destination_ip=detection.destination_ip,
            destination_ports=(detection.destination_port,),
            protocol=detection.protocol,
            attack_category="unknown",
            severity="informational",
            confidence=float(detection.calibrated_probability or 0.0),
            related_event_count=1,
            correlation_rule="unknown_detection",
            evidence_summary=detection.decision_reason,
            original_detection_references=(detection.event_id,),
            raw_detection_evidence=(detection.to_dict(),),
            suppression_status="not_suppressed",
            suppression_reason="",
            sensor_id=self.config.sensor_id,
        )

    def _store_alert(self, alert: SecurityAlert) -> SecurityAlert:
        self._alerts.append(alert)
        return alert

    def _require_incident(self, incident_id: str) -> Incident:
        for incident in self._incidents.values():
            if incident.incident_id == incident_id:
                return incident
        raise AlertManagerError(f"incident not found: {incident_id}")

    def _cleanup(self, now: float) -> None:
        event_cutoff = now - self.config.correlation_window_seconds
        while self._events and self._events[0].detection.event_timestamp < event_cutoff:
            self._events.popleft()
        incident_cutoff = now - self.config.incident_retention_seconds
        expired = [
            key
            for key, incident in self._incidents.items()
            if incident.last_seen < incident_cutoff and incident.state != "acknowledged"
        ]
        for key in expired:
            del self._incidents[key]
            self.metrics.incidents_expired += 1
        for source, times in list(self._source_alert_times.items()):
            while times and now - times[0] > self.config.source_rate_window_seconds:
                times.popleft()
            if not times:
                del self._source_alert_times[source]
        cooldown_cutoff = now - self.config.alert_cooldown_seconds
        self._last_alert_by_group = {
            group: timestamp
            for group, timestamp in self._last_alert_by_group.items()
            if timestamp >= cooldown_cutoff
        }
