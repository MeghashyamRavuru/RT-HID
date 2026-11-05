import unittest

from rt_nid_ml.alert_manager import AlertManager, AlertManagerConfig, AlertManagerError
from rt_nid_ml.flow_extractor import LIVE_FLOW_FEATURE_COLUMNS
from rt_nid_ml.live_detector import DetectionResult


def detection(
    event_id: str,
    timestamp: float,
    label: str = "port_scan",
    source: str = "10.0.0.1",
    destination: str = "10.0.0.2",
    destination_port: int = 80,
    status: str = "detected",
    probability: float = 0.9,
) -> DetectionResult:
    return DetectionResult(
        result_schema_version=1,
        event_id=event_id,
        event_timestamp=timestamp,
        flow_id=f"flow-{event_id}",
        source_ip=source,
        source_port=40000,
        destination_ip=destination,
        destination_port=destination_port,
        protocol="TCP",
        predicted_label=label,
        calibrated_probability=probability,
        selected_threshold=0.5,
        model_version="test",
        feature_schema_version=1,
        decision_status=status,
        decision_reason="test evidence",
        flow_completion_reason="tcp_finished",
        features={column: 1.0 for column in LIVE_FLOW_FEATURE_COLUMNS},
    )


class AlertManagerTests(unittest.TestCase):
    def test_individual_detection_creates_structured_alert(self) -> None:
        manager = AlertManager(AlertManagerConfig(sensor_id="sensor-a"))

        alert = manager.consume(detection("e1", 1.0))

        self.assertIsNotNone(alert)
        self.assertEqual(alert.attack_category, "port_scan")
        self.assertEqual(alert.sensor_id, "sensor-a")
        self.assertEqual(alert.original_detection_references, ("e1",))
        self.assertEqual(alert.suppression_status, "not_suppressed")

    def test_port_scan_correlates_distinct_ports(self) -> None:
        manager = AlertManager(AlertManagerConfig(
            sensor_id="s", port_scan_min_distinct_ports=3, alert_cooldown_seconds=0.001
        ))
        manager.consume(detection("e1", 1.0, destination_port=21))
        manager.consume(detection("e2", 2.0, destination_port=22))
        alert = manager.consume(detection("e3", 3.0, destination_port=23))

        self.assertEqual(alert.correlation_rule, "port_scan_distinct_ports")
        self.assertEqual(alert.attack_category, "port_scan")
        self.assertEqual(alert.related_event_count, 3)
        self.assertEqual(set(alert.destination_ports), {21, 22, 23})

    def test_brute_force_correlates_same_service(self) -> None:
        manager = AlertManager(AlertManagerConfig(
            sensor_id="s", brute_force_min_events=3, alert_cooldown_seconds=0.001
        ))
        for index in range(2):
            manager.consume(detection(f"e{index}", float(index + 1), "brute_force", destination_port=22))
        alert = manager.consume(detection("e3", 3.0, "brute_force", destination_port=22))

        self.assertEqual(alert.correlation_rule, "brute_force_repeated_service")
        self.assertEqual(alert.severity, "medium")

    def test_dos_correlates_target_rate_without_claiming_authentication(self) -> None:
        manager = AlertManager(AlertManagerConfig(
            sensor_id="s", dos_min_events=3, dos_min_rate_per_second=1, alert_cooldown_seconds=0.001
        ))
        for index in range(2):
            manager.consume(detection(f"e{index}", float(index + 1), "dos", destination_port=443))
        alert = manager.consume(detection("e3", 3.0, "dos", destination_port=443))

        self.assertEqual(alert.correlation_rule, "dos_repeated_target_rate")
        self.assertEqual(alert.severity, "high")

    def test_allowlist_suppresses_but_preserves_evidence(self) -> None:
        manager = AlertManager(AlertManagerConfig(
            sensor_id="s", allowlisted_sources=frozenset({"10.0.0.1"})
        ))

        alert = manager.consume(detection("e1", 1.0))

        self.assertEqual(alert.suppression_status, "suppressed")
        self.assertEqual(alert.suppression_reason, "allowlisted_source")
        self.assertEqual(alert.original_detection_references, ("e1",))
        self.assertEqual(len(manager.alerts()), 1)
        self.assertEqual(len(manager.incidents()), 0)

    def test_duplicate_and_cooldown_suppression(self) -> None:
        manager = AlertManager(AlertManagerConfig(sensor_id="s", alert_cooldown_seconds=10))
        first = detection("e1", 1.0)
        manager.consume(first)
        duplicate = manager.consume(first)
        cooldown = manager.consume(detection("e2", 2.0))

        self.assertEqual(duplicate.suppression_reason, "duplicate_detection")
        self.assertEqual(cooldown.suppression_reason, "alert_cooldown")
        self.assertEqual(manager.metrics.alerts_suppressed, 2)

    def test_source_rate_limit_suppresses_events(self) -> None:
        manager = AlertManager(AlertManagerConfig(
            sensor_id="s", source_rate_limit=1, alert_cooldown_seconds=0.001
        ))
        manager.consume(detection("e1", 1.0))
        alert = manager.consume(detection("e2", 2.0))

        self.assertEqual(alert.suppression_reason, "source_alert_rate_limit")

    def test_unknown_prediction_is_informational_and_retains_evidence(self) -> None:
        manager = AlertManager(AlertManagerConfig(sensor_id="s"))

        alert = manager.consume(detection("e1", 1.0, status="unknown", probability=None))

        self.assertEqual(alert.attack_category, "unknown")
        self.assertEqual(alert.severity, "informational")
        self.assertEqual(manager.metrics.unknown_events, 1)

    def test_incident_updates_acknowledges_and_resolves(self) -> None:
        manager = AlertManager(AlertManagerConfig(sensor_id="s", alert_cooldown_seconds=0.001))
        first = manager.consume(detection("e1", 1.0))
        second = manager.consume(detection("e2", 2.0))
        incident = manager.get_incident(first.incident_id)

        self.assertEqual(second.incident_id, first.incident_id)
        self.assertEqual(incident.state, "updated")
        self.assertEqual(manager.acknowledge_incident(incident.incident_id).state, "acknowledged")
        self.assertEqual(manager.resolve_incident(incident.incident_id).state, "resolved")

    def test_expired_correlation_window_prevents_old_events(self) -> None:
        manager = AlertManager(AlertManagerConfig(
            sensor_id="s", correlation_window_seconds=5, port_scan_min_distinct_ports=2,
            alert_cooldown_seconds=0.001,
        ))
        manager.consume(detection("e1", 1.0, destination_port=21))
        alert = manager.consume(detection("e2", 20.0, destination_port=22))

        self.assertEqual(alert.correlation_rule, "single_detected_event")
        self.assertEqual(alert.related_event_count, 1)

    def test_capacity_limits_event_retention(self) -> None:
        manager = AlertManager(AlertManagerConfig(
            sensor_id="s", max_events=2, alert_cooldown_seconds=0.001
        ))
        for index in range(3):
            manager.consume(detection(f"e{index}", float(index + 1)))

        self.assertLessEqual(len(manager._events), 2)
        self.assertLessEqual(len(manager._event_ids), 2)

    def test_invalid_detection_result_is_rejected(self) -> None:
        manager = AlertManager(AlertManagerConfig(sensor_id="s"))

        with self.assertRaises(AlertManagerError):
            manager.consume(object())
        invalid = detection("e1", 1.0)
        invalid.features.pop(next(iter(invalid.features)))
        with self.assertRaises(AlertManagerError):
            manager.consume(invalid)


if __name__ == "__main__":
    unittest.main()
