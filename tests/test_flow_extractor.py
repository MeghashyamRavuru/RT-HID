import unittest

from rt_nid_ml.flow_extractor import (
    LIVE_FLOW_FEATURE_COLUMNS,
    BidirectionalFlowExtractor,
)


def event(
    timestamp: float,
    src_ip: str = "10.0.0.1",
    src_port: int = 40000,
    dst_ip: str = "10.0.0.2",
    dst_port: int = 443,
    protocol: str = "TCP",
    packet_size: int = 100,
    payload_size: int = 20,
    tcp_flags: int = 0x10,
) -> dict:
    return {
        "timestamp": timestamp,
        "src_ip": src_ip,
        "src_port": src_port,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "protocol": protocol,
        "packet_size": packet_size,
        "payload_size": payload_size,
        "tcp_flags": tcp_flags if protocol == "TCP" else 0,
    }


class BidirectionalFlowExtractorTests(unittest.TestCase):
    def test_forward_only_traffic_is_one_flow(self) -> None:
        extractor = BidirectionalFlowExtractor(inactive_timeout_seconds=10)
        extractor.ingest(event(1.0, tcp_flags=0x02))
        extractor.ingest(event(2.0))

        records = extractor.flush()

        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].features["packet_count"], 2)
        self.assertEqual(records[0].features["forward_packet_count"], 2)
        self.assertEqual(records[0].features["backward_packet_count"], 0)
        self.assertEqual(set(records[0].features), set(LIVE_FLOW_FEATURE_COLUMNS))

    def test_reverse_traffic_updates_same_flow(self) -> None:
        extractor = BidirectionalFlowExtractor()
        extractor.ingest(event(1.0, tcp_flags=0x02))
        extractor.ingest(event(2.0, src_ip="10.0.0.2", src_port=443, dst_ip="10.0.0.1", dst_port=40000))

        record = extractor.flush()[0]

        self.assertEqual(record.features["packet_count"], 2)
        self.assertEqual(record.features["forward_packet_count"], 1)
        self.assertEqual(record.features["backward_packet_count"], 1)
        self.assertEqual(record.features["syn_count"], 1)

    def test_independent_connections_from_one_source_are_separate(self) -> None:
        extractor = BidirectionalFlowExtractor()
        extractor.ingest(event(1.0, dst_port=22, tcp_flags=0x02))
        extractor.ingest(event(1.1, dst_port=80, tcp_flags=0x02))

        self.assertEqual(extractor.active_flow_count, 2)
        self.assertEqual(len(extractor.flush()), 2)

    def test_tcp_and_udp_have_independent_flow_keys(self) -> None:
        extractor = BidirectionalFlowExtractor()
        extractor.ingest(event(1.0, protocol="TCP", tcp_flags=0x02))
        extractor.ingest(event(1.0, protocol="UDP"))

        self.assertEqual(extractor.active_flow_count, 2)
        records = extractor.flush()
        self.assertEqual({record.key.protocol for record in records}, {"TCP", "UDP"})

    def test_inactive_timeout_expires_flow(self) -> None:
        extractor = BidirectionalFlowExtractor(inactive_timeout_seconds=5)
        extractor.ingest(event(1.0))

        records = extractor.expire(6.0)

        self.assertEqual([record.reason for record in records], ["inactive_timeout"])
        self.assertEqual(extractor.active_flow_count, 0)

    def test_active_timeout_starts_a_new_generation(self) -> None:
        extractor = BidirectionalFlowExtractor(
            active_timeout_seconds=5, inactive_timeout_seconds=100
        )
        extractor.ingest(event(1.0))
        records = extractor.ingest(event(7.0))

        self.assertEqual([record.reason for record in records], ["active_timeout"])
        self.assertEqual(extractor.active_flow_count, 1)
        self.assertEqual(extractor.flush()[0].features["packet_count"], 1)

    def test_out_of_order_timestamps_do_not_create_negative_duration(self) -> None:
        extractor = BidirectionalFlowExtractor()
        extractor.ingest(event(10.0))
        extractor.ingest(event(8.0))
        extractor.ingest(event(12.0))

        record = extractor.flush()[0]

        self.assertEqual(record.features["flow_duration_seconds"], 4.0)
        self.assertGreaterEqual(record.features["mean_interarrival_seconds"], 0.0)

    def test_malformed_and_unsupported_events_are_rejected(self) -> None:
        extractor = BidirectionalFlowExtractor()

        self.assertEqual(extractor.ingest({"timestamp": 1.0}), [])
        self.assertEqual(extractor.ingest(event(1.0, protocol="ICMP")), [])
        self.assertEqual(extractor.ingest(event(1.0, src_ip="2001:db8::1")), [])
        self.assertEqual(extractor.rejected_events, 3)
        self.assertIsNotNone(extractor.last_rejection_reason)

    def test_capacity_cleanup_is_bounded_and_reported(self) -> None:
        extractor = BidirectionalFlowExtractor(max_flows=2)
        extractor.ingest(event(1.0, dst_port=22))
        extractor.ingest(event(1.0, dst_port=80))
        records = extractor.ingest(event(1.0, dst_port=443))

        self.assertLessEqual(extractor.active_flow_count, 2)
        self.assertEqual(extractor.evicted_flows, 1)
        self.assertEqual(records[0].reason, "capacity_eviction")


if __name__ == "__main__":
    unittest.main()
