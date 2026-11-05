import unittest

from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Raw

from rt_nid_ml.flow_extractor import BidirectionalFlowExtractor
from rt_nid_ml.scapy_adapter import ScapyCapture, ScapyPacketAdapter


def tcp_packet(
    timestamp: float = 1.0,
    src: str = "10.0.0.1",
    dst: str = "10.0.0.2",
    sport: int = 40000,
    dport: int = 443,
    flags: str = "A",
    payload: bytes = b"data",
):
    packet = IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags)
    if payload:
        packet = packet / Raw(load=payload)
    packet.time = timestamp
    return packet


def udp_packet(timestamp: float = 2.0):
    packet = IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=50000, dport=53)
    packet.time = timestamp
    return packet


class ScapyPacketAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.adapter = ScapyPacketAdapter()

    def test_ipv4_tcp_conversion_includes_lengths_timestamp_and_flags(self) -> None:
        packet = tcp_packet(flags="S", payload=b"abc")

        event = self.adapter.to_event(packet)

        self.assertIsNotNone(event)
        assert event is not None
        self.assertEqual(event.protocol, "TCP")
        self.assertEqual(event.src_ip, "10.0.0.1")
        self.assertEqual(event.src_port, 40000)
        self.assertEqual(event.dst_port, 443)
        self.assertEqual(event.payload_size, 3)
        self.assertGreater(event.packet_size, event.payload_size)
        self.assertEqual(event.tcp_flags, 0x02)
        self.assertEqual(event.timestamp, 1.0)

    def test_ipv4_udp_conversion_has_empty_payload_and_no_tcp_flags(self) -> None:
        event = self.adapter.to_event(udp_packet())

        self.assertIsNotNone(event)
        assert event is not None
        self.assertEqual(event.protocol, "UDP")
        self.assertEqual(event.src_port, 50000)
        self.assertEqual(event.dst_port, 53)
        self.assertEqual(event.payload_size, 0)
        self.assertEqual(event.tcp_flags, 0)

    def test_tcp_flag_conversion_covers_syn_fin_rst_ack(self) -> None:
        for flag, expected in (("S", 0x02), ("F", 0x01), ("R", 0x04), ("A", 0x10)):
            event = self.adapter.to_event(tcp_packet(flags=flag))
            self.assertIsNotNone(event)
            assert event is not None
            self.assertEqual(event.tcp_flags, expected)

    def test_malformed_missing_layer_and_unsupported_protocol_are_rejected(self) -> None:
        self.assertIsNone(self.adapter.to_event(object()))
        self.assertIsNone(self.adapter.to_event(TCP(sport=1, dport=2)))
        self.assertIsNone(self.adapter.to_event(IP(src="10.0.0.1", dst="10.0.0.2")))
        self.assertEqual(self.adapter.rejected_packets, 3)
        self.assertIsNotNone(self.adapter.last_rejection_reason)


class ScapyCaptureIntegrationTests(unittest.TestCase):
    def test_forward_reverse_packets_reach_one_flow(self) -> None:
        extractor = BidirectionalFlowExtractor()
        capture = ScapyCapture("test0", extractor=extractor)
        capture.process_packet(tcp_packet(timestamp=1.0, flags="S"))
        capture.process_packet(
            tcp_packet(
                timestamp=2.0,
                src="10.0.0.2",
                dst="10.0.0.1",
                sport=443,
                dport=40000,
                flags="A",
            )
        )

        records = extractor.flush()

        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].features["packet_count"], 2)
        self.assertEqual(records[0].features["forward_packet_count"], 1)
        self.assertEqual(records[0].features["backward_packet_count"], 1)
        self.assertEqual(capture.stats.events_emitted, 2)

    def test_capture_runner_uses_configured_interface_and_filter(self) -> None:
        observed = {}
        packets = [tcp_packet(flags="R")]

        def fake_sniff(**kwargs):
            observed.update(kwargs)
            for packet in packets:
                kwargs["prn"](packet)

        capture = ScapyCapture("Ethernet", "tcp port 443", sniff_fn=fake_sniff)
        stats = capture.run()

        self.assertEqual(observed["iface"], "Ethernet")
        self.assertEqual(observed["filter"], "tcp port 443")
        self.assertEqual(stats.packets_seen, 1)
        self.assertEqual(stats.flows_completed, 1)

    def test_udp_packet_flows_and_malformed_packets_are_counted(self) -> None:
        capture = ScapyCapture("test0")
        capture.process_packet(udp_packet())
        capture.process_packet(object())

        record = capture.extractor.flush()[0]

        self.assertEqual(record.key.protocol, "UDP")
        self.assertEqual(record.features["packet_count"], 1)
        self.assertEqual(capture.stats.rejected_packets, 1)

    def test_capture_backend_error_is_recorded(self) -> None:
        def failing_sniff(**_kwargs):
            raise OSError("interface unavailable")

        stats = ScapyCapture("missing0", sniff_fn=failing_sniff).run()

        self.assertEqual(stats.error, "interface unavailable")


if __name__ == "__main__":
    unittest.main()
