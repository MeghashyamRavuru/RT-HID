"""Scapy packet translation and capture orchestration for Phase 3A.

This module stops at the boundary between packet capture and flow extraction:
Scapy packet -> validated PacketEvent -> BidirectionalFlowExtractor. It does
not load models, emit ML alerts, or implement another flow table.
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass
from typing import Any, Callable

from .flow_extractor import BidirectionalFlowExtractor, FlowRecord, PacketEvent


@dataclass
class CaptureStats:
    packets_seen: int = 0
    events_emitted: int = 0
    rejected_packets: int = 0
    flows_completed: int = 0
    error: str | None = None


class ScapyPacketAdapter:
    """Translate supported Scapy IPv4 TCP/UDP packets into PacketEvent values."""

    def __init__(self) -> None:
        self.rejected_packets = 0
        self.last_rejection_reason: str | None = None

    def to_event(self, packet: Any) -> PacketEvent | None:
        try:
            from scapy.layers.inet import IP, TCP, UDP

            if not hasattr(packet, "haslayer") or not packet.haslayer(IP):
                raise ValueError("packet has no IPv4 network layer")
            if packet.haslayer(TCP):
                transport = packet[TCP]
                protocol = "TCP"
            elif packet.haslayer(UDP):
                transport = packet[UDP]
                protocol = "UDP"
            else:
                raise ValueError("unsupported transport protocol")

            packet_timestamp = getattr(packet, "time", None)
            if packet_timestamp is None:
                raise ValueError("packet has no timestamp")
            packet_size = len(bytes(packet))
            payload_size = len(bytes(transport.payload))
            tcp_flags = int(transport.flags) if protocol == "TCP" else 0
            return PacketEvent.from_mapping(
                {
                    "timestamp": float(packet_timestamp),
                    "src_ip": str(packet[IP].src),
                    "src_port": int(transport.sport),
                    "dst_ip": str(packet[IP].dst),
                    "dst_port": int(transport.dport),
                    "protocol": protocol,
                    "packet_size": packet_size,
                    "payload_size": payload_size,
                    "tcp_flags": tcp_flags,
                }
            )
        except (
            AttributeError,
            ImportError,
            IndexError,
            TypeError,
            ValueError,
            OverflowError,
        ) as error:
            self.rejected_packets += 1
            self.last_rejection_reason = str(error)
            return None


class ScapyCapture:
    """Capture packets and forward completed flow records to a callback.

    ``run`` is blocking by design for command-line sensors. ``start_background``
    uses Scapy's AsyncSniffer for applications that must keep their main thread
    responsive. Both paths use the same packet callback and extractor instance.
    """

    def __init__(
        self,
        interface: str,
        bpf_filter: str = "tcp or udp",
        extractor: BidirectionalFlowExtractor | None = None,
        adapter: ScapyPacketAdapter | None = None,
        on_flow: Callable[[FlowRecord], None] | None = None,
        logger: logging.Logger | None = None,
        sniff_fn: Callable[..., Any] | None = None,
    ) -> None:
        if not interface or not interface.strip():
            raise ValueError("interface is required")
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.extractor = extractor or BidirectionalFlowExtractor()
        self.adapter = adapter or ScapyPacketAdapter()
        self.on_flow = on_flow
        self.logger = logger or logging.getLogger(__name__)
        self._sniff_fn = sniff_fn
        self._sniffer: Any = None
        self.stats = CaptureStats()

    def process_packet(self, packet: Any) -> list[FlowRecord]:
        """Translate one captured packet and process any completed flows."""
        self.stats.packets_seen += 1
        event = self.adapter.to_event(packet)
        if event is None:
            self.stats.rejected_packets += 1
            return []
        self.stats.events_emitted += 1
        records = self.extractor.ingest(event)
        self._publish(records)
        return records

    def run(self, stop_event: threading.Event | None = None) -> CaptureStats:
        """Run blocking capture until Scapy stops, Ctrl-C, or stop_event fires."""
        stop_filter = (
            (lambda _packet: stop_event.is_set()) if stop_event is not None else None
        )
        try:
            sniff_fn = self._sniff_fn or self._load_sniff()
            sniff_fn(
                iface=self.interface,
                filter=self.bpf_filter,
                prn=lambda packet: self.process_packet(packet) and None,
                store=False,
                stop_filter=stop_filter,
            )
        except KeyboardInterrupt:
            self.logger.info("packet capture interrupted")
        except (OSError, PermissionError, RuntimeError) as error:
            self.stats.error = str(error)
            self.logger.error("packet capture failed: %s", error)
        finally:
            self._publish(self.extractor.flush())
        return self.stats

    def start_background(self) -> None:
        """Start Scapy AsyncSniffer without blocking the caller."""
        if self._sniffer is not None:
            raise RuntimeError("packet capture is already running")
        try:
            from scapy.sendrecv import AsyncSniffer

            self._sniffer = AsyncSniffer(
                iface=self.interface,
                filter=self.bpf_filter,
                prn=lambda packet: self.process_packet(packet) and None,
                store=False,
            )
            self._sniffer.start()
        except (OSError, PermissionError, RuntimeError) as error:
            self.stats.error = str(error)
            self.logger.error("packet capture failed to start: %s", error)
            self._sniffer = None

    def stop(self) -> CaptureStats:
        """Stop background capture and flush remaining partial flows."""
        if self._sniffer is not None:
            try:
                self._sniffer.stop()
            except (OSError, RuntimeError) as error:
                self.stats.error = str(error)
                self.logger.error("packet capture failed to stop: %s", error)
            finally:
                self._sniffer = None
        self._publish(self.extractor.flush())
        return self.stats

    def _publish(self, records: list[FlowRecord]) -> None:
        self.stats.flows_completed += len(records)
        if self.on_flow:
            for record in records:
                self.on_flow(record)

    @staticmethod
    def _load_sniff() -> Callable[..., Any]:
        try:
            from scapy.sendrecv import sniff

            return sniff
        except (ImportError, OSError) as error:
            raise RuntimeError("Scapy packet capture is unavailable") from error
