"""Bidirectional live-flow extraction independent of ML inference.

This module intentionally does not claim CICFlowMeter compatibility. Its
features are calculated from the packet-event contract below and would require
a separate model trained on exactly this schema before live inference.

Accepted event fields:
    timestamp, src_ip, src_port, dst_ip, dst_port, protocol, packet_size
Optional fields are payload_size and tcp_flags. IPv4 TCP and UDP are supported;
IPv6 is rejected explicitly until its address/protocol policy is added.

LIVE_FLOW_FEATURE_COLUMNS definitions:
    flow_duration_seconds: max_seen_timestamp - min_seen_timestamp.
    packet_count: packets observed in both directions.
    forward_packet_count/backward_packet_count: packets by canonical direction.
    byte_count/forward_byte_count/backward_byte_count: packet_size totals.
    payload_byte_count: payload_size total.
    packet_rate/byte_rate: totals divided by duration, or zero for one packet.
    mean_interarrival_seconds: mean of positive arrival-time gaps; negative
        gaps from out-of-order events are ignored.
    syn_count/fin_count/rst_count/ack_count: TCP flag counts; zero for UDP.

FlowRecord.key.protocol is metadata identifying TCP or UDP; it is deliberately
not included in LIVE_FLOW_FEATURE_COLUMNS because the live numeric feature
schema must not silently encode categorical protocol values.
"""

from __future__ import annotations

import ipaddress
import math
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any, Mapping

LIVE_FLOW_FEATURE_COLUMNS = (
    "flow_duration_seconds",
    "packet_count",
    "forward_packet_count",
    "backward_packet_count",
    "byte_count",
    "forward_byte_count",
    "backward_byte_count",
    "payload_byte_count",
    "packet_rate",
    "byte_rate",
    "mean_interarrival_seconds",
    "syn_count",
    "fin_count",
    "rst_count",
    "ack_count",
)
SUPPORTED_PROTOCOLS = {"tcp": "TCP", "6": "TCP", "udp": "UDP", "17": "UDP"}
TCP_SYN = 0x02
TCP_FIN = 0x01
TCP_RST = 0x04
TCP_ACK = 0x10


@dataclass(frozen=True, order=True)
class FlowKey:
    """Canonical bidirectional five-tuple key.

    Endpoint ordering is deterministic, so packets in reverse direction map to
    the same key. The endpoint names are canonical rather than packet-local.
    """

    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str

    @classmethod
    def from_event(cls, event: "PacketEvent") -> "FlowKey":
        left = (event.src_ip, event.src_port)
        right = (event.dst_ip, event.dst_port)
        if right < left:
            left, right = right, left
        return cls(left[0], left[1], right[0], right[1], event.protocol)

    def matches_forward(self, event: "PacketEvent") -> bool:
        return (event.src_ip, event.src_port) == (self.src_ip, self.src_port)


@dataclass(frozen=True)
class PacketEvent:
    timestamp: float
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str
    packet_size: int
    payload_size: int = 0
    tcp_flags: int = 0

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "PacketEvent":
        protocol = _normalize_protocol(value.get("protocol"))
        src_ip = _validate_ipv4(value.get("src_ip"))
        dst_ip = _validate_ipv4(value.get("dst_ip"))
        timestamp = _finite_number(value.get("timestamp"), "timestamp")
        src_port = _port(value.get("src_port"), "src_port")
        dst_port = _port(value.get("dst_port"), "dst_port")
        packet_size = _nonnegative_int(value.get("packet_size"), "packet_size")
        payload_size = _nonnegative_int(value.get("payload_size", 0), "payload_size")
        if payload_size > packet_size:
            raise ValueError("payload_size cannot exceed packet_size")
        flags = _nonnegative_int(value.get("tcp_flags", 0), "tcp_flags")
        if protocol == "UDP" and flags:
            raise ValueError("tcp_flags are only valid for TCP events")
        return cls(
            timestamp=timestamp,
            src_ip=src_ip,
            src_port=src_port,
            dst_ip=dst_ip,
            dst_port=dst_port,
            protocol=protocol,
            packet_size=packet_size,
            payload_size=payload_size,
            tcp_flags=flags,
        )


@dataclass(frozen=True)
class FlowRecord:
    key: FlowKey
    reason: str
    first_seen: float
    last_seen: float
    features: dict[str, float | int]


@dataclass
class _FlowState:
    key: FlowKey
    first_seen: float
    last_seen: float
    last_observed_timestamp: float
    packet_count: int = 0
    forward_packet_count: int = 0
    backward_packet_count: int = 0
    byte_count: int = 0
    forward_byte_count: int = 0
    backward_byte_count: int = 0
    payload_byte_count: int = 0
    interarrival_total: float = 0.0
    interarrival_count: int = 0
    syn_count: int = 0
    fin_count: int = 0
    rst_count: int = 0
    ack_count: int = 0

    def update(self, event: PacketEvent) -> None:
        forward = self.key.matches_forward(event)
        self.packet_count += 1
        self.forward_packet_count += int(forward)
        self.backward_packet_count += int(not forward)
        self.byte_count += event.packet_size
        self.forward_byte_count += event.packet_size if forward else 0
        self.backward_byte_count += event.packet_size if not forward else 0
        self.payload_byte_count += event.payload_size
        self.first_seen = min(self.first_seen, event.timestamp)
        self.last_seen = max(self.last_seen, event.timestamp)
        if event.timestamp > self.last_observed_timestamp:
            self.interarrival_total += event.timestamp - self.last_observed_timestamp
            self.interarrival_count += 1
            self.last_observed_timestamp = event.timestamp
        if event.protocol == "TCP":
            self.syn_count += int(bool(event.tcp_flags & TCP_SYN))
            self.fin_count += int(bool(event.tcp_flags & TCP_FIN))
            self.rst_count += int(bool(event.tcp_flags & TCP_RST))
            self.ack_count += int(bool(event.tcp_flags & TCP_ACK))

    def features(self) -> dict[str, float | int]:
        duration = max(self.last_seen - self.first_seen, 0.0)
        divisor = duration if duration > 0 else 1.0
        return {
            "flow_duration_seconds": float(duration),
            "packet_count": self.packet_count,
            "forward_packet_count": self.forward_packet_count,
            "backward_packet_count": self.backward_packet_count,
            "byte_count": self.byte_count,
            "forward_byte_count": self.forward_byte_count,
            "backward_byte_count": self.backward_byte_count,
            "payload_byte_count": self.payload_byte_count,
            "packet_rate": float(self.packet_count / divisor) if duration else 0.0,
            "byte_rate": float(self.byte_count / divisor) if duration else 0.0,
            "mean_interarrival_seconds": (
                float(self.interarrival_total / self.interarrival_count)
                if self.interarrival_count
                else 0.0
            ),
            "syn_count": self.syn_count,
            "fin_count": self.fin_count,
            "rst_count": self.rst_count,
            "ack_count": self.ack_count,
        }


class BidirectionalFlowExtractor:
    """Track bounded IPv4 TCP/UDP flow state without invoking an ML model."""

    def __init__(
        self,
        active_timeout_seconds: float = 300.0,
        inactive_timeout_seconds: float = 30.0,
        max_flows: int = 10_000,
        clock: Any = time.time,
    ) -> None:
        if active_timeout_seconds <= 0 or inactive_timeout_seconds <= 0:
            raise ValueError("flow timeouts must be positive")
        if max_flows < 1:
            raise ValueError("max_flows must be positive")
        self.active_timeout_seconds = float(active_timeout_seconds)
        self.inactive_timeout_seconds = float(inactive_timeout_seconds)
        self.max_flows = int(max_flows)
        self._clock = clock
        self._flows: OrderedDict[FlowKey, _FlowState] = OrderedDict()
        self.rejected_events = 0
        self.last_rejection_reason: str | None = None
        self.evicted_flows = 0

    @property
    def active_flow_count(self) -> int:
        return len(self._flows)

    def ingest(self, event: PacketEvent | Mapping[str, Any]) -> list[FlowRecord]:
        """Ingest one event and return any flows completed by this event."""
        try:
            packet = event if isinstance(event, PacketEvent) else PacketEvent.from_mapping(event)
        except (TypeError, ValueError, OverflowError) as error:
            self.rejected_events += 1
            self.last_rejection_reason = str(error)
            return []

        completed = self.expire(packet.timestamp)
        key = FlowKey.from_event(packet)
        state = self._flows.get(key)
        if state is not None and packet.timestamp - state.first_seen >= self.active_timeout_seconds:
            completed.append(self._close(key, "active_timeout"))
            state = None
        if state is None:
            state = _FlowState(
                key=key,
                first_seen=packet.timestamp,
                last_seen=packet.timestamp,
                last_observed_timestamp=packet.timestamp,
            )
            self._flows[key] = state
        state.update(packet)
        self._flows.move_to_end(key)
        if packet.protocol == "TCP" and (packet.tcp_flags & TCP_RST):
            completed.append(self._close(key, "tcp_reset"))
        elif packet.protocol == "TCP" and state.fin_count >= 2:
            completed.append(self._close(key, "tcp_finished"))
        completed.extend(self._enforce_capacity())
        return completed

    def expire(self, timestamp: float | None = None) -> list[FlowRecord]:
        """Close flows idle or active at the supplied logical time."""
        now = self._clock() if timestamp is None else float(timestamp)
        if not math.isfinite(now):
            return []
        completed: list[FlowRecord] = []
        for key, state in list(self._flows.items()):
            if now - state.last_seen >= self.inactive_timeout_seconds:
                completed.append(self._close(key, "inactive_timeout"))
            elif now - state.first_seen >= self.active_timeout_seconds:
                completed.append(self._close(key, "active_timeout"))
        return completed

    def flush(self) -> list[FlowRecord]:
        """Close all current flows during shutdown or controlled replay."""
        return [self._close(key, "flush") for key in list(self._flows)]

    def _close(self, key: FlowKey, reason: str) -> FlowRecord:
        state = self._flows.pop(key)
        return FlowRecord(
            key=state.key,
            reason=reason,
            first_seen=state.first_seen,
            last_seen=state.last_seen,
            features=state.features(),
        )

    def _enforce_capacity(self) -> list[FlowRecord]:
        evicted: list[FlowRecord] = []
        while len(self._flows) > self.max_flows:
            key = next(iter(self._flows))
            evicted.append(self._close(key, "capacity_eviction"))
            self.evicted_flows += 1
        return evicted


def _normalize_protocol(value: Any) -> str:
    key = str(value).strip().lower()
    if key not in SUPPORTED_PROTOCOLS:
        raise ValueError(f"unsupported protocol: {value!r}")
    return SUPPORTED_PROTOCOLS[key]


def _validate_ipv4(value: Any) -> str:
    try:
        address = ipaddress.ip_address(str(value).strip())
    except (ValueError, TypeError) as error:
        raise ValueError(f"invalid IP address: {value!r}") from error
    if address.version != 4:
        raise ValueError("IPv6 events are not supported yet")
    return str(address)


def _finite_number(value: Any, name: str) -> float:
    number = float(value)
    if not math.isfinite(number):
        raise ValueError(f"{name} must be finite")
    return number


def _port(value: Any, name: str) -> int:
    number = int(value)
    if not 0 <= number <= 65535:
        raise ValueError(f"{name} must be between 0 and 65535")
    return number


def _nonnegative_int(value: Any, name: str) -> int:
    number = int(value)
    if number < 0:
        raise ValueError(f"{name} must be non-negative")
    return number
