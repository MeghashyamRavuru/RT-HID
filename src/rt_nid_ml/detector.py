from __future__ import annotations

import argparse
import json
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Deque, Iterator

import joblib

FEATURE_COLUMNS = [
    "packet_count",
    "syn_ratio",
    "rst_ratio",
    "avg_payload_len",
    "unique_dst_ports",
    "connection_rate",
    "avg_packet_size",
    "mean_interarrival",
    "fin_ratio",
    "ack_ratio",
]
LEGACY_FEATURE_COLUMNS = FEATURE_COLUMNS[:6]
BENIGN_LABELS = {"0", "benign", "normal"}


@dataclass
class SourceWindow:
    events: Deque[tuple[float, int, int, int]] = field(default_factory=deque)
    last_emitted_at: float = 0.0


class PacketFeatureExtractor:
    def __init__(self, window_seconds: int = 10, emit_every_seconds: int = 2) -> None:
        self.window_seconds = window_seconds
        self.emit_every_seconds = emit_every_seconds
        self._state: dict[str, SourceWindow] = defaultdict(SourceWindow)

    def ingest_event(
        self,
        src_ip: str,
        dst_port: int,
        flags: int,
        payload_len: int,
        timestamp: float | None = None,
    ) -> list[dict[str, float | str]]:
        now = timestamp if timestamp is not None else time.time()
        source_state = self._state[src_ip]
        source_state.events.append((now, dst_port, flags, payload_len))
        self._prune(source_state, now)

        if source_state.last_emitted_at == 0.0:
            source_state.last_emitted_at = now

        if now - source_state.last_emitted_at < self.emit_every_seconds:
            return []

        source_state.last_emitted_at = now
        feature_row = self._to_features(src_ip, source_state.events)
        return [feature_row] if feature_row else []

    def _prune(self, source_state: SourceWindow, now: float) -> None:
        cutoff = now - self.window_seconds
        while source_state.events and source_state.events[0][0] < cutoff:
            source_state.events.popleft()

    @staticmethod
    def _to_features(src_ip: str, events: Deque[tuple[float, int, int, int]]) -> dict[str, float | str] | None:
        if not events:
            return None

        packet_count = len(events)
        syn_count = sum(1 for _, _, flags, _ in events if flags & 0x02)
        rst_count = sum(1 for _, _, flags, _ in events if flags & 0x04)
        payload_total = sum(payload_len for _, _, _, payload_len in events)
        unique_ports = len({dst_port for _, dst_port, _, _ in events})
        span = max(events[-1][0] - events[0][0], 1e-6)
        interarrivals = [later[0] - earlier[0] for earlier, later in zip(events, list(events)[1:])]
        packet_sizes = [payload_len for _, _, _, payload_len in events]

        return {
            "src_ip": src_ip,
            "packet_count": float(packet_count),
            "syn_ratio": float(syn_count / packet_count),
            "rst_ratio": float(rst_count / packet_count),
            "avg_payload_len": float(payload_total / packet_count),
            "unique_dst_ports": float(unique_ports),
            "connection_rate": float(packet_count / span),
            "avg_packet_size": float(sum(packet_sizes) / packet_count),
            "mean_interarrival": float(sum(interarrivals) / len(interarrivals)) if interarrivals else 0.0,
            "fin_ratio": float(sum(1 for _, _, flags, _ in events if flags & 0x01) / packet_count),
            "ack_ratio": float(sum(1 for _, _, flags, _ in events if flags & 0x10) / packet_count),
        }


class IntrusionModel:
    def __init__(self, model_path: str, threshold: float = 0.65) -> None:
        self.model = joblib.load(model_path)
        self.threshold = threshold

    def classify(self, feature_row: dict[str, float | str]) -> tuple[str, float]:
        expected_count = getattr(self.model, "n_features_in_", len(FEATURE_COLUMNS))
        columns = LEGACY_FEATURE_COLUMNS if expected_count == len(LEGACY_FEATURE_COLUMNS) else FEATURE_COLUMNS
        compatibility_defaults = {
            "avg_packet_size": feature_row.get("avg_payload_len", 0.0),
            "mean_interarrival": 1.0 / max(float(feature_row.get("connection_rate", 1.0)), 1e-6),
            "fin_ratio": feature_row.get("rst_ratio", 0.0),
            "ack_ratio": 1.0 - float(feature_row.get("syn_ratio", 0.0)),
        }
        vector = [[float(feature_row.get(col, compatibility_defaults.get(col, 0.0))) for col in columns]]
        legacy_row = not all(column in feature_row for column in FEATURE_COLUMNS)
        if hasattr(self.model, "predict_proba"):
            probabilities = self.model.predict_proba(vector)[0]
            classes = list(getattr(self.model, "classes_", range(len(probabilities))))
            best_index = max(range(len(probabilities)), key=probabilities.__getitem__)
            predicted = str(classes[best_index])
            score = float(probabilities[best_index])
        elif hasattr(self.model, "decision_function"):
            raw = float(self.model.decision_function(vector)[0])
            score = 1.0 / (1.0 + pow(2.718281828, -raw))
            predicted = str(self.model.predict(vector)[0])
        else:
            predicted = str(self.model.predict(vector)[0])
            score = 1.0

        if predicted.lower() in BENIGN_LABELS:
            label = "normal"
        elif len(getattr(self.model, "classes_", [])) <= 2 and predicted == "1":
            label = "malicious" if score >= self.threshold else "normal"
        else:
            label = predicted if score >= self.threshold else "normal"
        if legacy_row and label not in {"normal", "benign"}:
            label = "malicious"
        return label, score


def packet_to_event(packet: Any) -> tuple[str, int, int, int, float] | None:
    """Convert a Scapy IP/TCP packet into the extractor's stable event format."""
    from scapy.layers.inet import IP, TCP

    if IP not in packet or TCP not in packet:
        return None
    return (
        str(packet[IP].src),
        int(packet[TCP].dport),
        int(packet[TCP].flags),
        len(bytes(packet[TCP].payload)),
        float(packet.time),
    )


def iter_pcap(pcap_path: str | Path) -> Iterator[Any]:
    from scapy.utils import PcapReader

    with PcapReader(str(pcap_path)) as reader:
        yield from reader


def classify_packets(
    packets: Iterator[Any],
    classifier: IntrusionModel,
    extractor: PacketFeatureExtractor | None = None,
    on_alert: Callable[[dict[str, Any]], None] | None = None,
) -> list[dict[str, Any]]:
    extractor = extractor or PacketFeatureExtractor()
    alerts: list[dict[str, Any]] = []
    for packet in packets:
        event = packet_to_event(packet)
        if event is None:
            continue
        src_ip, dst_port, flags, payload_len, timestamp = event
        for row in extractor.ingest_event(src_ip, dst_port, flags, payload_len, timestamp):
            label, score = classifier.classify(row)
            if label == "normal":
                continue
            alert = {
                "timestamp": timestamp,
                "alert_type": label,
                "source_ip": row["src_ip"],
                "score": round(score, 4),
                "features": {key: row[key] for key in FEATURE_COLUMNS},
            }
            alerts.append(alert)
            if on_alert:
                on_alert(alert)
    return alerts


def run(
    interface: str,
    model_path: str,
    threshold: float,
    on_alert: Callable[[dict[str, Any]], None] | None = None,
) -> None:
    from scapy.all import sniff

    extractor = PacketFeatureExtractor()
    classifier = IntrusionModel(model_path=model_path, threshold=threshold)

    def on_packet(pkt) -> None:
        event = packet_to_event(pkt)
        if event is None:
            return
        src_ip, dst_port, flags, payload_len, timestamp = event

        for row in extractor.ingest_event(src_ip, dst_port, flags, payload_len, timestamp):
            label, score = classifier.classify(row)
            if label == "normal":
                continue
            alert = {
                "timestamp": timestamp,
                "alert_type": label,
                "source_ip": row["src_ip"],
                "score": round(score, 4),
                "features": {key: row[key] for key in FEATURE_COLUMNS},
            }
            print(json.dumps(alert), flush=True)
            if on_alert:
                on_alert(alert)

    sniff(iface=interface, filter="tcp", prn=on_packet, store=False)


def run_pcap(
    pcap_path: str,
    model_path: str,
    threshold: float,
    on_alert: Callable[[dict[str, Any]], None] | None = None,
) -> list[dict[str, Any]]:
    classifier = IntrusionModel(model_path=model_path, threshold=threshold)
    return classify_packets(iter_pcap(pcap_path), classifier, on_alert=on_alert)


def main() -> None:
    parser = argparse.ArgumentParser(description="Real-time SSH intrusion detector")
    parser.add_argument("--interface", default="eth0", help="Network interface to sniff")
    parser.add_argument("--pcap", help="Replay a PCAP instead of sniffing live traffic")
    parser.add_argument("--model", required=True, help="Path to trained model (joblib)")
    parser.add_argument("--threshold", type=float, default=0.65, help="Malicious score threshold")
    parser.add_argument("--dashboard-port", type=int, help="Also serve the dashboard on this port")
    args = parser.parse_args()
    on_alert = None
    if args.dashboard_port:
        from rt_nid_ml.dashboard import create_app

        store = create_app().config["ALERT_STORE"]
        threading.Thread(
            target=create_app(store).run,
            kwargs={"host": "127.0.0.1", "port": args.dashboard_port, "debug": False, "use_reloader": False},
            daemon=True,
        ).start()
        on_alert = store.record_alert
    if args.pcap:
        for alert in run_pcap(args.pcap, args.model, args.threshold, on_alert=on_alert):
            print(json.dumps(alert), flush=True)
    else:
        run(interface=args.interface, model_path=args.model, threshold=args.threshold, on_alert=on_alert)


if __name__ == "__main__":
    main()
