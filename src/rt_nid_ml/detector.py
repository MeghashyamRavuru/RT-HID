from __future__ import annotations

import argparse
import json
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Deque

import joblib

FEATURE_COLUMNS = [
    "packet_count",
    "syn_ratio",
    "rst_ratio",
    "avg_payload_len",
    "unique_dst_ports",
    "connection_rate",
]


@dataclass
class SourceWindow:
    events: Deque[tuple[float, int, int, int, int]] = field(default_factory=deque)
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
        source_state.events.append((now, dst_port, flags, payload_len, 1))
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
    def _to_features(src_ip: str, events: Deque[tuple[float, int, int, int, int]]) -> dict[str, float | str] | None:
        if not events:
            return None

        packet_count = len(events)
        syn_count = sum(1 for _, _, flags, _, _ in events if flags & 0x02)
        rst_count = sum(1 for _, _, flags, _, _ in events if flags & 0x04)
        payload_total = sum(payload_len for _, _, _, payload_len, _ in events)
        unique_ports = len({dst_port for _, dst_port, _, _, _ in events})
        span = max(events[-1][0] - events[0][0], 1e-6)

        return {
            "src_ip": src_ip,
            "packet_count": float(packet_count),
            "syn_ratio": float(syn_count / packet_count),
            "rst_ratio": float(rst_count / packet_count),
            "avg_payload_len": float(payload_total / packet_count),
            "unique_dst_ports": float(unique_ports),
            "connection_rate": float(packet_count / span),
        }


class IntrusionModel:
    def __init__(self, model_path: str, threshold: float = 0.65) -> None:
        self.model = joblib.load(model_path)
        self.threshold = threshold

    def classify(self, feature_row: dict[str, float | str]) -> tuple[str, float]:
        vector = [[feature_row[col] for col in FEATURE_COLUMNS]]
        if hasattr(self.model, "predict_proba"):
            score = float(self.model.predict_proba(vector)[0][1])
        elif hasattr(self.model, "decision_function"):
            raw = float(self.model.decision_function(vector)[0])
            score = 1.0 / (1.0 + pow(2.718281828, -raw))
        else:
            score = float(self.model.predict(vector)[0])

        label = "malicious" if score >= self.threshold else "benign"
        return label, score


def run(interface: str, model_path: str, threshold: float) -> None:
    from scapy.all import IP, TCP, sniff

    extractor = PacketFeatureExtractor()
    classifier = IntrusionModel(model_path=model_path, threshold=threshold)

    def on_packet(pkt) -> None:
        if IP not in pkt or TCP not in pkt:
            return
        src_ip = str(pkt[IP].src)
        dst_port = int(pkt[TCP].dport)
        flags = int(pkt[TCP].flags)
        payload_len = len(bytes(pkt[TCP].payload))

        for row in extractor.ingest_event(src_ip, dst_port, flags, payload_len):
            label, score = classifier.classify(row)
            if label == "malicious":
                print(
                    json.dumps(
                        {
                            "alert_type": "ssh_intrusion_suspected",
                            "source_ip": row["src_ip"],
                            "score": round(score, 4),
                            "features": {k: row[k] for k in FEATURE_COLUMNS},
                        }
                    ),
                    flush=True,
                )

    sniff(iface=interface, filter="tcp port 22", prn=on_packet, store=False)


def main() -> None:
    parser = argparse.ArgumentParser(description="Real-time SSH intrusion detector")
    parser.add_argument("--interface", default="eth0", help="Network interface to sniff")
    parser.add_argument("--model", required=True, help="Path to trained model (joblib)")
    parser.add_argument("--threshold", type=float, default=0.65, help="Malicious score threshold")
    args = parser.parse_args()
    run(interface=args.interface, model_path=args.model, threshold=args.threshold)


if __name__ == "__main__":
    main()
