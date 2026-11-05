"""Live-flow dataset collection and explicit ground-truth labeling.

This module consumes completed ``FlowRecord`` objects. It never uses model
predictions to assign labels and never stores packet payload contents.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import os
import uuid
from collections import Counter
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from .flow_extractor import LIVE_FLOW_FEATURE_COLUMNS, FlowRecord

LABELS = {"normal", "port_scan", "brute_force", "dos", "unknown"}
SCHEMA_VERSION = "live-flow-dataset-v1"
LIFECYCLE_REASONS = {
    "active_timeout",
    "capacity_eviction",
    "flush",
    "inactive_timeout",
    "tcp_finished",
    "tcp_reset",
}
DATASET_COLUMNS = (
    "record_id",
    *LIVE_FLOW_FEATURE_COLUMNS,
    "source_ip",
    "source_port",
    "destination_ip",
    "destination_port",
    "protocol",
    "flow_start_timestamp",
    "flow_end_timestamp",
    "flow_lifecycle_reason",
    "capture_session_id",
    "sensor_id",
    "experiment_id",
    "experiment_start_timestamp",
    "experiment_end_timestamp",
    "target_ip",
    "ground_truth_label",
    "label_source",
    "label_confidence",
    "label_reason",
    "clock_uncertainty_seconds",
)
OPTIONAL_EXPERIMENT_COLUMNS = {
    "experiment_id",
    "experiment_start_timestamp",
    "experiment_end_timestamp",
    "target_ip",
}


@dataclass(frozen=True)
class ExperimentSpec:
    experiment_id: str
    label: str
    start_timestamp: float
    end_timestamp: float
    target_ip: str
    confidence: float = 1.0
    label_source: str = "experiment_metadata"
    clock_uncertainty_seconds: float = 0.0
    notes: str = ""

    def __post_init__(self) -> None:
        if self.label not in LABELS - {"unknown"}:
            raise ValueError(f"unsupported experiment label: {self.label}")
        if self.end_timestamp < self.start_timestamp:
            raise ValueError("experiment end must not precede experiment start")
        if not self.target_ip:
            raise ValueError("experiment target_ip is required")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be between 0 and 1")
        if self.clock_uncertainty_seconds < 0:
            raise ValueError("clock uncertainty must be non-negative")


@dataclass(frozen=True)
class LabelDecision:
    label: str = "unknown"
    experiment_id: str = ""
    target_ip: str = ""
    source: str = "unassigned"
    confidence: float = 0.0
    reason: str = "no matching experiment metadata"
    clock_uncertainty_seconds: float = 0.0
    experiment_start_timestamp: float | None = None
    experiment_end_timestamp: float | None = None


class GroundTruthLabeler:
    """Assign labels only from explicit, time-and-target-scoped experiments."""

    def __init__(self, experiments: Iterable[ExperimentSpec] = ()) -> None:
        self.experiments = tuple(experiments)

    def label(self, record: FlowRecord) -> LabelDecision:
        endpoint_ips = {record.key.src_ip, record.key.dst_ip}
        matches: list[ExperimentSpec] = []
        for experiment in self.experiments:
            uncertainty = experiment.clock_uncertainty_seconds
            overlaps = (
                record.first_seen <= experiment.end_timestamp + uncertainty
                and record.last_seen >= experiment.start_timestamp - uncertainty
            )
            if overlaps and experiment.target_ip in endpoint_ips:
                matches.append(experiment)

        if not matches:
            return LabelDecision()
        labels = {experiment.label for experiment in matches}
        if len(labels) != 1:
            return LabelDecision(
                label="unknown",
                source="conflicting_experiment_metadata",
                reason="overlapping experiments disagree on the label",
            )
        selected = sorted(matches, key=lambda experiment: experiment.confidence, reverse=True)[0]
        return LabelDecision(
            label=selected.label,
            experiment_id=selected.experiment_id,
            target_ip=selected.target_ip,
            source=selected.label_source,
            confidence=selected.confidence,
            reason=selected.notes or "flow overlaps explicit experiment window and target",
            clock_uncertainty_seconds=selected.clock_uncertainty_seconds,
            experiment_start_timestamp=selected.start_timestamp,
            experiment_end_timestamp=selected.end_timestamp,
        )

    @classmethod
    def from_json(cls, path: Path) -> "GroundTruthLabeler":
        with path.open("r", encoding="utf-8") as file:
            payload = json.load(file)
        experiments = [ExperimentSpec(**item) for item in payload.get("experiments", payload)]
        return cls(experiments)


@dataclass
class CollectionStats:
    rows_written: int = 0
    unknown_rows: int = 0
    incomplete_rows: int = 0
    duplicate_rows: int = 0


class DatasetCollector:
    """Append completed flow records to one session CSV and JSON sidecar."""

    def __init__(
        self,
        output_dir: Path,
        session_id: str,
        sensor_id: str,
        labeler: GroundTruthLabeler | None = None,
        experiment_id: str = "",
        flush_each_row: bool = True,
    ) -> None:
        if not session_id or not sensor_id:
            raise ValueError("session_id and sensor_id are required")
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.session_id = session_id
        self.sensor_id = sensor_id
        self.labeler = labeler or GroundTruthLabeler()
        self.default_experiment_id = experiment_id
        self.flush_each_row = flush_each_row
        self.stats = CollectionStats()
        self._seen_fingerprints: set[str] = set()
        self._closed = False
        self.data_path = self.output_dir / f"session_{session_id}.csv"
        self.metadata_path = self.output_dir / f"session_{session_id}.json"
        exists = self.data_path.exists() and self.data_path.stat().st_size > 0
        self._file = self.data_path.open("a", encoding="utf-8", newline="")
        self._writer = csv.DictWriter(self._file, fieldnames=DATASET_COLUMNS)
        if not exists:
            self._writer.writeheader()
            self._file.flush()
        self._write_sidecar(status="open")

    def record_flow(self, record: FlowRecord) -> dict[str, Any]:
        if self._closed:
            raise RuntimeError("collector is closed")
        decision = self.labeler.label(record)
        if self.default_experiment_id and not decision.experiment_id:
            decision = LabelDecision(
                label=decision.label,
                experiment_id=self.default_experiment_id,
                target_ip=decision.target_ip,
                source=decision.source,
                confidence=decision.confidence,
                reason=decision.reason,
                clock_uncertainty_seconds=decision.clock_uncertainty_seconds,
                experiment_start_timestamp=decision.experiment_start_timestamp,
                experiment_end_timestamp=decision.experiment_end_timestamp,
            )
        row = self._row_from_record(record, decision)
        fingerprint = self._fingerprint(row)
        if fingerprint in self._seen_fingerprints:
            self.stats.duplicate_rows += 1
        self._seen_fingerprints.add(fingerprint)
        if row["ground_truth_label"] == "unknown":
            self.stats.unknown_rows += 1
        if row["flow_lifecycle_reason"] in {"active_timeout", "flush", "inactive_timeout", "capacity_eviction"}:
            self.stats.incomplete_rows += 1
        self._writer.writerow(row)
        self.stats.rows_written += 1
        if self.flush_each_row:
            self.flush()
        return row

    def flush(self) -> None:
        if not self._closed:
            self._file.flush()
            os.fsync(self._file.fileno())
            self._write_sidecar(status="open")

    def close(self) -> None:
        if self._closed:
            return
        self.flush()
        self._file.close()
        self._closed = True
        self._write_sidecar(status="closed")

    def _row_from_record(self, record: FlowRecord, decision: LabelDecision) -> dict[str, Any]:
        row: dict[str, Any] = {
            "record_id": uuid.uuid4().hex,
            **record.features,
            "source_ip": record.key.src_ip,
            "source_port": record.key.src_port,
            "destination_ip": record.key.dst_ip,
            "destination_port": record.key.dst_port,
            "protocol": record.key.protocol,
            "flow_start_timestamp": record.first_seen,
            "flow_end_timestamp": record.last_seen,
            "flow_lifecycle_reason": record.reason,
            "capture_session_id": self.session_id,
            "sensor_id": self.sensor_id,
            "experiment_id": decision.experiment_id,
            "experiment_start_timestamp": (
                decision.experiment_start_timestamp
                if decision.experiment_start_timestamp is not None
                else ""
            ),
            "experiment_end_timestamp": (
                decision.experiment_end_timestamp
                if decision.experiment_end_timestamp is not None
                else ""
            ),
            "target_ip": decision.target_ip,
            "ground_truth_label": decision.label,
            "label_source": decision.source,
            "label_confidence": decision.confidence,
            "label_reason": decision.reason,
            "clock_uncertainty_seconds": decision.clock_uncertainty_seconds,
        }
        return {column: row.get(column, "") for column in DATASET_COLUMNS}

    def _write_sidecar(self, status: str) -> None:
        payload = {
            "schema_version": SCHEMA_VERSION,
            "status": status,
            "session_id": self.session_id,
            "sensor_id": self.sensor_id,
            "data_file": self.data_path.name,
            "created_at_utc": datetime.now(timezone.utc).isoformat(),
            "columns": list(DATASET_COLUMNS),
            "feature_columns": list(LIVE_FLOW_FEATURE_COLUMNS),
            "stats": asdict(self.stats),
            "experiments": [asdict(experiment) for experiment in self.labeler.experiments],
        }
        temporary_path = self.metadata_path.with_suffix(".json.tmp")
        temporary_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        temporary_path.replace(self.metadata_path)

    @staticmethod
    def _fingerprint(row: dict[str, Any]) -> str:
        values = "|".join(
            str(row[column])
            for column in (
                "source_ip", "source_port", "destination_ip", "destination_port",
                "protocol", "flow_start_timestamp", "flow_end_timestamp",
            )
        )
        return hashlib.sha256(values.encode("utf-8")).hexdigest()

    def __enter__(self) -> "DatasetCollector":
        return self

    def __exit__(self, _type: Any, _value: Any, _traceback: Any) -> None:
        self.close()


@dataclass
class ValidationReport:
    path: str
    row_count: int = 0
    valid_rows: int = 0
    invalid_rows: int = 0
    duplicate_flows: int = 0
    incomplete_flows: int = 0
    unknown_labels: int = 0
    missing_values: int = 0
    invalid_values: int = 0
    schema_mismatch: list[str] = field(default_factory=list)
    issues: list[str] = field(default_factory=list)
    label_distribution: dict[str, int] = field(default_factory=dict)
    session_distribution: dict[str, int] = field(default_factory=dict)
    protocol_distribution: dict[str, int] = field(default_factory=dict)

    @property
    def valid(self) -> bool:
        return (
            not self.schema_mismatch
            and self.invalid_rows == 0
            and self.duplicate_flows == 0
            and not self.issues
        )


def validate_dataset(path: Path) -> ValidationReport:
    report = ValidationReport(path=str(path))
    seen: set[str] = set()
    try:
        with Path(path).open("r", encoding="utf-8", newline="") as file:
            reader = csv.DictReader(file)
            actual_columns = reader.fieldnames or []
            report.schema_mismatch = [
                column for column in DATASET_COLUMNS if column not in actual_columns
            ]
            if report.schema_mismatch:
                report.issues.append(
                    "missing required columns: " + ", ".join(report.schema_mismatch)
                )
                return report
            for row_number, row in enumerate(reader, start=2):
                report.row_count += 1
                row_invalid = False
                missing = [
                    column
                    for column in DATASET_COLUMNS
                    if column not in OPTIONAL_EXPERIMENT_COLUMNS and not row.get(column)
                ]
                if missing:
                    report.missing_values += len(missing)
                    report.issues.append(f"row {row_number}: missing values in {missing}")
                    row_invalid = True
                for column in LIVE_FLOW_FEATURE_COLUMNS:
                    try:
                        value = float(row[column])
                        if not math.isfinite(value):
                            raise ValueError
                    except (TypeError, ValueError):
                        report.invalid_values += 1
                        report.issues.append(f"row {row_number}: invalid feature {column}")
                        row_invalid = True
                try:
                    start = float(row["flow_start_timestamp"])
                    end = float(row["flow_end_timestamp"])
                    if not math.isfinite(start) or not math.isfinite(end) or end < start:
                        raise ValueError
                except (TypeError, ValueError):
                    report.invalid_values += 1
                    report.issues.append(f"row {row_number}: invalid flow timestamps")
                    row_invalid = True
                if row.get("experiment_id"):
                    try:
                        experiment_start = float(row["experiment_start_timestamp"])
                        experiment_end = float(row["experiment_end_timestamp"])
                        if not math.isfinite(experiment_start) or not math.isfinite(experiment_end):
                            raise ValueError
                    except (TypeError, ValueError):
                        report.invalid_values += 1
                        report.issues.append(
                            f"row {row_number}: invalid experiment timestamps"
                        )
                        row_invalid = True
                try:
                    confidence = float(row["label_confidence"])
                    if not 0.0 <= confidence <= 1.0:
                        raise ValueError
                except (TypeError, ValueError):
                    report.invalid_values += 1
                    report.issues.append(f"row {row_number}: invalid label confidence")
                    row_invalid = True
                label = row.get("ground_truth_label", "")
                report.label_distribution[label] = report.label_distribution.get(label, 0) + 1
                report.session_distribution[row.get("capture_session_id", "")] = (
                    report.session_distribution.get(row.get("capture_session_id", ""), 0) + 1
                )
                protocol = row.get("protocol", "")
                report.protocol_distribution[protocol] = report.protocol_distribution.get(protocol, 0) + 1
                if label == "unknown":
                    report.unknown_labels += 1
                elif label not in LABELS:
                    report.invalid_values += 1
                    report.issues.append(f"row {row_number}: unknown label {label!r}")
                    row_invalid = True
                if row.get("flow_lifecycle_reason") not in LIFECYCLE_REASONS:
                    report.invalid_values += 1
                    report.issues.append(f"row {row_number}: unknown lifecycle reason")
                    row_invalid = True
                if row.get("flow_lifecycle_reason") in {"active_timeout", "flush", "inactive_timeout", "capacity_eviction"}:
                    report.incomplete_flows += 1
                fingerprint = DatasetCollector._fingerprint(row)
                if fingerprint in seen:
                    report.duplicate_flows += 1
                    report.issues.append(f"row {row_number}: duplicate flow")
                seen.add(fingerprint)
                if row_invalid:
                    report.invalid_rows += 1
                else:
                    report.valid_rows += 1
    except OSError as error:
        report.issues.append(f"unable to read dataset: {error}")
    return report


def apply_manual_corrections(
    source_path: Path, corrections_path: Path, output_path: Path
) -> int:
    """Write a corrected derived CSV while leaving the captured source unchanged."""
    corrections: dict[str, dict[str, str]] = {}
    with Path(corrections_path).open("r", encoding="utf-8", newline="") as file:
        for correction in csv.DictReader(file):
            label = correction.get("ground_truth_label", "")
            if label not in LABELS:
                raise ValueError(f"invalid correction label: {label!r}")
            corrections[correction["record_id"]] = correction

    corrected = 0
    with Path(source_path).open("r", encoding="utf-8", newline="") as source:
        reader = csv.DictReader(source)
        fields = list(reader.fieldnames or [])
        for extra in ("original_ground_truth_label", "original_label_source"):
            if extra not in fields:
                fields.append(extra)
        with Path(output_path).open("w", encoding="utf-8", newline="") as destination:
            writer = csv.DictWriter(destination, fieldnames=fields)
            writer.writeheader()
            for row in reader:
                correction = corrections.get(row.get("record_id", ""))
                if correction:
                    row["original_ground_truth_label"] = row.get("ground_truth_label", "")
                    row["original_label_source"] = row.get("label_source", "")
                    row["ground_truth_label"] = correction["ground_truth_label"]
                    row["label_source"] = "manual_correction"
                    row["label_confidence"] = correction.get("label_confidence", "1.0")
                    row["label_reason"] = correction.get("label_reason", "manual correction")
                    corrected += 1
                else:
                    row.setdefault("original_ground_truth_label", "")
                    row.setdefault("original_label_source", "")
                writer.writerow(row)
    return corrected


def _main() -> None:
    parser = argparse.ArgumentParser(description="Collect and validate live flow datasets")
    subparsers = parser.add_subparsers(dest="command", required=True)
    validate_parser = subparsers.add_parser("validate")
    validate_parser.add_argument("dataset", type=Path)
    collect_parser = subparsers.add_parser("collect")
    collect_parser.add_argument("--interface", required=True)
    collect_parser.add_argument("--output-dir", type=Path, required=True)
    collect_parser.add_argument("--session-id", required=True)
    collect_parser.add_argument("--sensor-id", required=True)
    collect_parser.add_argument("--bpf-filter", default="tcp or udp")
    collect_parser.add_argument("--experiments", type=Path)
    args = parser.parse_args()

    if args.command == "validate":
        report = validate_dataset(args.dataset)
        print(json.dumps(asdict(report), indent=2))
        raise SystemExit(0 if report.valid else 2)

    from .scapy_adapter import ScapyCapture

    labeler = GroundTruthLabeler.from_json(args.experiments) if args.experiments else GroundTruthLabeler()
    with DatasetCollector(args.output_dir, args.session_id, args.sensor_id, labeler) as collector:
        capture = ScapyCapture(
            args.interface,
            bpf_filter=args.bpf_filter,
            on_flow=collector.record_flow,
        )
        stats = capture.run()
        print(json.dumps(asdict(stats), indent=2))


if __name__ == "__main__":
    _main()
