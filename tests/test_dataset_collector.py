import csv
import json
import tempfile
import unittest
from pathlib import Path

from rt_nid_ml.dataset_collector import (
    DATASET_COLUMNS,
    DatasetCollector,
    ExperimentSpec,
    GroundTruthLabeler,
    apply_manual_corrections,
    validate_dataset,
)
from rt_nid_ml.flow_extractor import FlowKey, FlowRecord, LIVE_FLOW_FEATURE_COLUMNS


def flow_record(
    start: float = 10.0,
    end: float = 12.0,
    reason: str = "tcp_finished",
) -> FlowRecord:
    features = {name: float(index + 1) for index, name in enumerate(LIVE_FLOW_FEATURE_COLUMNS)}
    return FlowRecord(
        key=FlowKey("10.0.0.1", 40000, "10.0.0.2", 22, "TCP"),
        reason=reason,
        first_seen=start,
        last_seen=end,
        features=features,
    )


class DatasetCollectorTests(unittest.TestCase):
    def test_row_preserves_features_and_explicit_experiment_label(self) -> None:
        labeler = GroundTruthLabeler(
            [ExperimentSpec("exp-1", "brute_force", 9.0, 13.0, "10.0.0.2")]
        )
        with tempfile.TemporaryDirectory() as directory:
            with DatasetCollector(Path(directory), "session-1", "sensor-a", labeler) as collector:
                row = collector.record_flow(flow_record())

            self.assertEqual(row["ground_truth_label"], "brute_force")
            self.assertEqual(row["experiment_id"], "exp-1")
            self.assertEqual(row["experiment_start_timestamp"], 9.0)
            self.assertEqual(row["experiment_end_timestamp"], 13.0)
            self.assertEqual(row["target_ip"], "10.0.0.2")
            self.assertEqual(row["capture_session_id"], "session-1")
            self.assertEqual(row["sensor_id"], "sensor-a")
            self.assertEqual(row["protocol"], "TCP")
            self.assertEqual(set(LIVE_FLOW_FEATURE_COLUMNS), {
                column for column in DATASET_COLUMNS if column in LIVE_FLOW_FEATURE_COLUMNS
            })
            self.assertTrue((Path(directory) / "session_session-1.json").exists())

    def test_unmatched_flow_remains_unknown(self) -> None:
        labeler = GroundTruthLabeler(
            [ExperimentSpec("exp-1", "dos", 9.0, 13.0, "10.0.0.99")]
        )
        decision = labeler.label(flow_record())

        self.assertEqual(decision.label, "unknown")
        self.assertEqual(decision.source, "unassigned")

    def test_target_and_time_scope_prevent_broad_attack_labeling(self) -> None:
        labeler = GroundTruthLabeler(
            [ExperimentSpec("exp-1", "port_scan", 20.0, 30.0, "10.0.0.2")]
        )

        decision = labeler.label(flow_record())

        self.assertEqual(decision.label, "unknown")

    def test_incremental_write_flush_and_sidecar_stats(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            collector = DatasetCollector(Path(directory), "session-2", "sensor-b")
            collector.record_flow(flow_record())
            collector.flush()
            data_path = Path(directory) / "session_session-2.csv"
            self.assertGreater(data_path.stat().st_size, 0)
            collector.close()

            metadata = json.loads((Path(directory) / "session_session-2.json").read_text())
            self.assertEqual(metadata["status"], "closed")
            self.assertEqual(metadata["stats"]["rows_written"], 1)

    def test_validation_reports_duplicates_incomplete_and_distribution(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            collector = DatasetCollector(Path(directory), "session-3", "sensor-c")
            collector.record_flow(flow_record(reason="flush"))
            collector.record_flow(flow_record(reason="flush"))
            collector.close()

            report = validate_dataset(Path(directory) / "session_session-3.csv")

            self.assertEqual(report.row_count, 2)
            self.assertEqual(report.duplicate_flows, 1)
            self.assertEqual(report.incomplete_flows, 2)
            self.assertEqual(report.unknown_labels, 2)
            self.assertEqual(report.protocol_distribution["TCP"], 2)
            self.assertEqual(report.session_distribution["session-3"], 2)

    def test_validation_reports_invalid_feature_and_label(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            collector = DatasetCollector(Path(directory), "session-4", "sensor-d")
            collector.record_flow(flow_record())
            collector.close()
            path = Path(directory) / "session_session-4.csv"
            with path.open(newline="", encoding="utf-8") as file:
                rows = list(csv.DictReader(file))
            rows[0]["packet_count"] = "nan"
            rows[0]["ground_truth_label"] = "fabricated"
            with path.open("w", newline="", encoding="utf-8") as file:
                writer = csv.DictWriter(file, fieldnames=DATASET_COLUMNS)
                writer.writeheader()
                writer.writerows(rows)

            report = validate_dataset(path)

            self.assertFalse(report.valid)
            self.assertGreaterEqual(report.invalid_values, 2)
            self.assertTrue(report.issues)

    def test_manual_correction_creates_derived_file_with_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            collector = DatasetCollector(root, "session-5", "sensor-e")
            collector.record_flow(flow_record())
            collector.close()
            source = root / "session_session-5.csv"
            with source.open(newline="", encoding="utf-8") as file:
                row = next(csv.DictReader(file))
            corrections = root / "corrections.csv"
            with corrections.open("w", newline="", encoding="utf-8") as file:
                writer = csv.DictWriter(
                    file,
                    fieldnames=["record_id", "ground_truth_label", "label_confidence", "label_reason"],
                )
                writer.writeheader()
                writer.writerow({
                    "record_id": row["record_id"],
                    "ground_truth_label": "normal",
                    "label_confidence": "0.9",
                    "label_reason": "operator review",
                })
            corrected = root / "corrected.csv"

            count = apply_manual_corrections(source, corrections, corrected)
            with corrected.open(newline="", encoding="utf-8") as file:
                corrected_row = next(csv.DictReader(file))
            with source.open(newline="", encoding="utf-8") as file:
                original_row = next(csv.DictReader(file))

            self.assertEqual(count, 1)
            self.assertEqual(corrected_row["ground_truth_label"], "normal")
            self.assertEqual(corrected_row["original_ground_truth_label"], original_row["ground_truth_label"])
            self.assertEqual(original_row["ground_truth_label"], "unknown")


if __name__ == "__main__":
    unittest.main()
