import json
import tempfile
import unittest
from pathlib import Path

import numpy as np
import pandas as pd

from rt_nid_ml.dataset_collector import DatasetCollector, ExperimentSpec, GroundTruthLabeler
from rt_nid_ml.flow_extractor import FlowKey, FlowRecord, LIVE_FLOW_FEATURE_COLUMNS
from rt_nid_ml.live_train import (
    LiveDatasetError,
    load_live_dataset,
    select_thresholds,
    session_aware_split,
    train_and_save,
)


def make_record(port: int, timestamp: float) -> FlowRecord:
    return FlowRecord(
        key=FlowKey("10.0.0.1", 40000 + port, "10.0.0.2", port, "TCP"),
        reason="tcp_finished",
        first_seen=timestamp,
        last_seen=timestamp + 1,
        features={name: float(index + port) for index, name in enumerate(LIVE_FLOW_FEATURE_COLUMNS)},
    )


def create_sessions(root: Path, count: int = 8, multiclass: bool = False) -> None:
    for index in range(count):
        session_id = f"session-{index}"
        start = float(index * 10)
        labels = ["normal", "port_scan"]
        if multiclass:
            labels.extend(["brute_force", "dos"])
        experiments = [
            ExperimentSpec(
                f"{label}-{index}",
                label,
                start + offset * 4 - 1,
                start + offset * 4 + 3,
                "10.0.0.2",
            )
            for offset, label in enumerate(labels)
        ]
        with DatasetCollector(
            root,
            session_id,
            "sensor-test",
            labeler=GroundTruthLabeler(experiments),
        ) as collector:
            for offset, _label in enumerate(labels):
                collector.record_flow(make_record(80 + offset, start + offset * 4))


class LiveTrainingTests(unittest.TestCase):
    def test_loader_preserves_schema_provenance_and_maps_binary_labels(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            create_sessions(Path(directory), 8)

            x, y, metadata, report = load_live_dataset(Path(directory), "binary")

            self.assertEqual(list(x.columns), list(LIVE_FLOW_FEATURE_COLUMNS))
            self.assertEqual(set(y), {"normal", "suspicious"})
            self.assertEqual(len(metadata), len(x))
            self.assertEqual(report.excluded_unknown, 0)
            self.assertEqual(len(report.provenance), 8)

    def test_unknown_labels_are_excluded(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            create_sessions(Path(directory), 8)
            session_path = Path(directory) / "session_session-0.csv"
            rows = pd.read_csv(session_path, dtype=str)
            rows.loc[0, "ground_truth_label"] = "unknown"
            rows.to_csv(session_path, index=False)

            _, y, _, report = load_live_dataset(Path(directory), "binary")

            self.assertEqual(report.excluded_unknown, 1)
            self.assertEqual(len(y), 15)

    def test_multiclass_mapping_preserves_attack_categories(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            create_sessions(Path(directory), 8, multiclass=True)

            _, y, _, report = load_live_dataset(Path(directory), "multiclass")

            self.assertEqual(set(y), {"normal", "port_scan", "brute_force", "dos"})
            self.assertEqual(report.excluded_unknown, 0)

    def test_schema_mismatch_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            create_sessions(Path(directory), 8)
            sidecar_path = Path(directory) / "session_session-0.json"
            sidecar = json.loads(sidecar_path.read_text())
            sidecar["feature_columns"] = ["wrong_feature"]
            sidecar_path.write_text(json.dumps(sidecar))

            with self.assertRaises(LiveDatasetError):
                load_live_dataset(Path(directory), "binary")

    def test_session_aware_split_never_overlaps_sessions(self) -> None:
        metadata = pd.DataFrame({"session_id": [f"s{i}" for i in range(8) for _ in range(2)]})
        labels = pd.Series(["normal", "suspicious"] * 8)

        partitions = session_aware_split(labels, metadata, seed=7)
        session_sets = [
            set(metadata.iloc[partitions[name]]["session_id"])
            for name in ("train", "calibration", "threshold", "final_test")
        ]

        self.assertEqual(sum(map(len, session_sets)), 8)
        self.assertEqual(len(set.union(*session_sets)), 8)
        self.assertEqual(sum(len(left & right) for left in session_sets for right in session_sets), 8)

    def test_insufficient_independent_sessions_are_rejected(self) -> None:
        metadata = pd.DataFrame({"session_id": ["s1", "s1", "s2", "s2", "s3", "s3"]})
        labels = pd.Series(["normal", "suspicious"] * 3)

        with self.assertRaises(LiveDatasetError):
            session_aware_split(labels, metadata, seed=7)

    def test_thresholds_mark_unsupported_benign_sample_targets(self) -> None:
        class FakeModel:
            classes_ = np.array(["normal", "suspicious"])

            def predict_proba(self, features):
                scores = features["score"].to_numpy()
                return np.column_stack([1 - scores, scores])

        thresholds = select_thresholds(
            FakeModel(),
            pd.DataFrame({"score": [0.1, 0.2, 0.8, 0.9]}),
            pd.Series(["normal", "normal", "suspicious", "suspicious"]),
        )

        self.assertFalse(thresholds["0.100%"]["supported"])
        self.assertEqual(thresholds["1.000%"]["benign_validation_samples"], 2)

    def test_live_artifact_saves_and_reloads(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            create_sessions(root / "data", 8)
            output = root / "live_model.joblib"

            artifact = train_and_save(root / "data", output, "binary", seed=7)
            import joblib

            loaded = joblib.load(output)

            self.assertEqual(artifact["artifact_type"], "live_flow_model")
            self.assertEqual(loaded["feature_columns"], list(LIVE_FLOW_FEATURE_COLUMNS))
            self.assertTrue(hasattr(loaded["model"], "predict_proba"))


if __name__ == "__main__":
    unittest.main()
