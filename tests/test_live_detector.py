import tempfile
import unittest
from pathlib import Path

import joblib
import numpy as np

from rt_nid_ml.flow_extractor import FlowKey, FlowRecord, LIVE_FLOW_FEATURE_COLUMNS
from rt_nid_ml.live_detector import LiveInferenceEngine, LiveInferenceError


class FakeCalibratedModel:
    def __init__(self, classes, probabilities):
        self.classes_ = np.asarray(classes)
        self.probabilities = np.asarray(probabilities, dtype=float)

    def predict_proba(self, _features):
        return np.asarray([self.probabilities])


def make_record(reason: str = "tcp_finished", features=None, start: float = 10.0) -> FlowRecord:
    values = {column: 1.0 for column in LIVE_FLOW_FEATURE_COLUMNS}
    if features:
        values.update(features)
    return FlowRecord(
        key=FlowKey("10.0.0.1", 40000, "10.0.0.2", 443, "TCP"),
        reason=reason,
        first_seen=start,
        last_seen=start + 2.0,
        features=values,
    )


def write_artifact(
    directory: Path,
    classes=("normal", "suspicious"),
    approach="binary",
    probabilities=(0.1, 0.9),
    supported=True,
    feature_columns=None,
    include_calibrator=True,
) -> Path:
    model = FakeCalibratedModel(classes, probabilities)
    artifact = {
        "artifact_type": "live_flow_model",
        "artifact_schema_version": 1,
        "feature_schema_version": 1,
        "model_version": "test-live-v1",
        "approach": approach,
        "model": model,
        "estimator": model,
        "model_family": "test",
        "feature_columns": feature_columns or list(LIVE_FLOW_FEATURE_COLUMNS),
        "classes": list(classes),
        "selected_thresholds": {
            "1.000%": {
                "target_fpr": 0.01,
                "threshold": 0.5,
                "supported": supported,
            }
        },
        "calibration": {"method": "sigmoid", "calibration_rows": 10},
    }
    if include_calibrator:
        artifact["calibrator"] = model
    path = directory / "live_model.joblib"
    joblib.dump(artifact, path)
    return path


class LiveDetectorTests(unittest.TestCase):
    def test_binary_artifact_loads_and_maps_actual_class_order(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = write_artifact(
                Path(directory),
                classes=("suspicious", "normal"),
                probabilities=(0.9, 0.1),
            )
            engine = LiveInferenceEngine(path)

            result = engine.process_flow(make_record())

            self.assertIsNotNone(result)
            assert result is not None
            self.assertEqual(result.predicted_label, "suspicious")
            self.assertEqual(result.decision_status, "detected")
            self.assertAlmostEqual(result.calibrated_probability or 0.0, 0.9)

    def test_multiclass_artifact_returns_attack_category(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = write_artifact(
                Path(directory),
                classes=("dos", "normal", "port_scan", "brute_force"),
                approach="multiclass",
                probabilities=(0.8, 0.05, 0.1, 0.05),
            )
            result = LiveInferenceEngine(path).process_flow(make_record())

            self.assertEqual(result.predicted_label, "dos")
            self.assertEqual(result.decision_status, "detected")

    def test_cicids_artifact_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "cicids.joblib"
            joblib.dump({"artifact_type": "CICIDS2017"}, path)

            with self.assertRaisesRegex(LiveInferenceError, "incompatible artifact type"):
                LiveInferenceEngine(path)

    def test_schema_order_and_missing_calibrator_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            reversed_columns = list(reversed(LIVE_FLOW_FEATURE_COLUMNS))
            path = write_artifact(Path(directory), feature_columns=reversed_columns)
            with self.assertRaisesRegex(LiveInferenceError, "schema or ordering"):
                LiveInferenceEngine(path)

            path = write_artifact(Path(directory), include_calibrator=False)
            with self.assertRaisesRegex(LiveInferenceError, "calibrated probability"):
                LiveInferenceEngine(path)

    def test_invalid_nan_and_infinity_features_abstain(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = write_artifact(Path(directory))
            engine = LiveInferenceEngine(path)

            nan_result = engine.process_flow(make_record(features={"packet_count": float("nan")}))
            inf_result = engine.process_flow(
                make_record(
                    features={"byte_count": float("inf"), "flow_duration_seconds": 2.0},
                    start=20.0,
                )
            )

            self.assertEqual(nan_result.decision_status, "unknown")
            self.assertEqual(inf_result.decision_status, "unknown")
            self.assertIn("non-finite", nan_result.decision_reason)

    def test_unsupported_threshold_abstains(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = write_artifact(Path(directory), supported=False)
            result = LiveInferenceEngine(path).process_flow(make_record())

            self.assertEqual(result.decision_status, "unknown")
            self.assertEqual(result.decision_reason, "selected_threshold_unsupported")

    def test_duplicate_flow_is_not_processed_twice(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            engine = LiveInferenceEngine(write_artifact(Path(directory)))
            record = make_record()

            first = engine.process_flow(record)
            second = engine.process_flow(record)

            self.assertIsNotNone(first)
            self.assertIsNone(second)
            self.assertEqual(engine.metrics.duplicate_flows, 1)

    def test_incomplete_flow_policy_is_configurable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = write_artifact(Path(directory))
            default_result = LiveInferenceEngine(path).process_flow(make_record("flush"))
            allowed_result = LiveInferenceEngine(
                path, classify_incomplete_flows=True
            ).process_flow(make_record("flush"))

            self.assertEqual(default_result.decision_status, "unknown")
            self.assertEqual(default_result.decision_reason, "incomplete_flow_not_classified")
            self.assertEqual(allowed_result.decision_status, "detected")
            self.assertEqual(allowed_result.flow_completion_reason, "flush")

    def test_artifact_reload_and_invalid_threshold_are_handled(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = write_artifact(Path(directory))
            reloaded = joblib.load(path)
            self.assertEqual(reloaded["artifact_type"], "live_flow_model")
            with self.assertRaisesRegex(LiveInferenceError, "threshold configuration not found"):
                LiveInferenceEngine(path, threshold_name="0.100%")


if __name__ == "__main__":
    unittest.main()
