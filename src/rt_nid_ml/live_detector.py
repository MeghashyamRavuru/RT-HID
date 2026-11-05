"""Phase 5 inference for the calibrated 15-feature live-flow artifact.

The legacy detector remains separate. This module consumes completed
FlowRecord objects and never classifies individual packets.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import math
import uuid
from collections import deque
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Callable, Mapping

import joblib
import numpy as np
import pandas as pd

from .flow_extractor import LIVE_FLOW_FEATURE_COLUMNS, FlowRecord

LIVE_ARTIFACT_TYPE = "live_flow_model"
SUPPORTED_ARTIFACT_SCHEMA_VERSION = 1
SUPPORTED_FEATURE_SCHEMA_VERSION = 1
SUPPORTED_APPROACHES = {
    "binary": {"normal", "suspicious"},
    "multiclass": {"normal", "port_scan", "brute_force", "dos"},
}
INCOMPLETE_FLOW_REASONS = {
    "active_timeout",
    "capacity_eviction",
    "flush",
    "inactive_timeout",
}
RESULT_SCHEMA_VERSION = 1


class LiveInferenceError(ValueError):
    """Raised when an artifact cannot be used safely for live inference."""


@dataclass(frozen=True)
class DetectionResult:
    result_schema_version: int
    event_id: str
    event_timestamp: float
    flow_id: str
    source_ip: str
    source_port: int
    destination_ip: str
    destination_port: int
    protocol: str
    predicted_label: str
    calibrated_probability: float | None
    selected_threshold: float | None
    model_version: str
    feature_schema_version: int
    decision_status: str
    decision_reason: str
    flow_completion_reason: str
    features: dict[str, float | None]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class InferenceMetrics:
    processed_flows: int = 0
    rejected_flows: int = 0
    failed_inferences: int = 0
    duplicate_flows: int = 0
    unknown_decisions: int = 0


class LiveInferenceEngine:
    """Validate one live artifact and classify completed flow records."""

    def __init__(
        self,
        artifact_path: str | Path,
        threshold_name: str = "1.000%",
        classify_incomplete_flows: bool = False,
        max_seen_flow_ids: int = 100_000,
        on_result: Callable[[DetectionResult], None] | None = None,
        logger: logging.Logger | None = None,
    ) -> None:
        if max_seen_flow_ids < 1:
            raise LiveInferenceError("max_seen_flow_ids must be positive")
        self.artifact_path = Path(artifact_path)
        self.artifact = self._load_and_validate_artifact()
        self.threshold_name = threshold_name
        self.threshold_config = self._validate_threshold(
            self.artifact["selected_thresholds"], threshold_name
        )
        self.classify_incomplete_flows = classify_incomplete_flows
        self.on_result = on_result
        self.logger = logger or logging.getLogger(__name__)
        self.metrics = InferenceMetrics()
        self._seen_flow_ids: set[str] = set()
        self._flow_id_order: deque[str] = deque(maxlen=max_seen_flow_ids)

    def process_flow(self, record: FlowRecord) -> DetectionResult | None:
        """Classify one completed flow, returning None for a duplicate."""
        flow_id = self.flow_id(record)
        if flow_id in self._seen_flow_ids:
            self.metrics.duplicate_flows += 1
            return None
        self._remember_flow(flow_id)
        self.metrics.processed_flows += 1

        base = self._base_result(record, flow_id)
        if record.reason in INCOMPLETE_FLOW_REASONS and not self.classify_incomplete_flows:
            result = self._replace_result(
                base,
                decision_status="unknown",
                decision_reason="incomplete_flow_not_classified",
            )
            return self._publish_unknown(result)

        try:
            vector = self._validated_vector(record.features)
        except LiveInferenceError as error:
            self.metrics.rejected_flows += 1
            result = self._replace_result(
                base,
                decision_status="unknown",
                decision_reason=str(error),
            )
            return self._publish_unknown(result)

        try:
            probabilities = np.asarray(self.artifact["model"].predict_proba(vector)[0], dtype=float)
            result = self._decide(base, probabilities)
        except (AttributeError, IndexError, TypeError, ValueError, OverflowError) as error:
            self.metrics.failed_inferences += 1
            self.logger.error("live flow inference failed: %s", error)
            result = self._replace_result(
                base,
                decision_status="unknown",
                decision_reason="probability_inference_failed",
            )
            return self._publish_unknown(result)
        if result.decision_status == "unknown":
            return self._publish_unknown(result)
        return self._publish(result)

    def capture_callback(self, record: FlowRecord) -> DetectionResult | None:
        """Callback suitable for ScapyCapture(on_flow=...)."""
        return self.process_flow(record)

    def _decide(self, base: DetectionResult, probabilities: np.ndarray) -> DetectionResult:
        classes = [str(label) for label in self.artifact["classes"]]
        if probabilities.ndim != 1 or len(probabilities) != len(classes):
            raise LiveInferenceError("model probability columns do not match artifact classes")
        if not np.isfinite(probabilities).all() or (probabilities < 0).any():
            raise LiveInferenceError("model returned invalid probabilities")
        if not math.isclose(float(probabilities.sum()), 1.0, rel_tol=1e-4, abs_tol=1e-4):
            raise LiveInferenceError("model probabilities do not sum to one")

        normal_index = classes.index("normal")
        attack_probability = float(1.0 - probabilities[normal_index])
        if not self.threshold_config["supported"]:
            return self._replace_result(
                base,
                calibrated_probability=attack_probability,
                selected_threshold=float(self.threshold_config["threshold"]),
                decision_status="unknown",
                decision_reason="selected_threshold_unsupported",
            )
        threshold = float(self.threshold_config["threshold"])
        predicted_class = classes[int(probabilities.argmax())]
        if attack_probability < threshold:
            return self._replace_result(
                base,
                predicted_label="benign",
                calibrated_probability=attack_probability,
                selected_threshold=threshold,
                decision_status="benign",
                decision_reason="attack_probability_below_threshold",
            )
        if self.artifact["approach"] == "binary":
            label = "suspicious"
        elif predicted_class == "normal":
            return self._replace_result(
                base,
                calibrated_probability=attack_probability,
                selected_threshold=threshold,
                decision_status="unknown",
                decision_reason="attack_score_exceeds_threshold_but_class_is_normal",
            )
        else:
            label = predicted_class
        return self._replace_result(
            base,
            predicted_label=label,
            calibrated_probability=attack_probability,
            selected_threshold=threshold,
            decision_status="detected",
            decision_reason="attack_probability_meets_threshold",
        )

    def _validated_vector(self, features: Mapping[str, Any]) -> pd.DataFrame:
        if set(features) != set(LIVE_FLOW_FEATURE_COLUMNS):
            missing = sorted(set(LIVE_FLOW_FEATURE_COLUMNS) - set(features))
            unexpected = sorted(set(features) - set(LIVE_FLOW_FEATURE_COLUMNS))
            raise LiveInferenceError(
                f"feature schema mismatch; missing={missing}, unexpected={unexpected}"
            )
        values: list[float] = []
        for column in LIVE_FLOW_FEATURE_COLUMNS:
            try:
                value = float(features[column])
            except (TypeError, ValueError, OverflowError) as error:
                raise LiveInferenceError(f"invalid feature value: {column}") from error
            if not math.isfinite(value):
                raise LiveInferenceError(f"non-finite feature value: {column}")
            values.append(value)
        return pd.DataFrame([values], columns=list(LIVE_FLOW_FEATURE_COLUMNS))

    def _base_result(self, record: FlowRecord, flow_id: str) -> DetectionResult:
        return DetectionResult(
            result_schema_version=RESULT_SCHEMA_VERSION,
            event_id=uuid.uuid4().hex,
            event_timestamp=float(record.last_seen),
            flow_id=flow_id,
            source_ip=record.key.src_ip,
            source_port=record.key.src_port,
            destination_ip=record.key.dst_ip,
            destination_port=record.key.dst_port,
            protocol=record.key.protocol,
            predicted_label="unknown",
            calibrated_probability=None,
            selected_threshold=None,
            model_version=str(self.artifact["model_version"]),
            feature_schema_version=int(self.artifact["feature_schema_version"]),
            decision_status="unknown",
            decision_reason="not_evaluated",
            flow_completion_reason=record.reason,
            features=self._safe_features(record.features),
        )

    @staticmethod
    def _safe_features(features: Mapping[str, Any]) -> dict[str, float | None]:
        safe: dict[str, float | None] = {}
        for column in LIVE_FLOW_FEATURE_COLUMNS:
            try:
                value = float(features[column])
            except (KeyError, TypeError, ValueError, OverflowError):
                safe[column] = None
            else:
                safe[column] = value if math.isfinite(value) else None
        return safe

    def _replace_result(self, result: DetectionResult, **changes: Any) -> DetectionResult:
        values = result.to_dict()
        values.update(changes)
        return DetectionResult(**values)

    def _publish_unknown(self, result: DetectionResult) -> DetectionResult:
        self.metrics.unknown_decisions += 1
        return self._publish(result)

    def _publish(self, result: DetectionResult) -> DetectionResult:
        if self.on_result:
            self.on_result(result)
        return result

    def _remember_flow(self, flow_id: str) -> None:
        if len(self._flow_id_order) == self._flow_id_order.maxlen:
            expired = self._flow_id_order.popleft()
            self._seen_flow_ids.discard(expired)
        self._flow_id_order.append(flow_id)
        self._seen_flow_ids.add(flow_id)

    @staticmethod
    def flow_id(record: FlowRecord) -> str:
        identity = "|".join(
            str(value)
            for value in (
                record.key.src_ip,
                record.key.src_port,
                record.key.dst_ip,
                record.key.dst_port,
                record.key.protocol,
                record.first_seen,
                record.last_seen,
            )
        )
        return hashlib.sha256(identity.encode("utf-8")).hexdigest()

    def _load_and_validate_artifact(self) -> dict[str, Any]:
        try:
            artifact = joblib.load(self.artifact_path)
        except Exception as error:
            raise LiveInferenceError(f"unable to load live artifact: {error}") from error
        if not isinstance(artifact, dict):
            raise LiveInferenceError("artifact is not a metadata dictionary")
        if artifact.get("artifact_type") != LIVE_ARTIFACT_TYPE:
            raise LiveInferenceError(
                "incompatible artifact type; expected live_flow_model, not CICIDS2017"
            )
        if artifact.get("artifact_schema_version") != SUPPORTED_ARTIFACT_SCHEMA_VERSION:
            raise LiveInferenceError("unsupported live artifact schema version")
        if artifact.get("feature_schema_version") != SUPPORTED_FEATURE_SCHEMA_VERSION:
            raise LiveInferenceError("unsupported or missing feature schema version")
        if artifact.get("feature_columns") != list(LIVE_FLOW_FEATURE_COLUMNS):
            raise LiveInferenceError("live artifact feature schema or ordering mismatch")
        approach = artifact.get("approach")
        classes = [str(label) for label in artifact.get("classes", [])]
        if approach not in SUPPORTED_APPROACHES:
            raise LiveInferenceError("unsupported live artifact approach")
        if set(classes) != SUPPORTED_APPROACHES[approach] or len(classes) != len(set(classes)):
            raise LiveInferenceError("live artifact class labels are invalid")
        model = artifact.get("model")
        calibrator = artifact.get("calibrator")
        if not hasattr(model, "predict_proba") or not hasattr(calibrator, "predict_proba"):
            raise LiveInferenceError("live artifact is missing calibrated probability components")
        model_classes = [str(label) for label in getattr(model, "classes_", [])]
        if model_classes != classes:
            raise LiveInferenceError("model class ordering does not match artifact classes")
        calibrator_classes = [
            str(label) for label in getattr(calibrator, "classes_", classes)
        ]
        if calibrator_classes != classes:
            raise LiveInferenceError("calibrator class ordering does not match artifact classes")
        calibration = artifact.get("calibration")
        if not isinstance(calibration, dict) or calibration.get("method") != "sigmoid":
            raise LiveInferenceError("missing required sigmoid calibration metadata")
        thresholds = artifact.get("selected_thresholds")
        if not isinstance(thresholds, dict) or not thresholds:
            raise LiveInferenceError("missing threshold configuration")
        for threshold_name in thresholds:
            self._validate_threshold(thresholds, threshold_name)
        if not artifact.get("model_version"):
            raise LiveInferenceError("missing model version")
        return artifact

    @staticmethod
    def _validate_threshold(thresholds: dict[str, Any], name: str) -> dict[str, Any]:
        if name not in thresholds:
            raise LiveInferenceError(f"threshold configuration not found: {name}")
        configuration = thresholds[name]
        if not isinstance(configuration, dict):
            raise LiveInferenceError(f"invalid threshold configuration: {name}")
        try:
            threshold = float(configuration["threshold"])
            target = float(configuration["target_fpr"])
            supported = bool(configuration["supported"])
        except (KeyError, TypeError, ValueError) as error:
            raise LiveInferenceError(f"invalid threshold configuration: {name}") from error
        if not 0.0 <= threshold <= 1.0 or not 0.0 <= target <= 1.0:
            raise LiveInferenceError(f"threshold values out of range: {name}")
        if not isinstance(configuration["supported"], bool):
            raise LiveInferenceError(f"threshold supported flag must be boolean: {name}")
        return {**configuration, "threshold": threshold, "target_fpr": target, "supported": supported}


def run_capture(
    interface: str,
    artifact_path: str | Path,
    bpf_filter: str = "tcp or udp",
    threshold_name: str = "1.000%",
    classify_incomplete_flows: bool = False,
) -> InferenceMetrics:
    """Run the Phase 3A capture pipeline through live inference."""
    from .scapy_adapter import ScapyCapture

    engine = LiveInferenceEngine(
        artifact_path,
        threshold_name=threshold_name,
        classify_incomplete_flows=classify_incomplete_flows,
        on_result=lambda result: print(json.dumps(result.to_dict()), flush=True),
    )
    capture = ScapyCapture(interface, bpf_filter=bpf_filter, on_flow=engine.capture_callback)
    capture.run()
    return engine.metrics


def main() -> None:
    parser = argparse.ArgumentParser(description="Run live-flow ML inference")
    parser.add_argument("--interface", required=True)
    parser.add_argument("--model", required=True, help="Path to a live_flow_model artifact")
    parser.add_argument("--bpf-filter", default="tcp or udp")
    parser.add_argument("--threshold", default="1.000%")
    parser.add_argument("--classify-incomplete", action="store_true")
    args = parser.parse_args()
    run_capture(
        args.interface,
        args.model,
        args.bpf_filter,
        args.threshold,
        args.classify_incomplete,
    )


if __name__ == "__main__":
    main()
