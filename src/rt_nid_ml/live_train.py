"""Phase 4 training for the custom 15-feature live-flow dataset.

This pipeline is intentionally separate from ``train.py``. Its input schema is
LIVE_FLOW_FEATURE_COLUMNS from flow_extractor.py and its artifact type is
``live_flow_model``; it must not be used as a CICFlowMeter model.
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import ExtraTreesClassifier, HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    balanced_accuracy_score,
    brier_score_loss,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.pipeline import Pipeline
from sklearn.model_selection import GroupShuffleSplit

from .dataset_collector import DATASET_COLUMNS, SCHEMA_VERSION
from .flow_extractor import LIVE_FLOW_FEATURE_COLUMNS

LIVE_ARTIFACT_TYPE = "live_flow_model"
LIVE_ARTIFACT_SCHEMA_VERSION = 1
LIVE_MODEL_VERSION = "live-flow-v1"
MIN_INDEPENDENT_SESSIONS_PER_CLASS = 2
TARGET_FPRS = (0.01, 0.005, 0.001)
BINARY_LABELS = ("normal", "suspicious")
MULTICLASS_LABELS = ("normal", "port_scan", "brute_force", "dos")


class LiveDatasetError(ValueError):
    """Raised when session data cannot support a trustworthy training run."""


class DatasetLoadReport:
    def __init__(self) -> None:
        self.files_read = 0
        self.rows_read = 0
        self.rows_loaded = 0
        self.excluded_invalid = 0
        self.excluded_unknown = 0
        self.excluded_duplicate = 0
        self.exclusion_reasons: Counter[str] = Counter()
        self.session_distribution: Counter[str] = Counter()
        self.label_distribution: Counter[str] = Counter()
        self.provenance: list[str] = []

    def as_dict(self) -> dict[str, Any]:
        return {
            "files_read": self.files_read,
            "rows_read": self.rows_read,
            "rows_loaded": self.rows_loaded,
            "excluded_invalid": self.excluded_invalid,
            "excluded_unknown": self.excluded_unknown,
            "excluded_duplicate": self.excluded_duplicate,
            "exclusion_reasons": dict(self.exclusion_reasons),
            "session_distribution": dict(self.session_distribution),
            "label_distribution": dict(self.label_distribution),
            "provenance": self.provenance,
        }


def _read_sidecar(csv_path: Path) -> dict[str, Any]:
    sidecar_path = csv_path.with_suffix(".json")
    if not sidecar_path.is_file():
        raise LiveDatasetError(f"missing metadata sidecar: {sidecar_path.name}")
    try:
        payload = json.loads(sidecar_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise LiveDatasetError(f"invalid metadata sidecar: {sidecar_path.name}") from error
    if payload.get("schema_version") != SCHEMA_VERSION:
        raise LiveDatasetError(
            f"{sidecar_path.name} has unsupported schema version "
            f"{payload.get('schema_version')!r}"
        )
    if payload.get("feature_columns") != list(LIVE_FLOW_FEATURE_COLUMNS):
        raise LiveDatasetError(f"{sidecar_path.name} has a live feature schema mismatch")
    if not payload.get("session_id") or not payload.get("sensor_id"):
        raise LiveDatasetError(f"{sidecar_path.name} lacks session or sensor metadata")
    return payload


def _flow_fingerprint(frame: pd.DataFrame) -> pd.Series:
    identity_columns = [
        "source_ip",
        "source_port",
        "destination_ip",
        "destination_port",
        "protocol",
        "flow_start_timestamp",
        "flow_end_timestamp",
    ]
    return pd.util.hash_pandas_object(
        frame[identity_columns].astype(str), index=False
    ).astype(str)


def load_live_dataset(
    dataset_dir: Path,
    approach: str = "binary",
) -> tuple[pd.DataFrame, pd.Series, pd.DataFrame, DatasetLoadReport]:
    """Load validated session CSVs and preserve provenance metadata."""
    if approach not in {"binary", "multiclass"}:
        raise ValueError("approach must be 'binary' or 'multiclass'")
    csv_files = sorted(Path(dataset_dir).rglob("session_*.csv"))
    if not csv_files:
        raise LiveDatasetError(f"no session CSV files found under {dataset_dir}")

    report = DatasetLoadReport()
    frames: list[pd.DataFrame] = []
    for csv_path in csv_files:
        sidecar = _read_sidecar(csv_path)
        frame = pd.read_csv(csv_path, dtype=str, keep_default_na=False)
        report.files_read += 1
        report.rows_read += len(frame)
        report.provenance.append(csv_path.name)
        missing_columns = [column for column in DATASET_COLUMNS if column not in frame.columns]
        if missing_columns:
            raise LiveDatasetError(
                f"{csv_path.name} is missing required columns: {missing_columns}"
            )
        frame = frame.copy()
        frame["_session_id"] = sidecar["session_id"]
        frame["_experiment_id"] = frame["experiment_id"]
        frame["_source_file"] = csv_path.name
        frames.append(frame)

    data = pd.concat(frames, ignore_index=True)
    for column in LIVE_FLOW_FEATURE_COLUMNS:
        data[column] = pd.to_numeric(data[column], errors="coerce")
    required_numeric = list(LIVE_FLOW_FEATURE_COLUMNS) + [
        "flow_start_timestamp",
        "flow_end_timestamp",
        "label_confidence",
    ]
    for column in required_numeric:
        data[column] = pd.to_numeric(data[column], errors="coerce")
    invalid_mask = data[required_numeric].isna().any(axis=1)
    invalid_mask |= ~np.isfinite(data[required_numeric]).all(axis=1)
    invalid_mask |= data["flow_end_timestamp"] < data["flow_start_timestamp"]
    invalid_mask |= ~data["ground_truth_label"].isin(
        {"normal", "port_scan", "brute_force", "dos", "unknown"}
    )
    if invalid_mask.any():
        report.excluded_invalid = int(invalid_mask.sum())
        report.exclusion_reasons["invalid_schema_or_value"] += report.excluded_invalid
    data = data.loc[~invalid_mask].copy()

    unknown_mask = data["ground_truth_label"].eq("unknown")
    report.excluded_unknown = int(unknown_mask.sum())
    if report.excluded_unknown:
        report.exclusion_reasons["unknown_label"] += report.excluded_unknown
    data = data.loc[~unknown_mask].copy()

    duplicate_mask = _flow_fingerprint(data).duplicated(keep="first")
    report.excluded_duplicate = int(duplicate_mask.sum())
    if report.excluded_duplicate:
        report.exclusion_reasons["duplicate_flow"] += report.excluded_duplicate
    data = data.loc[~duplicate_mask].copy()

    if approach == "binary":
        data["target"] = data["ground_truth_label"].map(
            lambda label: "normal" if label == "normal" else "suspicious"
        )
    else:
        data["target"] = data["ground_truth_label"]
    data = data[data["target"].isin(BINARY_LABELS if approach == "binary" else MULTICLASS_LABELS)].copy()
    if data.empty:
        raise LiveDatasetError("no usable labeled live-flow rows remain")

    report.rows_loaded = len(data)
    report.session_distribution.update(data["_session_id"].value_counts().to_dict())
    report.label_distribution.update(data["target"].value_counts().to_dict())
    session_support = data.groupby("target")["_session_id"].nunique()
    required_labels = set(BINARY_LABELS if approach == "binary" else MULTICLASS_LABELS)
    insufficient = {
        label: int(session_support.get(label, 0))
        for label in required_labels
        if int(session_support.get(label, 0)) < MIN_INDEPENDENT_SESSIONS_PER_CLASS
    }
    if insufficient:
        raise LiveDatasetError(
            "insufficient independent session support for supervised training: "
            f"{insufficient}"
        )
    metadata = data[["_session_id", "_experiment_id", "_source_file", "record_id"]].rename(
        columns={"_session_id": "session_id", "_experiment_id": "experiment_id", "_source_file": "source_file"}
    )
    x = data[list(LIVE_FLOW_FEATURE_COLUMNS)].astype("float32")
    y = data["target"].astype(str)
    return x.reset_index(drop=True), y.reset_index(drop=True), metadata.reset_index(drop=True), report


def _model_candidates(seed: int) -> dict[str, Pipeline]:
    def pipeline(estimator: Any) -> Pipeline:
        return Pipeline([("imputer", SimpleImputer(strategy="median")), ("classifier", estimator)])

    return {
        "random_forest": pipeline(
            RandomForestClassifier(n_estimators=160, class_weight="balanced", random_state=seed, n_jobs=-1)
        ),
        "extra_trees": pipeline(
            ExtraTreesClassifier(n_estimators=160, class_weight="balanced", random_state=seed, n_jobs=-1)
        ),
        "hist_gradient_boosting": pipeline(
            HistGradientBoostingClassifier(max_iter=160, random_state=seed)
        ),
    }


def session_aware_split(
    y: pd.Series, metadata: pd.DataFrame, seed: int
) -> dict[str, np.ndarray]:
    """Create train/calibration/threshold/final-test partitions by session."""
    groups = metadata["session_id"].to_numpy()
    unique_groups = np.unique(groups)
    if len(unique_groups) < 4:
        raise LiveDatasetError(
            f"at least 4 independent sessions are required; found {len(unique_groups)}"
        )
    all_classes = set(y.unique())
    splitter = GroupShuffleSplit(n_splits=200, test_size=0.25, random_state=seed)
    best: tuple[tuple[int, int, int], dict[str, np.ndarray]] | None = None
    for train_cal_idx, final_test_idx in splitter.split(metadata, y, groups):
        remaining_groups = groups[train_cal_idx]
        inner = GroupShuffleSplit(n_splits=20, test_size=0.333333, random_state=seed)
        for fit_cal_idx, threshold_idx_local in inner.split(train_cal_idx, y.iloc[train_cal_idx], remaining_groups):
            fit_cal_global = train_cal_idx[fit_cal_idx]
            threshold_idx = train_cal_idx[threshold_idx_local]
            inner_groups = groups[fit_cal_global]
            if len(np.unique(inner_groups)) < 2:
                continue
            calibration_splitter = GroupShuffleSplit(n_splits=1, test_size=0.5, random_state=seed)
            fit_local, calibration_local = next(
                calibration_splitter.split(fit_cal_global, y.iloc[fit_cal_global], inner_groups)
            )
            train_idx = fit_cal_global[fit_local]
            calibration_idx = fit_cal_global[calibration_local]
            partitions = {
                "train": train_idx,
                "calibration": calibration_idx,
                "threshold": threshold_idx,
                "final_test": final_test_idx,
            }
            if set(y.iloc[train_idx].unique()) != all_classes:
                continue
            threshold_classes = set(y.iloc[threshold_idx].unique())
            required_threshold_classes = (
                {"normal", "suspicious"}
                if "suspicious" in all_classes
                else all_classes
            )
            if not required_threshold_classes.issubset(threshold_classes):
                continue
            if set(y.iloc[calibration_idx].unique()) != all_classes:
                continue
            coverage = sum(len(np.unique(groups[indexes])) for indexes in partitions.values())
            score = (len(set(y.iloc[final_test_idx]) & all_classes), coverage, -len(final_test_idx))
            if best is None or score > best[0]:
                best = (score, partitions)
    if best is None:
        raise LiveDatasetError(
            "unable to create session-aware partitions with class coverage; "
            "collect more independent sessions"
        )
    return best[1]


def _calibrate(estimator: Any, x: pd.DataFrame, y: pd.Series) -> CalibratedClassifierCV:
    try:
        from sklearn.frozen import FrozenEstimator

        calibrator = CalibratedClassifierCV(
            estimator=FrozenEstimator(estimator), method="sigmoid", cv=2
        )
        calibrator.fit(x, y)
        return calibrator
    except ImportError:
        pass
    try:
        calibrator = CalibratedClassifierCV(estimator=estimator, method="sigmoid", cv="prefit")
    except TypeError:
        calibrator = CalibratedClassifierCV(base_estimator=estimator, method="sigmoid", cv="prefit")
    calibrator.fit(x, y)
    return calibrator


def _pr_auc(y: pd.Series, probabilities: np.ndarray, classes: list[str]) -> float:
    if len(classes) == 2:
        suspicious_index = classes.index("suspicious") if "suspicious" in classes else classes.index("dos")
        return float(average_precision_score((y != "normal").astype(int), probabilities[:, suspicious_index]))
    one_hot = np.column_stack([(y == label).astype(int) for label in classes])
    return float(average_precision_score(one_hot, probabilities, average="macro"))


def _evaluate_model(model: Any, x: pd.DataFrame, y: pd.Series) -> dict[str, Any]:
    probabilities = model.predict_proba(x)
    classes = [str(label) for label in model.classes_]
    predictions = np.asarray(classes)[probabilities.argmax(axis=1)]
    metrics = {
        "accuracy": float(accuracy_score(y, predictions)),
        "balanced_accuracy": float(balanced_accuracy_score(y, predictions)),
        "precision_macro": float(precision_score(y, predictions, average="macro", zero_division=0)),
        "recall_macro": float(recall_score(y, predictions, average="macro", zero_division=0)),
        "f1_macro": float(f1_score(y, predictions, average="macro", zero_division=0)),
        "pr_auc_macro": _pr_auc(y, probabilities, classes),
    }
    if "normal" in classes:
        normal_index = classes.index("normal")
        benign = y.to_numpy() == "normal"
        metrics["benign_fpr"] = float(((predictions != "normal") & benign).sum() / max(int(benign.sum()), 1))
        metrics["brier_score_normal"] = float(brier_score_loss(benign.astype(int), probabilities[:, normal_index]))
    metrics["confusion_matrix"] = confusion_matrix(y, predictions, labels=classes).tolist()
    return metrics


def select_thresholds(
    model: Any,
    x_threshold: pd.DataFrame,
    y_threshold: pd.Series,
) -> dict[str, dict[str, Any]]:
    classes = [str(label) for label in model.classes_]
    normal_index = classes.index("normal")
    scores = 1.0 - model.predict_proba(x_threshold)[:, normal_index]
    benign_scores = scores[y_threshold.to_numpy() == "normal"]
    suspicious_scores = scores[y_threshold.to_numpy() != "normal"]
    thresholds: dict[str, dict[str, Any]] = {}
    for target in TARGET_FPRS:
        name = f"{target:.3%}"
        minimum_benign = int(np.ceil(1.0 / target))
        supported = len(benign_scores) >= minimum_benign
        threshold = float(np.quantile(benign_scores, 1.0 - target, method="higher")) if len(benign_scores) else 1.0
        predicted = scores >= threshold
        actual = y_threshold.to_numpy() != "normal"
        fp = int((predicted & ~actual).sum())
        tp = int((predicted & actual).sum())
        tn = int((~predicted & ~actual).sum())
        fn = int((~predicted & actual).sum())
        thresholds[name] = {
            "target_fpr": target,
            "threshold": threshold,
            "supported": supported,
            "support_reason": "" if supported else f"requires at least {minimum_benign} benign threshold samples",
            "benign_validation_samples": int(len(benign_scores)),
            "suspicious_validation_samples": int(len(suspicious_scores)),
            "actual_fpr": fp / max(len(benign_scores), 1),
            "recall": tp / max(tp + fn, 1),
            "precision": tp / max(tp + fp, 1),
            "tp": tp,
            "fp": fp,
            "tn": tn,
            "fn": fn,
        }
    return thresholds


def train_and_save(
    dataset_dir: Path,
    output_path: Path,
    approach: str = "binary",
    seed: int = 7,
) -> dict[str, Any]:
    x, y, metadata, report = load_live_dataset(dataset_dir, approach)
    partitions = session_aware_split(y, metadata, seed)
    train_idx = partitions["train"]
    calibration_idx = partitions["calibration"]
    threshold_idx = partitions["threshold"]
    final_test_idx = partitions["final_test"]

    candidates = _model_candidates(seed)
    comparison: dict[str, Any] = {}
    calibrated_models: dict[str, Any] = {}
    for name, estimator in candidates.items():
        estimator.fit(x.iloc[train_idx], y.iloc[train_idx])
        calibrated = _calibrate(estimator, x.iloc[calibration_idx], y.iloc[calibration_idx])
        calibrated_models[name] = calibrated
        comparison[name] = _evaluate_model(calibrated, x.iloc[threshold_idx], y.iloc[threshold_idx])
    selected_name = max(
        comparison,
        key=lambda name: (comparison[name]["f1_macro"], comparison[name]["balanced_accuracy"], comparison[name]["pr_auc_macro"]),
    )
    selected_model = calibrated_models[selected_name]
    thresholds = select_thresholds(selected_model, x.iloc[threshold_idx], y.iloc[threshold_idx])
    final_metrics = _evaluate_model(selected_model, x.iloc[final_test_idx], y.iloc[final_test_idx])

    artifact = {
        "artifact_type": LIVE_ARTIFACT_TYPE,
        "artifact_schema_version": LIVE_ARTIFACT_SCHEMA_VERSION,
        "model_version": LIVE_MODEL_VERSION,
        "approach": approach,
        "model": selected_model,
        "estimator": getattr(
            getattr(selected_model, "estimator", None), "estimator", None
        )
        or getattr(selected_model, "estimator", None),
        "calibrator": selected_model,
        "model_family": selected_name,
        "feature_columns": list(LIVE_FLOW_FEATURE_COLUMNS),
        "feature_schema_version": 1,
        "classes": [str(label) for label in selected_model.classes_],
        "selected_thresholds": thresholds,
        "training_provenance": report.as_dict(),
        "session_splits": {
            name: {
                "rows": len(indexes),
                "sessions": sorted(metadata.iloc[indexes]["session_id"].unique()),
            }
            for name, indexes in partitions.items()
        },
        "model_comparison": comparison,
        "final_test_metrics": final_metrics,
        "calibration": {
            "method": "sigmoid",
            "calibration_rows": len(calibration_idx),
            "limitations": "isotonic calibration is not used; calibration quality depends on independent labeled sessions",
        },
        "sklearn_version": sklearn.__version__,
        "trained_at_utc": datetime.now(timezone.utc).isoformat(),
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(artifact, output_path)
    loaded = joblib.load(output_path)
    if loaded.get("artifact_type") != LIVE_ARTIFACT_TYPE:
        raise LiveDatasetError("saved artifact validation failed: wrong artifact type")
    if loaded.get("feature_columns") != list(LIVE_FLOW_FEATURE_COLUMNS):
        raise LiveDatasetError("saved artifact validation failed: feature schema mismatch")
    loaded["model"].predict_proba(x.iloc[final_test_idx[:1]])
    print(json.dumps({
        "model_family": selected_name,
        "approach": approach,
        "rows": len(x),
        "final_test_metrics": final_metrics,
        "thresholds": thresholds,
        "artifact": str(output_path),
    }, indent=2, default=str))
    return artifact


def main() -> None:
    parser = argparse.ArgumentParser(description="Train a model on the 15-feature live-flow dataset")
    parser.add_argument("--dataset-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--approach", choices=("binary", "multiclass"), default="binary")
    parser.add_argument("--seed", type=int, default=7)
    args = parser.parse_args()
    train_and_save(args.dataset_dir, args.output, args.approach, args.seed)


if __name__ == "__main__":
    main()
