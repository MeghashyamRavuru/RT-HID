from __future__ import annotations

import argparse
import re
import warnings
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.calibration import CalibratedClassifierCV
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    brier_score_loss,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import GroupShuffleSplit, train_test_split
from sklearn.pipeline import Pipeline

# CICFlowMeter columns selected for the first real-data baseline.
# This is NOT the current live detector's 10-column packet-window schema.
FEATURE_COLUMNS = [
    "Destination Port",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Fwd Packet Length Mean",
    "Bwd Packet Length Mean",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow IAT Mean",
    "Fwd IAT Mean",
    "Bwd IAT Mean",
    "SYN Flag Count",
    "RSTFlag Count",
    "FIN Flag Count",
    "ACK Flag Count",
    "Packet Length Mean",
    "Packet Length Std",
    "Average Packet Size",
    "Down/Up Ratio",
]
LABEL_COLUMN = "Label"
MIN_RELIABLE_SUPPORT = 50
KNOWN_STATISTICALLY_INSUFFICIENT = {"heartbleed", "infiltration"}
TARGET_FALSE_POSITIVE_RATES = (0.01, 0.005, 0.001)
MODEL_VERSION = "phase1-cicids-calibrated-v1"


def normalize_column_name(value: Any) -> str:
    """Normalize harmless CICFlowMeter header spelling differences."""
    return re.sub(r"[^a-z0-9]+", "", str(value).strip().lower())


def normalize_label(value: Any) -> str | None:
    """Map CICIDS2017 raw labels into stable project-level classes."""
    label = re.sub(r"\s+", " ", str(value)).strip().lower()
    if not label or label in {"nan", "none"}:
        return None
    if label == "benign":
        return "normal"
    if "portscan" in label:
        return "port_scan"
    if label == "ddos" or label.startswith("dos "):
        return "dos"
    if label in {"ftp-patator", "ssh-patator"}:
        return "brute_force"
    if label.startswith("web attack"):
        return "web_attack"
    if label == "bot":
        return "bot"
    if label == "infiltration":
        return "infiltration"
    if label == "heartbleed":
        return "heartbleed"
    return None


def _load_dataset_with_metadata(
    dataset_dir: Path, max_per_class: int, seed: int
) -> tuple[pd.DataFrame, pd.Series, pd.DataFrame, Counter]:
    csv_files = sorted(dataset_dir.rglob("*.csv"))
    if not csv_files:
        raise FileNotFoundError(f"No CSV files found under: {dataset_dir}")

    required = set(FEATURE_COLUMNS + [LABEL_COLUMN])
    required_keys = {normalize_column_name(name) for name in required}
    sampled_frames: list[pd.DataFrame] = []
    raw_label_counts: Counter = Counter()
    unknown_labels: Counter = Counter()

    for csv_path in csv_files:
        print(f"Reading: {csv_path}")
        frame = pd.read_csv(
            csv_path,
            usecols=lambda name: normalize_column_name(name) in required_keys,
            encoding="utf-8",
            encoding_errors="replace",
            low_memory=False,
        )
        frame.columns = [name.strip() for name in frame.columns]

        columns_by_key = {
            normalize_column_name(name): name for name in frame.columns
        }
        missing = required_keys.difference(columns_by_key)
        if missing:
            raise ValueError(
                f"{csv_path.name} is missing required columns: "
                f"{sorted(missing)}"
            )
        frame = frame.rename(
            columns={
                columns_by_key[normalize_column_name(name)]: name
                for name in required
            }
        )

        raw_labels = frame[LABEL_COLUMN].astype(str).str.strip()
        mapped_labels = raw_labels.map(normalize_label)
        raw_label_counts.update(raw_labels.value_counts().to_dict())

        unknown_mask = mapped_labels.isna()
        if unknown_mask.any():
            unknown_labels.update(raw_labels[unknown_mask].value_counts().to_dict())

        frame = frame.loc[~unknown_mask, FEATURE_COLUMNS].copy()
        frame["target"] = mapped_labels.loc[~unknown_mask].values
        frame["source_file"] = csv_path.name

        for column in FEATURE_COLUMNS:
            frame[column] = pd.to_numeric(frame[column], errors="coerce")
        frame[FEATURE_COLUMNS] = frame[FEATURE_COLUMNS].replace(
            [np.inf, -np.inf], np.nan
        )

        # Drop only rows with no usable feature values. Other missing values
        # are imputed inside the model pipeline using training data only.
        frame = frame.dropna(subset=FEATURE_COLUMNS, how="all")
        if frame.empty:
            continue

        frame["flow_fingerprint"] = pd.util.hash_pandas_object(
            frame[FEATURE_COLUMNS].round(6), index=False
        ).astype(str)

        # Bound memory use while processing each CSV.
        for _, class_frame in frame.groupby("target", sort=False):
            sampled_frames.append(
                class_frame.sample(
                    n=min(len(class_frame), max_per_class),
                    random_state=seed,
                )
            )
        del frame

    if not sampled_frames:
        raise ValueError("No usable labeled rows were found in the CSV files.")

    sampled = pd.concat(sampled_frames, ignore_index=True)
    balanced_parts = []
    for _, class_frame in sampled.groupby("target", sort=True):
        balanced_parts.append(
            class_frame.sample(
                n=min(len(class_frame), max_per_class),
                random_state=seed,
            )
        )

    data = pd.concat(balanced_parts, ignore_index=True)
    data = data.sample(frac=1.0, random_state=seed).reset_index(drop=True)

    if unknown_labels:
        print("\nUnmapped labels skipped:")
        for label, count in unknown_labels.most_common():
            print(f"  {label}: {count:,}")

    x = data[FEATURE_COLUMNS].astype("float32")
    y = data["target"].astype(str)
    metadata = data[["source_file", "flow_fingerprint"]].reset_index(drop=True)
    return x, y, metadata, raw_label_counts


def load_dataset(
    dataset_dir: Path, max_per_class: int, seed: int
) -> tuple[pd.DataFrame, pd.Series, Counter]:
    """Load flows while preserving the original three-value public API."""
    x, y, _, raw_label_counts = _load_dataset_with_metadata(
        dataset_dir, max_per_class, seed
    )
    return x, y, raw_label_counts


def build_model(seed: int) -> Pipeline:
    return Pipeline(
        steps=[
            ("imputer", SimpleImputer(strategy="median")),
            (
                "classifier",
                RandomForestClassifier(
                    n_estimators=150,
                    class_weight="balanced_subsample",
                    min_samples_leaf=2,
                    random_state=seed,
                    n_jobs=-1,
                ),
            ),
        ]
    )


def build_calibrated_model(seed: int) -> CalibratedClassifierCV:
    base_model = build_model(seed)
    try:
        return CalibratedClassifierCV(
            estimator=base_model, method="sigmoid", cv=3
        )
    except TypeError:
        # scikit-learn < 1.2 called this parameter base_estimator.
        return CalibratedClassifierCV(
            base_estimator=base_model, method="sigmoid", cv=3
        )


def attack_scores(model: Any, x: pd.DataFrame) -> np.ndarray:
    probabilities = model.predict_proba(x)
    classes = [str(label) for label in model.classes_]
    if "normal" not in classes:
        raise ValueError("Calibrated model must contain the 'normal' class")
    normal_index = classes.index("normal")
    return 1.0 - probabilities[:, normal_index]


def select_thresholds(
    model: Any, x_calibration: pd.DataFrame, y_calibration: pd.Series
) -> dict[str, dict[str, float]]:
    """Select score cutoffs using benign calibration flows only."""
    benign_scores = attack_scores(
        model, x_calibration[y_calibration.to_numpy() == "normal"]
    )
    if len(benign_scores) < 2:
        raise ValueError("At least two benign calibration flows are required")

    thresholds: dict[str, dict[str, float]] = {}
    for target in TARGET_FALSE_POSITIVE_RATES:
        threshold = float(
            np.quantile(benign_scores, 1.0 - target, method="higher")
        )
        calibration_false_positives = int((benign_scores >= threshold).sum())
        calibration_fpr = calibration_false_positives / len(benign_scores)
        thresholds[f"{target:.3%}"] = {
            "target_fpr": target,
            "threshold": threshold,
            "calibration_benign_count": int(len(benign_scores)),
            "calibration_false_positive_count": calibration_false_positives,
            "calibration_fpr": calibration_fpr,
            "target_supported": calibration_fpr <= target,
        }
    return thresholds


def evaluate_operating_points(
    model: Any,
    thresholds: dict[str, dict[str, float]],
    x_test: pd.DataFrame,
    y_test: pd.Series,
) -> dict[str, dict[str, float]]:
    scores = attack_scores(model, x_test)
    actual_attack = (y_test.to_numpy() != "normal").astype(int)
    results: dict[str, dict[str, float]] = {}
    for name, configuration in thresholds.items():
        predicted_attack = (scores >= configuration["threshold"]).astype(int)
        true_positive = int(((actual_attack == 1) & (predicted_attack == 1)).sum())
        false_positive = int(((actual_attack == 0) & (predicted_attack == 1)).sum())
        false_negative = int(((actual_attack == 1) & (predicted_attack == 0)).sum())
        true_negative = int(((actual_attack == 0) & (predicted_attack == 0)).sum())
        benign_count = int((actual_attack == 0).sum())
        attack_count = int((actual_attack == 1).sum())
        results[name] = {
            "target_fpr": configuration["target_fpr"],
            "threshold": configuration["threshold"],
            "calibration_fpr": configuration.get("calibration_fpr", 0.0),
            "target_supported": configuration.get("target_supported", True),
            "benign_count": benign_count,
            "attack_count": attack_count,
            "false_positive_count": false_positive,
            "true_positive_count": true_positive,
            "false_negative_count": false_negative,
            "true_negative_count": true_negative,
            "fpr": false_positive / benign_count if benign_count else 0.0,
            "recall": true_positive / attack_count if attack_count else 0.0,
            "precision": precision_score(
                actual_attack, predicted_attack, zero_division=0
            ),
            "brier_score": brier_score_loss(actual_attack, scores),
        }
    return results


def split_calibration_indices(
    train_idx: np.ndarray,
    y: pd.Series,
    metadata: pd.DataFrame,
    seed: int,
) -> tuple[np.ndarray, np.ndarray]:
    fit_idx, calibration_idx = train_test_split(
        train_idx,
        test_size=0.2,
        random_state=seed,
        stratify=y.iloc[train_idx],
    )
    fit_fingerprints = set(metadata.iloc[fit_idx]["flow_fingerprint"])
    calibration_fingerprints = metadata.iloc[calibration_idx]["flow_fingerprint"]
    calibration_idx = calibration_idx[
        ~calibration_fingerprints.isin(fit_fingerprints).to_numpy()
    ]
    if len(calibration_idx) == 0:
        raise ValueError("No independent calibration flows remain after deduplication")
    return fit_idx, calibration_idx


def choose_capture_split(
    y: pd.Series, metadata: pd.DataFrame, seed: int
) -> tuple[np.ndarray, np.ndarray] | None:
    """Choose an unseen-file split that keeps every class in training."""
    groups = metadata["source_file"].to_numpy()
    all_classes = set(y.unique())
    splitter = GroupShuffleSplit(n_splits=50, test_size=0.2, random_state=seed)
    best: tuple[tuple[int, int, int], np.ndarray, np.ndarray] | None = None

    for train_idx, test_idx in splitter.split(metadata, y, groups):
        train_classes = set(y.iloc[train_idx].unique())
        if train_classes != all_classes or len(test_idx) == 0:
            continue

        test_labels = y.iloc[test_idx]
        test_files = metadata.iloc[test_idx]["source_file"]
        reliable_count = 0
        test_class_count = 0
        for label in all_classes:
            support = int((test_labels == label).sum())
            file_count = int(test_files[test_labels == label].nunique())
            if support:
                test_class_count += 1
            if (
                support >= MIN_RELIABLE_SUPPORT
                and file_count >= 2
                and label not in KNOWN_STATISTICALLY_INSUFFICIENT
            ):
                reliable_count += 1

        score = (reliable_count, test_class_count, len(test_idx))
        if best is None or score > best[0]:
            best = (score, train_idx, test_idx)

    if best is None:
        return None
    return best[1], best[2]


def evaluate_split(
    name: str,
    x: pd.DataFrame,
    y: pd.Series,
    metadata: pd.DataFrame,
    train_idx: np.ndarray,
    test_idx: np.ndarray,
    seed: int,
    require_multiple_files: bool,
) -> dict[str, Any]:
    train_fingerprints = set(metadata.iloc[train_idx]["flow_fingerprint"])
    test_fingerprints = metadata.iloc[test_idx]["flow_fingerprint"]
    duplicate_mask = test_fingerprints.isin(train_fingerprints).to_numpy()
    duplicate_count = int(duplicate_mask.sum())
    clean_test_idx = test_idx[~duplicate_mask]

    print(f"\n{'=' * 70}\n{name}")
    print(f"Train rows: {len(train_idx):,}; candidate test rows: {len(test_idx):,}")
    print(f"Duplicate flows crossing partitions: {duplicate_count:,}")
    if duplicate_count:
        print("Duplicate test flows are excluded from evaluation metrics.")

    if len(clean_test_idx) == 0:
        print("No independent test flows remain; evaluation skipped.")
        return {"status": "unavailable", "duplicate_flows": duplicate_count}

    model = build_model(seed)
    model.fit(x.iloc[train_idx], y.iloc[train_idx])
    predictions = model.predict(x.iloc[clean_test_idx])
    test_labels = y.iloc[clean_test_idx]
    labels = sorted(y.iloc[train_idx].unique())
    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", category=UserWarning)
        report = classification_report(
            test_labels,
            predictions,
            labels=labels,
            output_dict=True,
            zero_division=0,
        )
    test_metadata = metadata.iloc[clean_test_idx].reset_index(drop=True)
    test_targets = test_labels.reset_index(drop=True)
    metrics = {
        "accuracy": float(accuracy_score(test_labels, predictions)),
        "balanced_accuracy": float(
            balanced_accuracy_score(test_labels, predictions)
        ),
        "macro_f1": float(
            f1_score(test_labels, predictions, average="macro", zero_division=0)
        ),
        "weighted_f1": float(
            f1_score(test_labels, predictions, average="weighted", zero_division=0)
        ),
    }

    reliable_classes: list[str] = []
    print("\nPer-class evaluation status:")
    for label in labels:
        support = int(report.get(label, {}).get("support", 0))
        label_file_count = int(
            test_metadata.loc[test_targets == label, "source_file"].nunique()
        )
        reasons: list[str] = []
        if support < MIN_RELIABLE_SUPPORT:
            reasons.append(f"support < {MIN_RELIABLE_SUPPORT}")
        if require_multiple_files and label_file_count < 2:
            reasons.append("fewer than 2 independent capture files")
        if label in KNOWN_STATISTICALLY_INSUFFICIENT:
            reasons.append("known dataset limitation")
        if reasons:
            status = "INSUFFICIENT: " + "; ".join(reasons)
        else:
            reliable_classes.append(label)
            status = "reliable enough for this split"
        print(
            f"  {label}: support={support:,}, capture_files={label_file_count}, "
            f"f1={report.get(label, {}).get('f1-score', 0.0):.4f} [{status}]"
        )

    reliable_metrics: dict[str, float] = {}
    if reliable_classes:
        reliable_metrics["reliable_macro_f1"] = float(
            f1_score(
                test_labels,
                predictions,
                labels=reliable_classes,
                average="macro",
                zero_division=0,
            )
        )
    print("\nOverall metrics (all test classes):")
    for metric, value in metrics.items():
        print(f"  {metric}: {value:.4f}")
    if reliable_metrics:
        print("Metrics for classes meeting the independent-sample rule:")
        for metric, value in reliable_metrics.items():
            print(f"  {metric}: {value:.4f}")
    else:
        print("No classes met the independent-sample rule.")

    return {
        "status": "evaluated",
        **metrics,
        **reliable_metrics,
        "duplicate_flows": duplicate_count,
        "evaluation_rows": len(clean_test_idx),
        "reliable_classes": reliable_classes,
        "class_report": {
            label: report.get(label, {}) for label in labels
        },
    }


def train_and_save(
    dataset_dir: Path,
    output_path: Path | None = None,
    max_per_class: int = 15000,
    seed: int = 7,
) -> None:
    # Keep the original one-argument demo API working for existing callers.
    if output_path is None:
        legacy_output = dataset_dir
        rng = np.random.default_rng(seed)
        benign = np.column_stack(
            [
                rng.normal(20, 5, 500).clip(3, 120),
                rng.normal(0.25, 0.1, 500).clip(0, 1),
                rng.normal(0.05, 0.05, 500).clip(0, 1),
                rng.normal(180, 80, 500).clip(20, 1500),
                rng.normal(1.1, 0.2, 500).clip(1, 10),
                rng.normal(4, 1.5, 500).clip(0.5, 50),
            ]
        )
        malicious = np.column_stack(
            [
                rng.normal(80, 18, 500).clip(8, 250),
                rng.normal(0.85, 0.1, 500).clip(0, 1),
                rng.normal(0.45, 0.2, 500).clip(0, 1),
                rng.normal(30, 20, 500).clip(0, 300),
                rng.normal(1.0, 0.1, 500).clip(1, 10),
                rng.normal(18, 5, 500).clip(1, 200),
            ]
        )
        legacy_model = LogisticRegression(max_iter=500, random_state=seed)
        legacy_model.fit(
            np.vstack([benign, malicious]),
            np.concatenate([np.zeros(500), np.ones(500)]),
        )
        legacy_output.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(legacy_model, legacy_output)
        return
    x, y, metadata, raw_label_counts = _load_dataset_with_metadata(
        dataset_dir, max_per_class, seed
    )
    class_counts = y.value_counts().sort_index()
    too_small = class_counts[class_counts < 2]
    if not too_small.empty:
        raise ValueError(
            "Each class needs at least 2 usable rows for a stratified split. "
            f"Underrepresented classes: {too_small.to_dict()}"
        )

    rare_classes = class_counts[class_counts < MIN_RELIABLE_SUPPORT]
    if not rare_classes.empty:
        print("\nWARNING: These classes have fewer than 50 sampled rows.")
        print("Their test metrics will be statistically unreliable:")
        for label, count in rare_classes.items():
            print(f"  {label}: {count}")

    row_train_idx, row_test_idx = train_test_split(
        np.arange(len(y)), test_size=0.2, random_state=seed, stratify=y
    )
    row_metrics = evaluate_split(
        "Random row split (duplicate-aware)",
        x,
        y,
        metadata,
        row_train_idx,
        row_test_idx,
        seed,
        require_multiple_files=False,
    )

    capture_split = choose_capture_split(y, metadata, seed)
    if capture_split is None:
        print("\nCapture-file split: unavailable")
        print("No unseen-file split could retain every class in training.")
        capture_metrics: dict[str, Any] = {
            "status": "unavailable",
            "reason": "insufficient capture-file coverage",
        }
    else:
        capture_train_idx, capture_test_idx = capture_split
        capture_metrics = evaluate_split(
            "Capture-file split (unseen files, duplicate-aware)",
            x,
            y,
            metadata,
            capture_train_idx,
            capture_test_idx,
            seed,
            require_multiple_files=True,
        )

    final_train_idx, final_test_idx = (
        capture_split
        if capture_split is not None
        else (row_train_idx, row_test_idx)
    )
    fit_idx, calibration_idx = split_calibration_indices(
        final_train_idx, y, metadata, seed
    )
    calibrated_model = build_calibrated_model(seed)
    calibrated_model.fit(x.iloc[fit_idx], y.iloc[fit_idx])
    thresholds = select_thresholds(
        calibrated_model, x.iloc[calibration_idx], y.iloc[calibration_idx]
    )
    operating_points = evaluate_operating_points(
        calibrated_model,
        thresholds,
        x.iloc[final_test_idx],
        y.iloc[final_test_idx],
    )
    print("\nCalibrated operating points on the held-out final test:")
    for name, result in operating_points.items():
        print(
            f"  target={name}, threshold={result['threshold']:.4f}, "
            f"actual_fpr={result['fpr']:.4f}, recall={result['recall']:.4f}, "
            f"precision={result['precision']:.4f}, "
            f"FP={int(result['false_positive_count'])}, "
            f"TP={int(result['true_positive_count'])}, "
            f"FN={int(result['false_negative_count'])}, "
            f"TN={int(result['true_negative_count'])}"
        )

    print("\nClass counts after per-class sampling:")
    for label, count in class_counts.items():
        print(f"  {label}: {count:,}")

    print("\nFinal calibrated model fit: training partition only")
    labels = sorted(y.unique())
    output_path.parent.mkdir(parents=True, exist_ok=True)
    artifact = {
        "model": calibrated_model,
        "feature_columns": FEATURE_COLUMNS,
        "classes": labels,
        "metrics": {
            "random_row_split": row_metrics,
            "capture_file_split": capture_metrics,
            "calibrated_operating_points": operating_points,
        },
        "probability_calibration": {
            "method": "sigmoid",
            "cv": 3,
            "fit_rows": len(fit_idx),
            "calibration_rows": len(calibration_idx),
            "final_test_rows": len(final_test_idx),
        },
        "evaluation_protocol": {
            "duplicate_policy": "exclude test flows whose feature fingerprint occurs in training",
            "reliable_support_threshold": MIN_RELIABLE_SUPPORT,
            "known_statistically_insufficient": sorted(
                KNOWN_STATISTICALLY_INSUFFICIENT
            ),
            "final_test_split": (
                "capture_file" if capture_split is not None else "random_row"
            ),
        },
        "selected_thresholds": thresholds,
        "training_class_counts": class_counts.to_dict(),
        "raw_label_counts": dict(raw_label_counts),
        "dataset": "CICIDS2017",
        "model_type": "RandomForestClassifier",
        "max_per_class": max_per_class,
        "seed": seed,
        "model_version": MODEL_VERSION,
        "sklearn_version": sklearn.__version__,
        "trained_at_utc": datetime.now(timezone.utc).isoformat(),
        "feature_schema_version": 1,
        "schema_version": 3,
    }
    joblib.dump(artifact, output_path)
    reloaded = joblib.load(output_path)
    if not isinstance(reloaded, dict) or "model" not in reloaded:
        raise ValueError("Saved model artifact failed validation: missing model")
    reloaded_model = reloaded["model"]
    if list(reloaded["feature_columns"]) != FEATURE_COLUMNS:
        raise ValueError("Saved model artifact failed validation: feature schema mismatch")
    if not hasattr(reloaded_model, "predict_proba"):
        raise ValueError("Saved model artifact failed validation: no predict_proba")
    reloaded_model.predict_proba(x.iloc[:1])
    print("Validated saved artifact by reloading it and running inference.")
    print(f"\nSaved CICIDS2017 flow model artifact to: {output_path}")
    print("IMPORTANT: This artifact uses CICFlowMeter flow-level features.")
    print("It is not compatible with the current live detector's packet-window")
    print("features until the detector is updated in a separate integration step.")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Train and evaluate an RT-NID-ML model using CICIDS2017 CSV flows."
    )
    parser.add_argument(
        "--dataset-dir", default="datasets", help="Directory containing CICIDS2017 CSV files"
    )
    parser.add_argument(
        "--output", default="models/cicids_flow_model.joblib", help="Output path for the CICIDS2017 model artifact"
    )
    parser.add_argument(
        "--max-per-class", type=int, default=15000, help="Maximum sampled rows retained per mapped class"
    )
    parser.add_argument("--seed", type=int, default=7, help="Random seed")
    args = parser.parse_args()
    if args.max_per_class < 2:
        parser.error("--max-per-class must be at least 2")
    train_and_save(Path(args.dataset_dir), Path(args.output), args.max_per_class, args.seed)


if __name__ == "__main__":
    main()
