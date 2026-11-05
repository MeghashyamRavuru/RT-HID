from __future__ import annotations

import argparse
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
from sklearn.metrics import accuracy_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import make_pipeline

from rt_nid_ml.detector import FEATURE_COLUMNS


def build_synthetic_training_data(seed: int = 7, samples_per_class: int = 500) -> tuple[np.ndarray, np.ndarray]:
    rng = np.random.default_rng(seed)

    def make_class(means: list[float], scales: list[float]) -> np.ndarray:
        return np.column_stack(
            [rng.normal(mean, scale, samples_per_class) for mean, scale in zip(means, scales)]
        )

    scan = make_class([100, 0.9, 0.5, 25, 30, 25, 65, 0.03, 0.15, 0.2], [15, 0.08, 0.12, 10, 5, 5, 12, 0.02, 0.05, 0.08])
    brute_force = make_class([80, 0.85, 0.45, 30, 1, 18, 70, 0.2, 0.35, 0.55], [18, 0.1, 0.2, 20, 0.1, 5, 15, 0.1, 0.08, 0.1])
    dos = make_class([220, 0.45, 0.7, 5, 2, 80, 75, 0.01, 0.05, 0.7], [25, 0.12, 0.12, 5, 1, 15, 15, 0.01, 0.03, 0.1])
    c2 = make_class([35, 0.35, 0.1, 90, 1, 3, 95, 1.5, 0.05, 0.8], [8, 0.1, 0.05, 25, 0.2, 1, 20, 0.4, 0.03, 0.1])

    normal = np.column_stack([
        rng.normal(20, 5, samples_per_class).clip(3, 120),
        rng.normal(0.25, 0.1, samples_per_class).clip(0, 1),
        rng.normal(0.05, 0.05, samples_per_class).clip(0, 1),
        rng.normal(180, 80, samples_per_class).clip(20, 1500),
        rng.normal(1.1, 0.2, samples_per_class).clip(1, 10),
        rng.normal(4, 1.5, samples_per_class).clip(0.5, 50),
        rng.normal(220, 80, samples_per_class).clip(20, 1600),
        rng.normal(0.8, 0.4, samples_per_class).clip(0.01, 5),
        rng.normal(0.02, 0.03, samples_per_class).clip(0, 1),
        rng.normal(0.6, 0.2, samples_per_class).clip(0, 1),
    ])
    x = np.vstack([normal, scan, brute_force, dos, c2]).astype(float)
    y = np.concatenate([
        np.full(samples_per_class, "normal"),
        np.full(samples_per_class, "scan"),
        np.full(samples_per_class, "brute_force"),
        np.full(samples_per_class, "dos"),
        np.full(samples_per_class, "c2"),
    ])
    return x, y


def train_and_save(output_path: Path) -> None:
    x, y = build_synthetic_training_data()
    x_train, x_test, y_train, y_test = train_test_split(x, y, test_size=0.2, random_state=7, stratify=y)
    candidates = {
        "random_forest": RandomForestClassifier(n_estimators=180, random_state=7, n_jobs=-1),
        "gradient_boosting": make_pipeline(StandardScaler(), GradientBoostingClassifier(random_state=7)),
    }
    scores = {}
    for name, candidate in candidates.items():
        candidate.fit(x_train, y_train)
        scores[name] = accuracy_score(y_test, candidate.predict(x_test))
    model_name = max(scores, key=scores.get)
    model = candidates[model_name]

    output_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, output_path)
    print(f"Saved {model_name} model to {output_path} (validation accuracy: {scores[model_name]:.3f})")
    print(f"Feature order: {', '.join(FEATURE_COLUMNS)}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Train starter SSH intrusion model")
    parser.add_argument("--output", required=True, help="Output .joblib model path")
    args = parser.parse_args()
    train_and_save(Path(args.output))


if __name__ == "__main__":
    main()
