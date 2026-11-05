from __future__ import annotations

import argparse
from pathlib import Path

import joblib
import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

from rt_nid_ml.detector import FEATURE_COLUMNS


def build_synthetic_training_data(seed: int = 7, samples_per_class: int = 500) -> tuple[np.ndarray, np.ndarray]:
    rng = np.random.default_rng(seed)

    benign = np.column_stack(
        [
            rng.normal(20, 5, samples_per_class).clip(3, 120),
            rng.normal(0.25, 0.1, samples_per_class).clip(0, 1),
            rng.normal(0.05, 0.05, samples_per_class).clip(0, 1),
            rng.normal(180, 80, samples_per_class).clip(20, 1500),
            rng.normal(1.1, 0.2, samples_per_class).clip(1, 10),
            rng.normal(4, 1.5, samples_per_class).clip(0.5, 50),
        ]
    )
    malicious = np.column_stack(
        [
            rng.normal(80, 18, samples_per_class).clip(8, 250),
            rng.normal(0.85, 0.1, samples_per_class).clip(0, 1),
            rng.normal(0.45, 0.2, samples_per_class).clip(0, 1),
            rng.normal(30, 20, samples_per_class).clip(0, 300),
            rng.normal(1.0, 0.1, samples_per_class).clip(1, 10),
            rng.normal(18, 5, samples_per_class).clip(1, 200),
        ]
    )

    x = np.vstack([benign, malicious])
    y = np.concatenate([np.zeros(samples_per_class), np.ones(samples_per_class)])
    return x.astype(float), y.astype(int)


def train_and_save(output_path: Path) -> None:
    x, y = build_synthetic_training_data()
    model = make_pipeline(StandardScaler(), LogisticRegression(max_iter=500, random_state=7))
    model.fit(x, y)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, output_path)
    print(f"Saved model to {output_path}")
    print(f"Feature order: {', '.join(FEATURE_COLUMNS)}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Train starter SSH intrusion model")
    parser.add_argument("--output", required=True, help="Output .joblib model path")
    args = parser.parse_args()
    train_and_save(Path(args.output))


if __name__ == "__main__":
    main()
