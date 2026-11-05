import unittest

import numpy as np
import pandas as pd

from rt_nid_ml.train import evaluate_operating_points, select_thresholds


class FakeCalibratedModel:
    classes_ = np.array(["normal", "dos"])

    def predict_proba(self, features: pd.DataFrame) -> np.ndarray:
        attack_score = features["attack_score"].to_numpy(dtype=float)
        return np.column_stack([1.0 - attack_score, attack_score])


class CalibrationEvaluationTests(unittest.TestCase):
    def test_thresholds_use_benign_calibration_scores(self) -> None:
        model = FakeCalibratedModel()
        calibration = pd.DataFrame({"attack_score": [0.01, 0.10, 0.20, 0.40]})
        labels = pd.Series(["normal", "normal", "normal", "dos"])

        thresholds = select_thresholds(model, calibration, labels)

        self.assertEqual(set(thresholds), {"1.000%", "0.500%", "0.100%"})
        self.assertAlmostEqual(thresholds["1.000%"]["threshold"], 0.20)

    def test_operating_points_report_benign_confusion_counts(self) -> None:
        model = FakeCalibratedModel()
        thresholds = {"test": {"target_fpr": 0.01, "threshold": 0.5}}
        features = pd.DataFrame({"attack_score": [0.1, 0.8, 0.9, 0.2]})
        labels = pd.Series(["normal", "dos", "normal", "normal"])

        result = evaluate_operating_points(model, thresholds, features, labels)["test"]

        self.assertEqual(result["benign_count"], 3)
        self.assertEqual(result["attack_count"], 1)
        self.assertEqual(result["false_positive_count"], 1)
        self.assertEqual(result["true_positive_count"], 1)
        self.assertEqual(result["false_negative_count"], 0)
        self.assertEqual(result["true_negative_count"], 2)


if __name__ == "__main__":
    unittest.main()
