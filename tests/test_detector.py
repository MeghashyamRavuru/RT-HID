import tempfile
import unittest
from pathlib import Path

from rt_nid_ml.detector import IntrusionModel, PacketFeatureExtractor
from rt_nid_ml.train import train_and_save


class PacketFeatureExtractorTests(unittest.TestCase):
    def test_feature_extraction_for_source_window(self) -> None:
        extractor = PacketFeatureExtractor(window_seconds=10, emit_every_seconds=2)
        src_ip = "10.0.0.4"
        extractor.ingest_event(src_ip, 22, 0x02, 0, timestamp=1.0)
        extractor.ingest_event(src_ip, 22, 0x06, 0, timestamp=2.0)
        rows = extractor.ingest_event(src_ip, 22, 0x12, 120, timestamp=3.1)

        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row["src_ip"], src_ip)
        self.assertEqual(row["packet_count"], 3.0)
        self.assertEqual(row["unique_dst_ports"], 1.0)
        self.assertGreater(row["syn_ratio"], 0.6)


class IntrusionModelTests(unittest.TestCase):
    def test_trained_model_classifies_clear_bruteforce_pattern(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            model_path = Path(tmp_dir) / "model.joblib"
            train_and_save(model_path)
            model = IntrusionModel(str(model_path), threshold=0.65)

            label, score = model.classify(
                {
                    "packet_count": 120.0,
                    "syn_ratio": 0.95,
                    "rst_ratio": 0.6,
                    "avg_payload_len": 10.0,
                    "unique_dst_ports": 1.0,
                    "connection_rate": 30.0,
                }
            )
            self.assertEqual(label, "malicious")
            self.assertGreaterEqual(score, 0.65)


if __name__ == "__main__":
    unittest.main()
