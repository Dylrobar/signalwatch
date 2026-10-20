import json
import unittest
from pathlib import Path

from signalwatch.extraction_evaluation import evaluate


class ExtractionEvaluationTests(unittest.TestCase):
    def test_frozen_holdout_reports_precision_recall_by_evidence_class(self):
        corpus = json.loads((Path(__file__).parent / "fixtures" / "extraction_holdout_v1.json").read_text())
        report = evaluate(corpus)
        self.assertEqual(report, evaluate(corpus))
        self.assertEqual(report["cases"], 34)
        self.assertEqual(set(report["evidence_classes"]),
                         {"asserted_use", "negated", "historical", "planned", "requirement", "alternative", "mention"})
        # Broad regression guard, not a calibration claim. Any ambiguity
        # errors remain exposed rather than relabeling the fixture to pass.
        self.assertGreaterEqual(report["overall"]["precision"], .85)
        self.assertGreaterEqual(report["overall"]["recall"], .85)
        self.assertGreaterEqual(report["evidence_classes"]["asserted_use"]["precision"], .9)


if __name__ == "__main__":
    unittest.main()
