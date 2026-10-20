"""Reproducible offline scoring of a labeled technographic extraction holdout."""

import argparse
import json
from collections import Counter
from pathlib import Path

from .technographics import extract


def evaluate(corpus):
    totals = Counter()
    classes = {}
    errors = []
    for case in corpus["cases"]:
        expected = {(row["product"], row["status"]) for row in case["expected"]}
        predicted = {(row["product"], row["status"]) for row in extract(case["text"], source_type=case.get("source_type", ""))}
        matched, extra, missing = expected & predicted, predicted - expected, expected - predicted
        for metric, entries in (("true_positive", matched), ("false_positive", extra), ("false_negative", missing)):
            totals[metric] += len(entries)
            for _, status in entries:
                classes.setdefault(status, Counter())[metric] += 1
        if extra or missing:
            errors.append({"id": case["id"], "extra": sorted(extra), "missing": sorted(missing)})

    def scores(counts):
        tp, fp, fn = (counts[key] for key in ("true_positive", "false_positive", "false_negative"))
        return {"true_positive": tp, "false_positive": fp, "false_negative": fn,
                "precision": round(tp / (tp + fp), 4) if tp + fp else None,
                "recall": round(tp / (tp + fn), 4) if tp + fn else None,
                "f1": round(2 * tp / (2 * tp + fp + fn), 4) if 2 * tp + fp + fn else None}

    return {"corpus": corpus["name"], "version": corpus["version"], "cases": len(corpus["cases"]),
            "overall": scores(totals), "evidence_classes": {key: scores(value) for key, value in sorted(classes.items())},
            "errors": errors, "limitations": corpus.get("limitations", [])}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpus", type=Path, help="Path to a labeled JSON holdout corpus")
    args = parser.parse_args()
    print(json.dumps(evaluate(json.loads(args.corpus.read_text(encoding="utf-8"))), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
