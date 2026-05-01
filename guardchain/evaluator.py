from __future__ import annotations

import csv
from pathlib import Path
from typing import Any

from .scanner import scan

VALID_LABELS = {"BENIGN", "SUSPICIOUS", "MALICIOUS"}


def evaluate_dataset(
    dataset: str | Path,
    labels_csv: str | Path,
    suspicious_mode: str = "positive",
    max_files: int = 5000,
    max_size_mb: int = 100,
) -> dict[str, Any]:
    dataset_root = Path(dataset).expanduser().resolve()
    labels_path = Path(labels_csv).expanduser().resolve()
    rows = _read_labels(labels_path)
    results: list[dict[str, Any]] = []
    tp = fp = tn = fn = 0
    missing: list[str] = []

    for rel_path, expected in rows:
        target = dataset_root / rel_path
        if not target.exists():
            missing.append(rel_path)
            continue
        result = scan(target, max_files=max_files, max_size_mb=max_size_mb)
        predicted = result.label
        actual_positive = _is_positive(expected, suspicious_mode)
        predicted_positive = _is_positive(predicted, suspicious_mode)
        if actual_positive and predicted_positive:
            tp += 1
        elif not actual_positive and predicted_positive:
            fp += 1
        elif not actual_positive and not predicted_positive:
            tn += 1
        else:
            fn += 1
        results.append({"path": rel_path, "expected": expected, "predicted": predicted, "score": result.score})

    precision = _safe_div(tp, tp + fp)
    recall = _safe_div(tp, tp + fn)
    return {
        "dataset": str(dataset_root),
        "labels": str(labels_path),
        "suspicious_mode": suspicious_mode,
        "counts": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
        "precision": precision,
        "recall": recall,
        "f1_score": _safe_div(2 * precision * recall, precision + recall),
        "accuracy": _safe_div(tp + tn, tp + tn + fp + fn),
        "false_positive_rate": _safe_div(fp, fp + tn),
        "false_negative_rate": _safe_div(fn, fn + tp),
        "missing": missing,
        "results": results,
    }


def _read_labels(path: Path) -> list[tuple[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        rows: list[tuple[str, str]] = []
        for row in reader:
            normalized = {key.lstrip("\ufeff") if key else key: value for key, value in row.items()}
            rel_path = (normalized.get("path") or "").strip()
            label = (normalized.get("label") or "").strip().upper()
            if not rel_path or label not in VALID_LABELS:
                continue
            rows.append((rel_path, label))
        return rows


def _is_positive(label: str, suspicious_mode: str) -> bool:
    if label == "MALICIOUS":
        return True
    if label == "SUSPICIOUS":
        return suspicious_mode == "positive"
    return False


def _safe_div(numerator: float, denominator: float) -> float:
    return round(numerator / denominator, 6) if denominator else 0.0
