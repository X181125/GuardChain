from pathlib import Path
import csv
from collections import Counter

root = Path("benchmarks/final_dataset")
out = Path("benchmarks/final_dataset/labels.csv")
rows = []

for p in sorted((root / "malicious").iterdir()):
    if p.is_dir():
        rows.append({"path": f"malicious/{p.name}", "label": "MALICIOUS", "group": "datadog_pypi_malicious"})

for p in sorted((root / "benign").iterdir()):
    if p.is_file():
        rows.append({"path": f"benign/{p.name}", "label": "BENIGN", "group": "benign_pypi"})

local_labels = {
    "benign_pkg": "BENIGN",
    "suspicious_pkg": "SUSPICIOUS",
    "malicious_like_pkg": "MALICIOUS",
    "setup_time_malicious_like_pkg": "MALICIOUS",
    "download_execute_like_pkg": "MALICIOUS",
    "typosquat_like_pkg": "SUSPICIOUS",
}

for rel, label in local_labels.items():
    p = root / "local" / rel
    if p.exists():
        rows.append({"path": f"local/{rel}", "label": label, "group": "local_synthetic"})

out.parent.mkdir(parents=True, exist_ok=True)
with out.open("w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=["path", "label", "group"])
    writer.writeheader()
    writer.writerows(rows)

print(f"Wrote {len(rows)} labels to {out}")
print("By group:", Counter(r["group"] for r in rows))
print("By label:", Counter(r["label"] for r in rows))
