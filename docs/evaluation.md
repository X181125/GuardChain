# Evaluation Mode

GuardChain can evaluate predictions against a labeled dataset.

```bash
python -m guardchain evaluate --dataset ./dataset --labels ./labels.csv --json reports/eval.json
```

`labels.csv` must contain:

```csv
path,label
benign/pkg1,BENIGN
malicious/pkg2,MALICIOUS
suspicious/pkg3,SUSPICIOUS
```

Metrics include true positives, false positives, true negatives, false negatives, precision, recall, F1 score, accuracy, false positive rate, and false negative rate.

By default `SUSPICIOUS` is treated as positive for binary metrics. Use `--suspicious-as-negative` to treat it as negative.
