def normalize_binary_label(value):
    if value is None:
        return None
    normalized = str(value).strip().lower()
    if normalized in {"yes", "true", "1", "positive", "relevant", "vulnerable"}:
        return "yes"
    if normalized in {"no", "false", "0", "negative", "irrelevant", "safe", "non-vulnerable"}:
        return "no"
    return None


def safe_divide(numerator, denominator):
    if denominator == 0:
        return 0.0
    return numerator / denominator


def confusion_counts(records, prediction_key="final_decision", label_key="ground_truth_label"):
    counts = {"tp": 0, "fp": 0, "fn": 0, "tn": 0}
    for record in records:
        predicted = normalize_binary_label(record.get(prediction_key))
        actual = normalize_binary_label(record.get(label_key))
        if predicted is None or actual is None:
            continue
        if predicted == "yes" and actual == "yes":
            counts["tp"] += 1
        elif predicted == "yes" and actual == "no":
            counts["fp"] += 1
        elif predicted == "no" and actual == "yes":
            counts["fn"] += 1
        else:
            counts["tn"] += 1
    return counts


def classification_metrics(counts):
    precision = safe_divide(counts["tp"], counts["tp"] + counts["fp"])
    recall = safe_divide(counts["tp"], counts["tp"] + counts["fn"])
    specificity = safe_divide(counts["tn"], counts["tn"] + counts["fp"])
    f1 = safe_divide(2 * precision * recall, precision + recall)
    accuracy = safe_divide(
        counts["tp"] + counts["tn"],
        counts["tp"] + counts["fp"] + counts["fn"] + counts["tn"],
    )
    return {
        "precision": precision,
        "recall": recall,
        "specificity": specificity,
        "f1": f1,
        "accuracy": accuracy,
    }
