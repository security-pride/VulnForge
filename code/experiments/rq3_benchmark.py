import sys
from pathlib import Path

CODE_DIR = Path(__file__).resolve().parents[1]
if str(CODE_DIR) not in sys.path:
    sys.path.insert(0, str(CODE_DIR))

from common.io_utils import append_jsonl, load_records
from common.metrics import classification_metrics, confusion_counts, normalize_binary_label
from common.modeling import generate_analysis, load_generation_bundle
from common.prompting import build_detection_prompt

ORIGINAL_DATASET_PATHS = {
    "d2a": "xxx",
    "diversevul": "xxx",
}
VULNFORGE_DATASET_PATHS = {
    "d2a": "xxx",
    "diversevul": "xxx",
}
MODEL_PATHS = {
    "qwen3_8b": "xxx",
    "qwen3_32b": "xxx",
    "gpt_4o_mini": "xxx",
    "gpt_4o": "xxx",
}
PREDICTION_OUTPUT_PATH = "xxx"
SUMMARY_OUTPUT_PATH = "xxx"


def as_function_list(value):
    if isinstance(value, dict):
        records = []
        for key, payload in value.items():
            if isinstance(payload, dict):
                records.append({"function_id": key, "code": payload.get("code", ""), "name": payload.get("name", key)})
            else:
                records.append({"function_id": key, "code": str(payload), "name": key})
        return records
    if isinstance(value, list):
        records = []
        for index, payload in enumerate(value, start=1):
            if isinstance(payload, dict):
                records.append(payload)
            else:
                records.append({"function_id": f"function-{index}", "code": str(payload), "name": f"function_{index}"})
        return records
    return []


def normalize_detection_sample(record, variant):
    functions = as_function_list(record.get("functions"))
    if not functions:
        functions = as_function_list(record.get("vulnerable_functions"))
    description = record.get("description") or record.get("Bug information") or record.get("CVE information") or ""
    cwe_list = record.get("cwe_list") or record.get("CWE information") or []
    sample = {
        "sample_id": record.get("sample_id") or record.get("id"),
        "cve_id": record.get("cve_id"),
        "description": description,
        "cwe_list": cwe_list if isinstance(cwe_list, list) else [cwe_list],
        "functions": functions,
        "vulnerability_context": record.get("vulnerability_context", []),
        "local_dependency_graph": record.get("local_dependency_graph", {}),
        "label": normalize_binary_label(record.get("label") or record.get("ground_truth_label") or record.get("response")),
        "variant": variant,
    }
    return sample


def evaluate_records(records, bundle, dataset_name, variant, model_name):
    prediction_records = []
    for record in records:
        sample = normalize_detection_sample(record, variant)
        prompt = build_detection_prompt(sample, use_context=variant == "vulnforge")
        result = generate_analysis(bundle, prompt, temperature=0.0, max_new_tokens=128)
        prediction_records.append(
            {
                "dataset": dataset_name,
                "variant": variant,
                "model_name": model_name,
                "sample_id": sample.get("sample_id"),
                "cve_id": sample.get("cve_id"),
                "label": sample.get("label"),
                "prediction": result.get("decision"),
                "rationale": result.get("rationale"),
            }
        )
    return prediction_records


def write_summary(prediction_records, dataset_name, variant, model_name):
    counts = confusion_counts(
        [{"final_decision": record.get("prediction"), "ground_truth_label": record.get("label")} for record in prediction_records]
    )
    metrics = classification_metrics(counts)
    append_jsonl(
        SUMMARY_OUTPUT_PATH,
        {
            "dataset": dataset_name,
            "variant": variant,
            "model_name": model_name,
            "samples": len(prediction_records),
            **counts,
            **metrics,
        },
    )


def main():
    for model_name, model_path in MODEL_PATHS.items():
        if model_path == "xxx":
            continue
        bundle = load_generation_bundle(model_path)
        for dataset_name, original_path in ORIGINAL_DATASET_PATHS.items():
            if original_path != "xxx":
                original_predictions = evaluate_records(load_records(original_path), bundle, dataset_name, "original", model_name)
                for record in original_predictions:
                    append_jsonl(PREDICTION_OUTPUT_PATH, record)
                write_summary(original_predictions, dataset_name, "original", model_name)
            refined_path = VULNFORGE_DATASET_PATHS.get(dataset_name, "xxx")
            if refined_path != "xxx":
                refined_predictions = evaluate_records(load_records(refined_path), bundle, dataset_name, "vulnforge", model_name)
                for record in refined_predictions:
                    append_jsonl(PREDICTION_OUTPUT_PATH, record)
                write_summary(refined_predictions, dataset_name, "vulnforge", model_name)


if __name__ == "__main__":
    main()
