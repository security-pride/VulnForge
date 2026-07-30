import sys
from pathlib import Path

CODE_DIR = Path(__file__).resolve().parents[1]
if str(CODE_DIR) not in sys.path:
    sys.path.insert(0, str(CODE_DIR))

from common.io_utils import append_jsonl, load_records
from common.metrics import classification_metrics, confusion_counts, normalize_binary_label
from common.modeling import generate_analysis, load_generation_bundle
from common.prompting import build_detection_prompt

EVALUATION_INPUT_PATH = "xxx"
MODEL_PATHS = {
    "base_model": "xxx",
    "sft_original": "xxx",
    "sft_vulnforge": "xxx",
}
PREDICTION_OUTPUT_PATH = "xxx"
SUMMARY_OUTPUT_PATH = "xxx"


def normalize_evaluation_sample(record):
    if "prompt" in record and "response" in record:
        return {
            "prompt": record["prompt"],
            "label": normalize_binary_label(record["response"]),
            "sample_id": record.get("sample_id"),
            "cve_id": record.get("cve_id"),
        }
    return {
        "prompt": build_detection_prompt(
            {
                "description": record.get("description", ""),
                "cwe_list": record.get("cwe_list", []),
                "functions": record.get("functions", []),
                "vulnerability_context": record.get("vulnerability_context", []),
                "local_dependency_graph": record.get("local_dependency_graph", {}),
            },
            use_context=True,
        ),
        "label": normalize_binary_label(record.get("label") or record.get("ground_truth_label")),
        "sample_id": record.get("sample_id"),
        "cve_id": record.get("cve_id"),
    }


def main():
    evaluation_records = [normalize_evaluation_sample(record) for record in load_records(EVALUATION_INPUT_PATH)]
    for model_name, model_path in MODEL_PATHS.items():
        if model_path == "xxx":
            continue
        bundle = load_generation_bundle(model_path)
        prediction_records = []
        for sample in evaluation_records:
            result = generate_analysis(bundle, sample["prompt"], temperature=0.0, max_new_tokens=128)
            prediction_records.append(
                {
                    "model_name": model_name,
                    "sample_id": sample.get("sample_id"),
                    "cve_id": sample.get("cve_id"),
                    "label": sample.get("label"),
                    "prediction": result.get("decision"),
                    "rationale": result.get("rationale"),
                }
            )
        for record in prediction_records:
            append_jsonl(PREDICTION_OUTPUT_PATH, record)
        counts = confusion_counts(
            [{"final_decision": record.get("prediction"), "ground_truth_label": record.get("label")} for record in prediction_records]
        )
        metrics = classification_metrics(counts)
        append_jsonl(
            SUMMARY_OUTPUT_PATH,
            {
                "model_name": model_name,
                "samples": len(prediction_records),
                **counts,
                **metrics,
            },
        )


if __name__ == "__main__":
    main()
