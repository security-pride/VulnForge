import sys
from pathlib import Path

CODE_DIR = Path(__file__).resolve().parents[1]
if str(CODE_DIR) not in sys.path:
    sys.path.insert(0, str(CODE_DIR))

from common.io_utils import append_jsonl, load_records
from common.metrics import normalize_binary_label
from common.prompting import build_rq4_training_record

ORIGINAL_TRAIN_INPUT_PATH = "xxx"
VULNFORGE_TRAIN_INPUT_PATH = "xxx"
EVALUATION_INPUT_PATH = "xxx"
ORIGINAL_TRAIN_OUTPUT_PATH = "xxx"
VULNFORGE_TRAIN_OUTPUT_PATH = "xxx"
EVALUATION_OUTPUT_PATH = "xxx"


def as_function_list(value):
    if isinstance(value, dict):
        return [{"function_id": key, "code": payload.get("code", "") if isinstance(payload, dict) else str(payload)} for key, payload in value.items()]
    if isinstance(value, list):
        return [payload if isinstance(payload, dict) else {"function_id": str(index), "code": str(payload)} for index, payload in enumerate(value, start=1)]
    return []


def normalize_training_sample(record, use_context):
    functions = as_function_list(record.get("functions"))
    if not functions:
        functions = as_function_list(record.get("vulnerable_functions"))
    return {
        "sample_id": record.get("sample_id") or record.get("id"),
        "cve_id": record.get("cve_id"),
        "description": record.get("description") or record.get("Bug information") or record.get("CVE information") or "",
        "cwe_list": record.get("cwe_list") or [],
        "functions": functions,
        "vulnerability_context": record.get("vulnerability_context", []),
        "local_dependency_graph": record.get("local_dependency_graph", {}),
        "label": normalize_binary_label(record.get("label") or record.get("ground_truth_label") or record.get("response")),
        "use_context": use_context,
    }


def convert_records(input_path, output_path, use_context):
    for record in load_records(input_path):
        sample = normalize_training_sample(record, use_context)
        if sample["label"] is None:
            continue
        training_record = build_rq4_training_record(sample, use_context)
        if training_record["response"] is None:
            continue
        append_jsonl(output_path, training_record)


def main():
    if ORIGINAL_TRAIN_INPUT_PATH != "xxx":
        convert_records(ORIGINAL_TRAIN_INPUT_PATH, ORIGINAL_TRAIN_OUTPUT_PATH, False)
    if VULNFORGE_TRAIN_INPUT_PATH != "xxx":
        convert_records(VULNFORGE_TRAIN_INPUT_PATH, VULNFORGE_TRAIN_OUTPUT_PATH, True)
    if EVALUATION_INPUT_PATH != "xxx":
        convert_records(EVALUATION_INPUT_PATH, EVALUATION_OUTPUT_PATH, True)


if __name__ == "__main__":
    main()
