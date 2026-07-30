import sys
from pathlib import Path

CODE_DIR = Path(__file__).resolve().parents[1]
if str(CODE_DIR) not in sys.path:
    sys.path.insert(0, str(CODE_DIR))

from common.dataset_utils import normalize_dataset_record
from common.io_utils import append_jsonl, load_records
from patch_decomposition.decomposer import build_commit_group_id, decompose_normalized_record, fetch_commit_payload, verify_record_metadata

DATASET_INPUT_PATHS = {
    "bigvul": "xxx",
    "d2a": "xxx",
    "diversevul": "xxx",
    "reposvul": "xxx",
}
VERIFIED_OUTPUT_PATH = "xxx"
FILTERED_OUTPUT_PATH = "xxx"
SUB_PATCH_OUTPUT_PATH = "xxx"
GITHUB_TOKEN = "xxx"


def process_dataset(dataset_name, input_path):
    for raw_record in load_records(input_path):
        normalized = normalize_dataset_record(dataset_name, raw_record)
        if not verify_record_metadata(normalized):
            append_jsonl(
                FILTERED_OUTPUT_PATH,
                {
                    "dataset": dataset_name,
                    "sample_id": normalized.get("sample_id"),
                    "cve_id": normalized.get("cve_id"),
                    "reason": "metadata_verification_failed",
                    "record": normalized,
                },
            )
            continue
        commit_payload = fetch_commit_payload(normalized, GITHUB_TOKEN)
        sub_patches = decompose_normalized_record(normalized, commit_payload)
        verified_record = {
            "dataset": dataset_name,
            "sample_id": normalized.get("sample_id"),
            "cve_id": normalized.get("cve_id"),
            "commit_group_id": build_commit_group_id(normalized),
            "commit_url": normalized.get("commit_url"),
            "commit_hash": normalized.get("commit_hash"),
            "repo_name": normalized.get("repo_name"),
            "description": normalized.get("description"),
            "cwe_list": normalized.get("cwe_list", []),
            "commit_message": commit_payload.get("commit_message", normalized.get("commit_message", "")),
            "sub_patch_count": len(sub_patches),
        }
        append_jsonl(VERIFIED_OUTPUT_PATH, verified_record)
        for sub_patch in sub_patches:
            append_jsonl(SUB_PATCH_OUTPUT_PATH, sub_patch)


def main():
    for dataset_name, input_path in DATASET_INPUT_PATHS.items():
        if input_path == "xxx":
            continue
        process_dataset(dataset_name, input_path)


if __name__ == "__main__":
    main()
