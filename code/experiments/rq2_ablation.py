import sys
from pathlib import Path

CODE_DIR = Path(__file__).resolve().parents[1]
if str(CODE_DIR) not in sys.path:
    sys.path.insert(0, str(CODE_DIR))

from common.io_utils import append_jsonl, load_records
from common.metrics import classification_metrics, confusion_counts

CONFIG_INPUT_PATHS = {
    "base_agent": "xxx",
    "without_uq": "xxx",
    "without_cf": "xxx",
    "full_vulnforge": "xxx",
}
SUMMARY_OUTPUT_PATH = "xxx"
DETAIL_OUTPUT_PATH = "xxx"


def main():
    for config_name, input_path in CONFIG_INPUT_PATHS.items():
        if input_path == "xxx":
            continue
        records = load_records(input_path)
        counts = confusion_counts(records)
        metrics = classification_metrics(counts)
        append_jsonl(
            SUMMARY_OUTPUT_PATH,
            {
                "configuration": config_name,
                "samples": len(records),
                **counts,
                **metrics,
            },
        )
        for record in records:
            append_jsonl(DETAIL_OUTPUT_PATH, {"configuration": config_name, **record})


if __name__ == "__main__":
    main()
