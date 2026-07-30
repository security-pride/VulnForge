import sys
from pathlib import Path

CODE_DIR = Path(__file__).resolve().parents[1]
if str(CODE_DIR) not in sys.path:
    sys.path.insert(0, str(CODE_DIR))

from common.io_utils import append_jsonl, load_records
from patch_untangling.agent import HuggingFacePatchAgent
from patch_untangling.pipeline import aggregate_commit_results, run_agentic_untangling

SUB_PATCH_INPUT_PATHS = {
    "bigvul": "xxx",
    "d2a": "xxx",
    "diversevul": "xxx",
    "reposvul": "xxx",
}
CONTEXT_INPUT_PATHS = {
    "bigvul": "xxx",
    "d2a": "xxx",
    "diversevul": "xxx",
    "reposvul": "xxx",
}
DECISION_OUTPUT_PATH = "xxx"
AGGREGATED_OUTPUT_PATH = "xxx"
AGENT_MODEL_PATH = "xxx"
CRITIC_MODEL_PATH = "xxx"
RUN_MODE = "full_vulnforge"
ENTROPY_THRESHOLD = 0.4
RATIONALE_THRESHOLD = 0.85


def process_dataset(dataset_name, agent, critic):
    sub_patches = load_records(SUB_PATCH_INPUT_PATHS[dataset_name])
    context_records = load_records(CONTEXT_INPUT_PATHS[dataset_name])
    decision_records = run_agentic_untangling(
        sub_patches,
        context_records,
        agent,
        critic,
        RUN_MODE,
        ENTROPY_THRESHOLD,
        RATIONALE_THRESHOLD,
    )
    for decision_record in decision_records:
        append_jsonl(DECISION_OUTPUT_PATH, decision_record)
    grouped = {}
    for decision_record in decision_records:
        grouped.setdefault(decision_record.get("commit_group_id"), []).append(decision_record)
    for commit_results in grouped.values():
        append_jsonl(AGGREGATED_OUTPUT_PATH, aggregate_commit_results(commit_results))


def main():
    agent = HuggingFacePatchAgent(AGENT_MODEL_PATH, temperature=0.0)
    critic = None
    if RUN_MODE in {"without_uq", "full_vulnforge"}:
        critic = HuggingFacePatchAgent(CRITIC_MODEL_PATH, temperature=0.0)
    for dataset_name, input_path in SUB_PATCH_INPUT_PATHS.items():
        if input_path == "xxx":
            continue
        process_dataset(dataset_name, agent, critic)


if __name__ == "__main__":
    main()
