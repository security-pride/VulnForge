import sys
from collections import defaultdict
from pathlib import Path

CODE_DIR = Path(__file__).resolve().parents[1]
if str(CODE_DIR) not in sys.path:
    sys.path.insert(0, str(CODE_DIR))

from common.prompting import build_agent_prompt, build_critic_prompt


def context_index_key(payload):
    for key in ("commit_group_id", "cve_id", "sample_id"):
        value = payload.get(key)
        if value:
            return value
    return None


def index_context_records(records):
    index = {}
    for record in records:
        key = context_index_key(record)
        if key:
            index[key] = record
    return index


def resolve_context_payload(sub_patch, context_index):
    for key in (sub_patch.get("commit_group_id"), sub_patch.get("cve_id"), sub_patch.get("sample_id")):
        if key and key in context_index:
            return context_index[key]
    return {}


def group_sub_patches(sub_patches):
    grouped = defaultdict(list)
    for sub_patch in sub_patches:
        grouped[sub_patch.get("commit_group_id")].append(sub_patch)
    return grouped


def peer_sub_patches(sub_patch, grouped):
    return [candidate for candidate in grouped.get(sub_patch.get("commit_group_id"), []) if candidate.get("sub_patch_id") != sub_patch.get("sub_patch_id")]


def use_critic(mode, initial_result, entropy_threshold, rationale_threshold):
    if mode == "base_agent":
        return False
    if mode == "without_uq":
        return True
    if mode == "without_cf":
        return False
    if mode == "full_vulnforge":
        return (
            initial_result.get("predictive_entropy", 0.0) > entropy_threshold
            or initial_result.get("normalized_rationale_perplexity", 0.0) > rationale_threshold
        )
    return False


def evaluate_sub_patch(sub_patch, grouped_sub_patches, context_index, agent, critic, mode, entropy_threshold, rationale_threshold):
    peers = peer_sub_patches(sub_patch, grouped_sub_patches)
    context_payload = resolve_context_payload(sub_patch, context_index)
    initial_prompt = build_agent_prompt(sub_patch, peers, context_payload)
    initial_result = agent.analyze(initial_prompt)
    final_result = dict(initial_result)
    critic_triggered = False
    if critic is not None and use_critic(mode, initial_result, entropy_threshold, rationale_threshold):
        critic_triggered = True
        critic_prompt = build_critic_prompt(sub_patch, peers, context_payload, initial_result)
        final_result = critic.analyze(critic_prompt)
    return {
        "dataset": sub_patch.get("dataset"),
        "sample_id": sub_patch.get("sample_id"),
        "cve_id": sub_patch.get("cve_id"),
        "commit_group_id": sub_patch.get("commit_group_id"),
        "sub_patch_id": sub_patch.get("sub_patch_id"),
        "function_name": sub_patch.get("function_name"),
        "file_path": sub_patch.get("file_path"),
        "description": sub_patch.get("description"),
        "cwe_list": sub_patch.get("cwe_list", []),
        "patch": sub_patch.get("patch", ""),
        "pre_patch_function": sub_patch.get("pre_patch_function", ""),
        "post_patch_function": sub_patch.get("post_patch_function", ""),
        "peer_sub_patch_ids": [peer.get("sub_patch_id") for peer in peers],
        "context_payload": context_payload,
        "mode": mode,
        "initial_decision": initial_result.get("decision"),
        "initial_rationale": initial_result.get("rationale"),
        "predictive_entropy": initial_result.get("predictive_entropy"),
        "rationale_perplexity": initial_result.get("rationale_perplexity"),
        "normalized_rationale_perplexity": initial_result.get("normalized_rationale_perplexity"),
        "critic_triggered": critic_triggered,
        "final_decision": final_result.get("decision"),
        "final_rationale": final_result.get("rationale"),
        "ground_truth_label": sub_patch.get("ground_truth_label"),
    }


def run_agentic_untangling(sub_patches, context_records, agent, critic, mode, entropy_threshold, rationale_threshold):
    grouped = group_sub_patches(sub_patches)
    context_index = index_context_records(context_records)
    results = []
    for sub_patch in sub_patches:
        results.append(
            evaluate_sub_patch(
                sub_patch,
                grouped,
                context_index,
                agent,
                critic,
                mode,
                entropy_threshold,
                rationale_threshold,
            )
        )
    return results


def aggregate_commit_results(results):
    if not results:
        return {}
    relevant = [result for result in results if result.get("final_decision") == "yes"]
    fallback_relevant_sub_patch_id = None
    if not relevant and results:
        relevant = [results[0]]
        fallback_relevant_sub_patch_id = results[0].get("sub_patch_id")
    irrelevant = [result for result in results if result not in relevant]
    context_payload = results[0].get("context_payload", {})
    return {
        "dataset": results[0].get("dataset"),
        "sample_id": results[0].get("sample_id"),
        "cve_id": results[0].get("cve_id"),
        "commit_group_id": results[0].get("commit_group_id"),
        "vulnerable_functions": [
            {
                "sub_patch_id": result.get("sub_patch_id"),
                "function_name": result.get("function_name"),
                "code": result.get("pre_patch_function"),
            }
            for result in relevant
        ],
        "safe_functions": [
            {
                "sub_patch_id": result.get("sub_patch_id"),
                "function_name": result.get("function_name"),
                "code": result.get("post_patch_function"),
            }
            for result in relevant
        ],
        "vulnerability_context": [
            {
                "sub_patch_id": result.get("sub_patch_id"),
                "function_name": result.get("function_name"),
                "code": result.get("pre_patch_function"),
            }
            for result in irrelevant
        ],
        "local_dependency_graph": context_payload,
        "fallback_relevant_sub_patch_id": fallback_relevant_sub_patch_id,
    }
