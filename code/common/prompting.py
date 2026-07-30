import json

from common.dataset_utils import stringify


def render_payload(payload):
    return json.dumps(payload, ensure_ascii=False, indent=2)


def build_agent_prompt(sub_patch, peer_sub_patches, context_graph):
    metadata = {
        "dataset": sub_patch.get("dataset"),
        "cve_id": sub_patch.get("cve_id"),
        "description": sub_patch.get("description"),
        "cwe_list": sub_patch.get("cwe_list", []),
        "commit_message": sub_patch.get("commit_message", ""),
        "file_path": sub_patch.get("file_path", ""),
        "function_name": sub_patch.get("function_name", ""),
    }
    focal_patch = {
        "sub_patch_id": sub_patch.get("sub_patch_id"),
        "patch": sub_patch.get("patch", ""),
        "pre_patch_function": sub_patch.get("pre_patch_function", ""),
        "post_patch_function": sub_patch.get("post_patch_function", ""),
    }
    peer_payload = []
    for peer in peer_sub_patches:
        peer_payload.append(
            {
                "sub_patch_id": peer.get("sub_patch_id"),
                "function_name": peer.get("function_name", ""),
                "file_path": peer.get("file_path", ""),
                "patch": peer.get("patch", ""),
            }
        )
    return "\n".join(
        [
            "Role: Security expert and vulnerability analysis specialist.",
            "Task: Decide whether the focal sub-patch is relevant to the vulnerability.",
            "Output format:",
            'Decision: yes or no',
            "Rationale: one concise paragraph",
            "Vulnerability metadata:",
            render_payload(metadata),
            "Focal sub-patch:",
            render_payload(focal_patch),
            "Peer sub-patches:",
            render_payload(peer_payload),
            "Local dependency graph:",
            render_payload(context_graph),
        ]
    )


def build_critic_prompt(sub_patch, peer_sub_patches, context_graph, initial_result):
    return "\n".join(
        [
            build_agent_prompt(sub_patch, peer_sub_patches, context_graph),
            "Initial analysis:",
            render_payload(initial_result),
            "Task: Re-evaluate the focal sub-patch using deeper reference reasoning and return a corrected decision.",
        ]
    )


def build_detection_prompt(sample, use_context):
    payload = {
        "bug_type": sub_patch_bug_type(sample),
        "description": sample.get("description", ""),
        "functions": sample.get("functions", []),
    }
    if use_context:
        payload["local_dependency_graph"] = sample.get("local_dependency_graph", {})
        payload["vulnerability_context"] = sample.get("vulnerability_context", [])
    return "\n".join(
        [
            "You are a vulnerability detection expert.",
            "Decide whether the provided code contains the described vulnerability type.",
            "Output only yes or no on the first line and then a short rationale.",
            stringify(payload),
        ]
    )


def build_rq4_training_record(sample, use_context):
    prompt = build_detection_prompt(sample, use_context)
    label = sample.get("label")
    return {"prompt": prompt, "response": label}


def sub_patch_bug_type(sample):
    cwe_list = sample.get("cwe_list") or []
    if cwe_list:
        return cwe_list[0]
    return sample.get("description", "")
