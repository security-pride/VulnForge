import hashlib
import os
from urllib.parse import urlparse

from common.dataset_utils import line_overlap, parse_location_range, parse_patch_hunks


def build_commit_group_id(record):
    if record.get("cve_id"):
        return f'{record.get("dataset", "dataset")}::{record["cve_id"]}'
    if record.get("sample_id"):
        return f'{record.get("dataset", "dataset")}::{record["sample_id"]}'
    return f'{record.get("dataset", "dataset")}::unknown'


def verify_record_metadata(record):
    if record.get("metadata_verified") is True:
        return True
    description = " ".join(
        [
            str(record.get("description", "")),
            " ".join(str(reference) for reference in record.get("references", [])),
        ]
    ).lower()
    if not description or not record.get("commit_url"):
        return False
    for function in record.get("functions", []):
        function_name = str(function.get("name", "")).lower()
        file_name = os.path.basename(str(function.get("file_path", ""))).lower()
        if function_name and function_name in description:
            return True
        if file_name and file_name in description:
            return True
    return False


def github_api_commit_url(commit_url):
    parsed = urlparse(commit_url)
    segments = [segment for segment in parsed.path.split("/") if segment]
    if "commit" not in segments or len(segments) < 4:
        return ""
    owner = segments[0]
    repo = segments[1]
    commit_hash = segments[-1]
    return f"https://api.github.com/repos/{owner}/{repo}/commits/{commit_hash}"


def fetch_commit_payload(record, github_token):
    if "commit_payload" in record:
        return record["commit_payload"]
    commit_url = record.get("commit_url", "")
    if not commit_url:
        return {"commit_message": record.get("commit_message", ""), "files": []}
    api_url = github_api_commit_url(commit_url)
    if not api_url:
        return {"commit_message": record.get("commit_message", ""), "files": []}
    import requests

    headers = {}
    if github_token and github_token != "xxx":
        headers["Authorization"] = f"Bearer {github_token}"
    response = requests.get(api_url, headers=headers, timeout=60)
    response.raise_for_status()
    payload = response.json()
    files = []
    for file_payload in payload.get("files", []):
        files.append(
            {
                "filename": file_payload.get("filename", ""),
                "patch": file_payload.get("patch", ""),
            }
        )
    return {
        "commit_message": payload.get("commit", {}).get("message", record.get("commit_message", "")),
        "files": files,
    }


def relevant_functions_for_file(record, file_name):
    return [function for function in record.get("functions", []) if function.get("file_path") == file_name]


def synthetic_sub_patch_id(commit_group_id, file_name, index):
    digest = hashlib.md5(f"{commit_group_id}:{file_name}:{index}".encode("utf-8")).hexdigest()[:12]
    return f"sub_patch::{digest}"


def function_sub_patch_id(commit_group_id, function_name, location):
    digest = hashlib.md5(f"{commit_group_id}:{function_name}:{location}".encode("utf-8")).hexdigest()[:12]
    return f"sub_patch::{digest}"


def build_function_sub_patch(record, function, commit_message, matched_hunks):
    commit_group_id = build_commit_group_id(record)
    return {
        "dataset": record.get("dataset"),
        "sample_id": record.get("sample_id"),
        "cve_id": record.get("cve_id"),
        "commit_group_id": commit_group_id,
        "sub_patch_id": function_sub_patch_id(commit_group_id, function.get("name", ""), function.get("location", "")),
        "description": record.get("description", ""),
        "cwe_list": record.get("cwe_list", []),
        "commit_url": record.get("commit_url", ""),
        "commit_hash": record.get("commit_hash", ""),
        "commit_message": commit_message,
        "repo_name": record.get("repo_name", ""),
        "file_path": function.get("file_path", ""),
        "function_name": function.get("name", ""),
        "function_location": function.get("location", ""),
        "pre_patch_function": function.get("pre_patch_function", ""),
        "post_patch_function": function.get("post_patch_function", ""),
        "patch": "\n".join(hunk["patch"] for hunk in matched_hunks),
        "references": record.get("references", []),
        "peer_sub_patch_ids": [],
        "ground_truth_label": record.get("ground_truth_label"),
    }


def build_synthetic_sub_patch(record, file_name, hunk, index, commit_message):
    commit_group_id = build_commit_group_id(record)
    return {
        "dataset": record.get("dataset"),
        "sample_id": record.get("sample_id"),
        "cve_id": record.get("cve_id"),
        "commit_group_id": commit_group_id,
        "sub_patch_id": synthetic_sub_patch_id(commit_group_id, file_name, index),
        "description": record.get("description", ""),
        "cwe_list": record.get("cwe_list", []),
        "commit_url": record.get("commit_url", ""),
        "commit_hash": record.get("commit_hash", ""),
        "commit_message": commit_message,
        "repo_name": record.get("repo_name", ""),
        "file_path": file_name,
        "function_name": f"unknown_function_{index}",
        "function_location": "",
        "pre_patch_function": "",
        "post_patch_function": "",
        "patch": hunk["patch"],
        "references": record.get("references", []),
        "peer_sub_patch_ids": [],
        "ground_truth_label": record.get("ground_truth_label"),
    }


def decompose_normalized_record(record, commit_payload=None):
    payload = commit_payload or {"commit_message": record.get("commit_message", ""), "files": []}
    commit_message = payload.get("commit_message", record.get("commit_message", ""))
    sub_patches = []
    for file_payload in payload.get("files", []):
        file_name = file_payload.get("filename", "")
        hunks = parse_patch_hunks(file_payload.get("patch", ""))
        functions = relevant_functions_for_file(record, file_name)
        matched_hunk_ids = set()
        for function in functions:
            function_range = parse_location_range(function.get("location"))
            matched_hunks = []
            for index, hunk in enumerate(hunks):
                if line_overlap(function_range, hunk["line_span"]):
                    matched_hunks.append(hunk)
                    matched_hunk_ids.add(index)
            if matched_hunks:
                sub_patches.append(build_function_sub_patch(record, function, commit_message, matched_hunks))
        for index, hunk in enumerate(hunks):
            if index not in matched_hunk_ids:
                sub_patches.append(build_synthetic_sub_patch(record, file_name, hunk, index, commit_message))
    sub_patch_ids = [sub_patch["sub_patch_id"] for sub_patch in sub_patches]
    for sub_patch in sub_patches:
        sub_patch["peer_sub_patch_ids"] = [peer_id for peer_id in sub_patch_ids if peer_id != sub_patch["sub_patch_id"]]
    return sub_patches
