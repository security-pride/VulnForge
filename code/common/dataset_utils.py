import json
import re
from urllib.parse import urlparse


def coalesce(*values):
    for value in values:
        if value is None:
            continue
        if isinstance(value, str) and value == "":
            continue
        if isinstance(value, (list, dict, tuple)) and len(value) == 0:
            continue
        if isinstance(value, set) and len(value) == 0:
            continue
        return value
    return None


def stringify(value):
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return json.dumps(value, ensure_ascii=False)


def ensure_list(value):
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def extract_repo_name(commit_url):
    if not commit_url or "github.com" not in commit_url:
        return ""
    parsed = urlparse(commit_url)
    segments = [segment for segment in parsed.path.split("/") if segment]
    if len(segments) >= 2:
        return "/".join(segments[:2])
    return ""


def extract_commit_hash(commit_url, fallback=None):
    if commit_url and "/commit/" in commit_url:
        return commit_url.rstrip("/").split("/commit/")[-1]
    return fallback or ""


def parse_location_range(location):
    if not location:
        return None, None
    match = re.match(r"(\d+):\d+\s*-\s*(\d+):\d+", str(location))
    if not match:
        return None, None
    return int(match.group(1)), int(match.group(2))


def parse_patch_hunks(patch_text):
    if not patch_text:
        return []
    hunks = []
    current = None
    for line in patch_text.splitlines():
        header = re.match(r"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@", line)
        if header:
            if current is not None:
                hunks.append(current)
            current = {
                "header": line,
                "old_start": int(header.group(1)),
                "old_count": int(header.group(2) or "1"),
                "new_start": int(header.group(3)),
                "new_count": int(header.group(4) or "1"),
                "lines": [line],
            }
            continue
        if current is not None:
            current["lines"].append(line)
    if current is not None:
        hunks.append(current)
    for hunk in hunks:
        hunk["patch"] = "\n".join(hunk["lines"])
        old_end = hunk["old_start"] + max(hunk["old_count"], 1) - 1
        new_end = hunk["new_start"] + max(hunk["new_count"], 1) - 1
        hunk["line_span"] = (min(hunk["old_start"], hunk["new_start"]), max(old_end, new_end))
    return hunks


def line_overlap(left, right):
    if left[0] is None or right[0] is None:
        return False
    return max(left[0], right[0]) <= min(left[1], right[1])


def normalize_function_entry(function_id, payload):
    return {
        "function_id": str(function_id),
        "name": coalesce(payload.get("name"), payload.get("function_name"), payload.get("func_name"), "unknown_function"),
        "file_path": coalesce(payload.get("file"), payload.get("file_path"), payload.get("filename"), ""),
        "location": coalesce(payload.get("loc"), payload.get("location"), payload.get("func_loc"), ""),
        "pre_patch_function": coalesce(payload.get("code"), payload.get("func"), payload.get("before"), payload.get("vulnerable"), payload.get("pre_patch_function"), ""),
        "post_patch_function": coalesce(payload.get("after"), payload.get("fixed"), payload.get("safe"), payload.get("post_patch_function"), payload.get("code_after"), ""),
        "touched_by_commit": bool(coalesce(payload.get("touched_by_commit"), True)),
    }


def normalize_bigvul_record(item):
    commit_url = coalesce(item.get("commit_url"), item.get("url"), item.get("html_url"), "")
    function_payload = {
        "name": coalesce(item.get("func_name"), item.get("function_name"), item.get("function"), "unknown_function"),
        "file_path": coalesce(item.get("file_path"), item.get("file"), item.get("filename"), ""),
        "location": coalesce(item.get("loc"), item.get("location"), ""),
        "pre_patch_function": coalesce(item.get("func_before"), item.get("before"), item.get("code"), item.get("vulnerable_code"), ""),
        "post_patch_function": coalesce(item.get("func_after"), item.get("after"), item.get("patched_code"), item.get("fixed_code"), ""),
        "touched_by_commit": True,
    }
    return {
        "dataset": "bigvul",
        "sample_id": str(coalesce(item.get("id"), item.get("_id"), item.get("sample_id"), "")),
        "cve_id": coalesce(item.get("cve_id"), item.get("cve"), ""),
        "description": coalesce(item.get("vulnerability_description"), item.get("description"), item.get("bug_info"), ""),
        "cwe_list": ensure_list(coalesce(item.get("cwe_list"), item.get("cwe"), item.get("cwe_id"), [])),
        "commit_url": commit_url,
        "commit_hash": extract_commit_hash(commit_url, coalesce(item.get("commit_id"), item.get("hash"), "")),
        "commit_message": coalesce(item.get("commit_message"), item.get("message"), ""),
        "repo_name": coalesce(item.get("repo_name"), item.get("project"), extract_repo_name(commit_url)),
        "references": ensure_list(coalesce(item.get("references"), item.get("reference"), [])),
        "functions": [normalize_function_entry(coalesce(item.get("function_id"), "func-1"), function_payload)],
        "raw_record": item,
    }


def normalize_d2a_record(item):
    commit_url = coalesce(item.get("commit", {}).get("url"), item.get("commit_url"), "")
    functions = []
    for function_id, payload in item.get("functions", {}).items():
        functions.append(normalize_function_entry(function_id, payload))
    return {
        "dataset": "d2a",
        "sample_id": str(coalesce(item.get("id"), item.get("sample_id"), "")),
        "cve_id": coalesce(item.get("cve_id"), item.get("cve"), ""),
        "description": " ".join(
            [part for part in [coalesce(item.get("bug_type"), ""), coalesce(item.get("bug_info", {}).get("qualifier"), "")] if part]
        ).strip(),
        "cwe_list": ensure_list(coalesce(item.get("cwe_list"), item.get("cwe"), [])),
        "commit_url": commit_url,
        "commit_hash": extract_commit_hash(commit_url, coalesce(item.get("hash"), "")),
        "commit_message": coalesce(item.get("commit_message"), item.get("message"), ""),
        "repo_name": coalesce(item.get("repo_name"), extract_repo_name(commit_url)),
        "references": ensure_list(coalesce(item.get("references"), item.get("bug_info", {}).get("url"), [])),
        "functions": functions,
        "raw_record": item,
    }


def normalize_diversevul_record(item):
    commit_url = coalesce(item.get("commit_url"), item.get("url"), "")
    function_payload = {
        "name": coalesce(item.get("func_name"), item.get("function_name"), "unknown_function"),
        "file_path": coalesce(item.get("file_path"), item.get("file"), item.get("filename"), ""),
        "location": coalesce(item.get("loc"), item.get("location"), ""),
        "pre_patch_function": coalesce(item.get("func"), item.get("code"), ""),
        "post_patch_function": coalesce(item.get("func_after"), item.get("after"), ""),
        "touched_by_commit": True,
    }
    return {
        "dataset": "diversevul",
        "sample_id": str(coalesce(item.get("id"), item.get("sample_id"), "")),
        "cve_id": coalesce(item.get("cve_id"), item.get("cve"), ""),
        "description": coalesce(item.get("bug_info"), item.get("description"), ""),
        "cwe_list": ensure_list(coalesce(item.get("cwe"), item.get("cwe_list"), [])),
        "commit_url": commit_url,
        "commit_hash": extract_commit_hash(commit_url, coalesce(item.get("hash"), "")),
        "commit_message": coalesce(item.get("message"), item.get("commit_message"), ""),
        "repo_name": coalesce(item.get("repo_name"), extract_repo_name(commit_url)),
        "references": ensure_list(coalesce(item.get("references"), [])),
        "functions": [normalize_function_entry(coalesce(item.get("function_id"), "func-1"), function_payload)],
        "raw_record": item,
    }


def normalize_reposvul_record(item):
    commit_url = coalesce(item.get("html_url"), item.get("commit_url"), "")
    details = ensure_list(item.get("details"))
    functions = []
    if details:
        for index, payload in enumerate(details, start=1):
            functions.append(normalize_function_entry(f"func-{index}", payload))
    else:
        functions.append(
            normalize_function_entry(
                "func-1",
                {
                    "name": coalesce(item.get("func_name"), "unknown_function"),
                    "file_path": coalesce(item.get("file_path"), item.get("file"), ""),
                    "location": coalesce(item.get("loc"), ""),
                    "pre_patch_function": coalesce(item.get("code"), ""),
                    "post_patch_function": coalesce(item.get("after"), ""),
                    "touched_by_commit": True,
                },
            )
        )
    return {
        "dataset": "reposvul",
        "sample_id": str(coalesce(item.get("id"), item.get("sample_id"), "")),
        "cve_id": coalesce(item.get("cve_id"), item.get("cve"), ""),
        "description": coalesce(item.get("cve_description"), item.get("description"), ""),
        "cwe_list": ensure_list(coalesce(item.get("cwe_id"), item.get("cwe"), [])),
        "commit_url": commit_url,
        "commit_hash": extract_commit_hash(commit_url, coalesce(item.get("hash"), "")),
        "commit_message": coalesce(item.get("commit_message"), item.get("message"), ""),
        "repo_name": coalesce(item.get("repo_name"), extract_repo_name(commit_url)),
        "references": ensure_list(coalesce(item.get("references"), [])),
        "functions": functions,
        "raw_record": item,
    }


def normalize_dataset_record(dataset_name, item):
    normalized_name = str(dataset_name).strip().lower()
    if normalized_name == "bigvul":
        return normalize_bigvul_record(item)
    if normalized_name == "d2a":
        return normalize_d2a_record(item)
    if normalized_name == "diversevul":
        return normalize_diversevul_record(item)
    if normalized_name == "reposvul":
        return normalize_reposvul_record(item)
    raise ValueError(f"Unsupported dataset: {dataset_name}")
