import json
import os
import subprocess
import sys
from pathlib import Path

from include_retrieve import get_all_files
from patch_analyzer import analyze_patch

CODE_DIR = Path(__file__).resolve().parents[1]
if str(CODE_DIR) not in sys.path:
    sys.path.insert(0, str(CODE_DIR))

from common.io_utils import append_jsonl, load_records

INPUT_PATH = "xxx"
OUTPUT_PATH = "xxx"
REPO_ROOT = "xxx"
CPG_OUTPUT_DIR = "xxx"
TEMP_CONTEXT_DIR = "xxx"


def get_parent_commit(repo_path, commit_hash):
    result = subprocess.run(
        ["git", "rev-parse", f"{commit_hash}^"],
        capture_output=True,
        text=True,
        cwd=repo_path,
        check=True,
    )
    return result.stdout.strip()


def checkout_commit(repo_path, commit_hash):
    subprocess.run(["git", "checkout", commit_hash, "-f"], cwd=repo_path, check=True)


def create_exclude_regex(repo_path, file_path, changed_methods):
    reachable_files = get_all_files(repo_path, os.path.join(repo_path, file_path), changed_methods)
    reachable_relative_paths = sorted({os.path.relpath(path, repo_path) for path in reachable_files})
    if not reachable_relative_paths:
        return r".*\.nomatch$"
    return f"^(?!({'|'.join(reachable_relative_paths)})$).*\\.(c|h)$"


def map_line_numbers(file_patches, file_path, visited_lines, version):
    patch = file_patches.get(file_path, {"del_lines": [], "add_lines": []})
    deleted_lines = sorted({int(line) for line in patch.get("del_lines", [])})
    added_lines = sorted({int(line) for line in patch.get("add_lines", [])})
    mapped_lines = []
    for line in visited_lines:
        if version == "before" and line in deleted_lines:
            continue
        if version == "after" and line in added_lines:
            continue
        if version == "before":
            offset = -sum(1 for deleted in deleted_lines if deleted < line) + sum(1 for added in added_lines if added < line)
            mapped_lines.append(line + offset)
        else:
            offset = sum(1 for added in added_lines if added < line) - sum(1 for deleted in deleted_lines if deleted < line)
            mapped_lines.append(line - offset)
    return mapped_lines


def collect_changed_methods(script_dir, repo_path, file_patches, parent_hash, commit_hash, cpg_output_dir):
    changed_methods = {}
    for version, version_hash in (("before", parent_hash), ("after", commit_hash)):
        checkout_commit(repo_path, version_hash)
        for file_path, patch_payload in file_patches.items():
            line_numbers = patch_payload["del_lines"] if version == "before" else patch_payload["add_lines"]
            if not line_numbers:
                line_numbers = [0]
            line_numbers_string = ",".join(map(str, sorted(line_numbers)))
            methods_output = Path(cpg_output_dir) / f"methods_{version}_{Path(file_path).name}.txt"
            subprocess.run(
                [
                    "joern",
                    "--script",
                    str(script_dir / "get_methods.scala"),
                    "--param",
                    f"codeFile={os.path.join(repo_path, file_path)}",
                    "--param",
                    f"outFile={methods_output}",
                    "--param",
                    f"lineNumbers={line_numbers_string}",
                ],
                check=True,
                cwd=script_dir,
            )
            if methods_output.exists():
                with methods_output.open("r", encoding="utf-8") as handle:
                    for line in handle:
                        method_info = line.strip().split()
                        if not method_info:
                            continue
                        changed_methods.setdefault(file_path, set()).add(method_info[0])
                methods_output.unlink()
    return changed_methods


def merge_context_payloads(contexts, file_patches):
    final_payload = {
        "callee_methods": [],
        "caller_methods": [],
        "type_defs": [],
        "global_vars": [],
        "import_libs": [],
        "vulnerable_methods_pre": contexts["before"]["vulnerableMethods"],
        "vulnerable_methods_post": contexts["after"]["vulnerableMethods"],
        "visited_lines_pre": {},
        "visited_lines_post": {},
        "visited_params": {},
    }
    final_payload["callee_methods"] = [list(item) for item in {tuple(item) for item in contexts["before"]["calleeMethods"] + contexts["after"]["calleeMethods"]}]
    final_payload["caller_methods"] = [list(item) for item in {tuple(item) for item in contexts["before"]["callerMethods"] + contexts["after"]["callerMethods"]}]
    final_payload["type_defs"] = [list(item) for item in {tuple(item) for item in contexts["before"]["typeDefs"] + contexts["after"]["typeDefs"]}]
    final_payload["global_vars"] = sorted(set(contexts["before"]["globalVars"] + contexts["after"]["globalVars"]))
    final_payload["import_libs"] = sorted(set(contexts["before"]["importContext"] + contexts["after"]["importContext"]))

    visited_before = {}
    visited_after = {}
    for line_number, method_name, file_path in contexts["before"]["visitedLines"]:
        visited_before.setdefault(file_path, []).append(line_number)
    for line_number, method_name, file_path in contexts["after"]["visitedLines"]:
        visited_after.setdefault(file_path, []).append(line_number)

    for file_path, lines in visited_before.items():
        final_payload["visited_lines_pre"][file_path] = sorted(set(map_line_numbers(file_patches, file_path, lines, "before") + visited_after.get(file_path, [])))
    for file_path, lines in visited_after.items():
        final_payload["visited_lines_post"][file_path] = sorted(set(map_line_numbers(file_patches, file_path, lines, "after") + visited_before.get(file_path, [])))

    visited_params = {}
    for param, method_name, file_path in contexts["before"]["visitedParams"] + contexts["after"]["visitedParams"]:
        visited_params.setdefault(file_path, set()).add((param, method_name))
    final_payload["visited_params"] = {file_path: sorted(list(values)) for file_path, values in visited_params.items()}
    return final_payload


def build_context_payload(repo_path, commit_hash):
    script_dir = Path(__file__).resolve().parent
    cpg_output_dir = Path(CPG_OUTPUT_DIR)
    temp_context_dir = Path(TEMP_CONTEXT_DIR)
    cpg_output_dir.mkdir(parents=True, exist_ok=True)
    temp_context_dir.mkdir(parents=True, exist_ok=True)
    parent_hash = get_parent_commit(repo_path, commit_hash)
    patches = analyze_patch(repo_path, commit_hash)
    file_patches = {}
    for patch in patches:
        file_patches.setdefault(patch.file_path, {"del_lines": [], "add_lines": []})
        file_patches[patch.file_path]["del_lines"].extend(patch.deleted_lines.keys())
        file_patches[patch.file_path]["add_lines"].extend(patch.added_lines.keys())
    changed_methods = collect_changed_methods(script_dir, repo_path, file_patches, parent_hash, commit_hash, cpg_output_dir)
    if not changed_methods:
        return {}
    contexts = {"before": None, "after": None}
    changed_method_list = sorted({method for methods in changed_methods.values() for method in methods})
    for version, version_hash in (("before", parent_hash), ("after", commit_hash)):
        checkout_commit(repo_path, version_hash)
        cpg_path = cpg_output_dir / f"{Path(repo_path).name}_{version_hash[:8]}.bin"
        generated_files = []
        for file_path in file_patches:
            subprocess.run(
                [
                    "joern-parse",
                    ".",
                    "-o",
                    str(cpg_path),
                    "--language",
                    "C",
                    "--frontend-args",
                    "--exclude-regex",
                    create_exclude_regex(repo_path, file_path, changed_method_list),
                ],
                check=True,
                cwd=repo_path,
            )
        for file_path, methods in changed_methods.items():
            line_numbers = file_patches[file_path]["del_lines"] if version == "before" else file_patches[file_path]["add_lines"]
            if not line_numbers:
                line_numbers = [0]
            line_numbers_string = ",".join(map(str, sorted(line_numbers)))
            output_path = temp_context_dir / f"context_{version}_{Path(file_path).name}.json"
            generated_files.append(output_path)
            subprocess.run(
                [
                    "joern",
                    "--script",
                    str(script_dir / "bfs.scala"),
                    "--param",
                    f'methodnameList={",".join(sorted(methods))}',
                    "--param",
                    f"cpgFile={cpg_path}",
                    "--param",
                    f"outFile={output_path}",
                    "--param",
                    f"filename={file_path}",
                    "--param",
                    f"lineNumbers={line_numbers_string}",
                ],
                check=True,
                cwd=script_dir,
            )
        merged = {
            "calleeMethods": [],
            "callerMethods": [],
            "typeDefs": [],
            "globalVars": [],
            "importContext": [],
            "vulnerableMethods": [],
            "visitedLines": [],
            "visitedParams": [],
        }
        for generated_file in generated_files:
            if generated_file.exists():
                with generated_file.open("r", encoding="utf-8") as handle:
                    payload = json.load(handle)
                for key in merged:
                    merged[key].extend(payload.get(key, []))
                generated_file.unlink()
        contexts[version] = merged
    checkout_commit(repo_path, commit_hash)
    candidate_sub_patches = []
    for patch in patches:
        candidate_sub_patches.append(
            {
                "file_path": patch.file_path,
                "function_name": patch.function_name,
                "deleted_lines": patch.deleted_lines,
                "added_lines": patch.added_lines,
            }
        )
    return {
        "candidate_sub_patches": candidate_sub_patches,
        **merge_context_payloads(contexts, file_patches),
    }


def resolve_repo_path(record):
    repo_path = record.get("repo_path")
    if repo_path:
        return repo_path
    repo_name = record.get("repo_name", "")
    if "/" in repo_name:
        repo_name = repo_name.split("/")[-1]
    return str(Path(REPO_ROOT) / repo_name)


def process_record(record):
    repo_path = resolve_repo_path(record)
    commit_hash = record.get("commit_hash") or record.get("hash") or record.get("commit_id")
    context_payload = build_context_payload(repo_path, commit_hash)
    output_record = {
        "dataset": record.get("dataset"),
        "sample_id": record.get("sample_id") or record.get("id"),
        "cve_id": record.get("cve_id"),
        "commit_group_id": record.get("commit_group_id") or record.get("cve_id") or record.get("sample_id") or record.get("id"),
        "repo_name": record.get("repo_name"),
        "repo_path": repo_path,
        "commit_hash": commit_hash,
        **context_payload,
    }
    append_jsonl(OUTPUT_PATH, output_record)


def main():
    for record in load_records(INPUT_PATH):
        process_record(record)


if __name__ == "__main__":
    main()
