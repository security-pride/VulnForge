import json
import pickle
from pathlib import Path


def ensure_parent_dir(path):
    Path(path).parent.mkdir(parents=True, exist_ok=True)


def read_jsonl(path):
    records = []
    target = Path(path)
    if not target.exists():
        return records
    with target.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


def write_jsonl(path, records):
    ensure_parent_dir(path)
    with Path(path).open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")


def append_jsonl(path, record):
    ensure_parent_dir(path)
    with Path(path).open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, ensure_ascii=False) + "\n")


def read_json(path):
    target = Path(path)
    if not target.exists():
        return None
    with target.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def write_json(path, payload):
    ensure_parent_dir(path)
    with Path(path).open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, ensure_ascii=False, indent=2)


def load_pickle_records(path):
    records = []
    target = Path(path)
    if not target.exists():
        return records
    with target.open("rb") as handle:
        while True:
            try:
                records.append(pickle.load(handle))
            except EOFError:
                break
    return records


def load_records(path):
    suffix = Path(path).suffix.lower()
    if suffix == ".jsonl":
        return read_jsonl(path)
    if suffix == ".json":
        payload = read_json(path)
        if payload is None:
            return []
        if isinstance(payload, list):
            return payload
        return [payload]
    if suffix in {".pickle", ".pkl"}:
        return load_pickle_records(path)
    return []
