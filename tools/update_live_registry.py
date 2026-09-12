#!/usr/bin/env python3
"""Atomically merge Project_Mati metadata into a live connector or RMM registry."""
import argparse
import hashlib
import json
import os
import tempfile
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID


def binding(value):
    agent, endpoint, identity = value.split(":", 2)
    if not agent.isdigit():
        raise argparse.ArgumentTypeError("agent ID must be numeric")
    UUID(endpoint)
    UUID(identity)
    return agent, {"endpoint": endpoint, "identity": identity}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--kind", required=True, choices=("connector", "rmm"))
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--binding", action="append", default=[], type=binding)
    args = parser.parse_args()

    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))["detections"]
    original = args.config.read_bytes()
    value = json.loads(original)
    bindings = dict(args.binding)
    if args.kind == "connector":
        value["detections"] = {rule: {"context_fields": item["context_fields"]} for rule, item in manifest.items()}
        value.setdefault("agents", {}).update(bindings)
        policy_count = 0
    else:
        sources = value.get("sources", [])
        if not isinstance(sources, list) or len(sources) != 1 or not isinstance(sources[0], dict):
            raise SystemExit("expected exactly one configured Wazuh source")
        source = sources[0]
        allowed = ("id", "version", "severity", "attack", "context_fields", "checklist")
        source["detections"] = {rule: {key: item[key] for key in allowed} for rule, item in manifest.items()}
        source.setdefault("agents", {}).update(bindings)
        windows = defaultdict(list)
        for rule, item in manifest.items():
            windows[item["window_seconds"]].append(rule)
        source["case_policies"] = [
            {"id": f"project-mati-soc-{window}-v1", "enabled": True, "rule_ids": rules,
             "minimum_level": 10, "group_by": ["endpoint", "detection_id"],
             "window_seconds": window, "closed_behavior": "new_case", "owner": "SOC",
             "team": "SOC", "tags": ["automatic", "wazuh", "project-mati"]}
            for window, rules in sorted(windows.items())
        ]
        policy_count = len(source["case_policies"])

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup = args.config.with_name(args.config.name + ".project-mati-backup-" + stamp)
    fd = os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(original)
        stream.flush()
        os.fsync(stream.fileno())
    info = args.config.stat()
    encoded = (json.dumps(value, indent=2) + "\n").encode()
    with tempfile.NamedTemporaryFile(dir=args.config.parent, delete=False) as stream:
        temporary = Path(stream.name)
        stream.write(encoded)
        stream.flush()
        os.fsync(stream.fileno())
    os.chmod(temporary, info.st_mode & 0o777)
    os.chown(temporary, info.st_uid, info.st_gid)
    os.replace(temporary, args.config)
    print(json.dumps({"kind": args.kind, "detections": len(manifest), "policies": policy_count,
                      "bindings_added": sorted(bindings), "backup": str(backup),
                      "sha256": hashlib.sha256(encoded).hexdigest()}))


if __name__ == "__main__":
    main()
