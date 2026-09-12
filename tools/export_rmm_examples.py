#!/usr/bin/env python3
"""Export authoritative Project_Mati metadata into NorthGate RMM examples."""
import argparse
import json
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("rmm_root", type=Path)
    args = parser.parse_args()
    manifest = json.loads((ROOT / "wazuh/project-mati-detections.json").read_text(encoding="utf-8"))["detections"]

    connector_path = args.rmm_root / "deploy/wazuh/connector.example.json"
    connector = json.loads(connector_path.read_text(encoding="utf-8"))
    connector["detections"] = {rule: {"context_fields": item["context_fields"]} for rule, item in manifest.items()}
    write_json(connector_path, connector)

    source_path = args.rmm_root / "deploy/wazuh/rmm-source.example.json"
    registry = json.loads(source_path.read_text(encoding="utf-8"))
    source = registry["sources"][0]
    allowed = ("id", "version", "severity", "attack", "context_fields", "checklist")
    source["detections"] = {rule: {key: item[key] for key in allowed} for rule, item in manifest.items()}
    windows = defaultdict(list)
    for rule, item in manifest.items():
        windows[item["window_seconds"]].append(rule)
    source["case_policies"] = [
        {
            "id": f"project-mati-soc-{window}-v1",
            "enabled": True,
            "rule_ids": rules,
            "minimum_level": 10,
            "group_by": ["endpoint", "detection_id"],
            "window_seconds": window,
            "closed_behavior": "new_case",
            "owner": "SOC",
            "team": "SOC",
            "tags": ["automatic", "wazuh", "project-mati"],
        }
        for window, rules in sorted(windows.items())
    ]
    write_json(source_path, registry)
    print(json.dumps({"detections": len(manifest), "policy_windows": sorted(windows), "rmm_root": str(args.rmm_root)}))


if __name__ == "__main__":
    main()
