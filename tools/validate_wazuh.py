#!/usr/bin/env python3
"""Validate manifest/XML consistency and Project_Mati positive/negative fixtures."""
import json
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def detections(fields, decoder="windows_eventchannel"):
    result = []
    event = str(fields.get("win.system.eventID", ""))
    image = str(fields.get("win.eventdata.newProcessName", ""))
    command = str(fields.get("win.eventdata.commandLine", ""))
    if event == "4688" and re.search(r"\\(?:powershell|pwsh)\.exe$", image, re.I):
        if re.search(r"(?:^|\s)-(?:enc|encodedcommand)(?:\s|$)|DownloadString.{0,512}(?:Invoke-Expression|IEX)", command, re.I):
            result.append("110101")
        if re.search(r"Set-MpPreference\s+-Disable(?:Realtime|Behavior)Monitoring\s+\$true|(?:Add|Set)-MpPreference\s+-ExclusionPath\s+C:\\(?:\s|$)", command, re.I):
            result.append("110121")
    service = str(fields.get("win.eventdata.serviceFileName", ""))
    if event == "7045" and re.search(r"\\(?:Users\\Public|AppData\\Local\\Temp|Windows\\Temp|ADMIN\$)\\|\\(?:powershell|cmd|rundll32)\.exe(?:\s|$)", service, re.I):
        result.append("110111")
    sudo = str(fields.get("command", ""))
    if decoder == "sudo" and fields.get("dstuser") == "root" and re.search(r"(?:^|\s)(?:/bin/(?:ba)?sh|/usr/bin/dash)(?:\s|$)|/usr/bin/(?:chmod\s+u\+s|chown\s+root)(?:\s|$)", sudo, re.I):
        result.append("110131")
    return result


def main():
    xml = ROOT / "wazuh/rules/110-project-mati.xml"
    tree = ET.parse(xml)
    ids = {node.attrib["id"] for node in tree.findall(".//rule") if int(node.attrib["level"]) > 0}
    manifest = json.loads((ROOT / "wazuh/project-mati-detections.json").read_text())
    if ids != set(manifest["detections"]):
        raise SystemExit(f"manifest/XML mismatch: {sorted(ids ^ set(manifest['detections']))}")
    cases = json.loads((ROOT / "wazuh/fixtures/cases.json").read_text())
    failures = []
    for case in cases:
        actual = detections(case["fields"], case.get("decoder", "windows_eventchannel"))
        expected = [] if case["expect"] is None else [case["expect"]]
        if actual != expected:
            failures.append({"name": case["name"], "expected": expected, "actual": actual})
    print(json.dumps({"fixtures": len(cases), "passed": len(cases) - len(failures), "failures": failures}, indent=2))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
