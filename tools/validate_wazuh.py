#!/usr/bin/env python3
"""Validate manifest/XML consistency and Project_Mati positive/negative fixtures."""
import json
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def matches(fields, decoder="windows_eventchannel", repeat=1):
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
    if decoder == "sudo" and fields.get("dstuser") == "root" and str(fields.get("srcuser", "")).casefold() not in {"northgate-mcp", "northgate-bootstrap"} and re.search(r"(?:^|\s)(?:/bin/(?:ba)?sh|/usr/bin/dash)(?:\s|$)|/usr/bin/(?:chmod\s+u\+s|chown\s+root)(?:\s|$)", sudo, re.I):
        result.append("110131")

    method = str(fields.get("request.method", ""))
    source = str(fields.get("request.remote_ip", ""))
    uri = str(fields.get("request.uri", ""))
    status = str(fields.get("status", ""))
    tls = str(fields.get("request.tls.version", ""))
    web = decoder == "json" and bool(source) and re.fullmatch(r"GET|HEAD|OPTIONS|POST|PUT|PATCH|DELETE", method, re.I)
    if web:
        if re.search(r"(?:^|/)(?:\.env(?:\.|/|$)|\.git(?:/|$)|wp-config\.php(?:$|\?)|server-status(?:$|\?)|actuator/(?:env|heapdump)|WEB-INF/web\.xml|\.aws/credentials)", uri, re.I):
            result.append("110201")
        if repeat >= 6 and re.search(r"^/(?:admin|administrator|manage|management|internal|api/(?:admin|management|internal))(?:/|$|\?)", uri, re.I) and status in {"401", "403", "404"}:
            result.append("110203")
        if re.search(r"^/(?:login|signin|auth|oauth|token|session|admin|api/(?:auth|token|session|admin))(?:/|$|\?)", uri, re.I) and tls in {"769", "770", "TLSv1", "TLSv1.1"}:
            result.append("110204")
        injection = re.search(r"\bunion(?:%20|\+|\s)+select\b|(?:%27|'|%22|\")(?:%20|\+|\s)*(?:or|and)(?:%20|\+|\s)+(?:1=1|true)\b|(?:\.\./|%2e%2e(?:%2f|/))|(?:;|%3b)(?:%20|\+|\s)*(?:cat|id|whoami|curl|wget)(?:%20|\+|\s)|(?:%3c|<)script(?:%3e|>)", uri, re.I)
        if injection:
            result.append("110205")
        privileged = method.upper() in {"POST", "PUT", "PATCH", "DELETE"} and re.search(r"^/(?:admin|api/admin|api/(?:bulk|export|import|reset|users|roles|permissions))(?:/|$|\?)", uri, re.I) and re.fullmatch(r"2\d\d", status)
        if repeat >= 20 and privileged:
            result.append("110207")
        auth = re.search(r"^/(?:login|signin|auth|oauth|token|session|api/(?:auth|token|session))(?:/|$|\?)", uri, re.I) and status in {"401", "403"}
        if repeat >= 6 and auth:
            result.append("110209")
        if repeat >= 5 and re.fullmatch(r"5\d\d", status):
            result.append("110211")

    if decoder == "sysmon-linux" and str(fields.get("system.eventId", "")) == "11":
        sys_image = str(fields.get("eventdata.image", ""))
        target = str(fields.get("eventdata.targetFilename", ""))
        if re.search(r"^/(?:opt|srv|var/www|rmm/api)/.+/(?:package(?:-lock)?\.json|requirements(?:-[^/]+)?\.txt|poetry\.lock|Pipfile(?:\.lock)?|Gemfile(?:\.lock)?|composer\.(?:json|lock)|go\.(?:mod|sum)|Cargo\.(?:toml|lock)|vendor/|node_modules/)", target, re.I) and re.search(r"/(?:curl|wget|npm|npx|yarn|pnpm|pip|pip3|poetry|gem|bundle|composer|go|cargo|bash|sh|python3?|node)$", sys_image, re.I):
            result.append("110221")
        if re.search(r"^/(?:etc/(?:nginx|caddy|wazuh-agent)|opt|srv|var/www|rmm/api)/(?!.*(?:access[_-]?log|error[_-]?log|logrotate|ossec|sysmon)).*(?:auth|oauth|session|permission|role|access|middleware|security|policy|caddy|nginx).*$", target, re.I) and re.search(r"/(?:bash|sh|dash|zsh|vi|vim|nano|sed|perl|python3?|node|curl|wget|cp|mv|install|tee)$", sys_image, re.I):
            result.append("110222")
        if re.search(r"^/(?:etc/(?:rsyslog|logrotate|wazuh-agent|sysmon)|var/ossec/etc|etc/(?:nginx|caddy))/.*(?:log|ossec|sysmon).*$", target, re.I) and re.search(r"/(?:bash|sh|dash|zsh|vi|vim|nano|sed|perl|python3?|cp|mv|install|tee|truncate)$", sys_image, re.I):
            result.append("110223")
    if decoder == "json" and fields.get("project_mati.event") == "web_log_health" and fields.get("healthy") is False:
        result.append("110230")
    return result


def main():
    rule_path = ROOT / "wazuh/rules/110-project-mati.xml"
    tree = ET.parse(rule_path)
    deployable = {}
    for node in tree.findall(".//rule"):
        description = node.findtext("description", "")
        if description.startswith("PM-"):
            deployable[node.attrib["id"]] = int(node.attrib["level"])
    manifest = json.loads((ROOT / "wazuh/project-mati-detections.json").read_text())
    manifest_ids = set(manifest["detections"])
    if set(deployable) != manifest_ids:
        raise SystemExit(f"manifest/XML mismatch: {sorted(set(deployable) ^ manifest_ids)}")
    low = {rule_id: level for rule_id, level in deployable.items() if level < 10}
    if low:
        raise SystemExit(f"case detection below Wazuh level 10: {low}")
    owasp = {item.get("owasp", "").split(":", 1)[0] for item in manifest["detections"].values() if item.get("owasp")}
    expected_owasp = {f"A{i:02d}" for i in range(1, 11)}
    if owasp != expected_owasp:
        raise SystemExit(f"OWASP coverage mismatch: {sorted(owasp ^ expected_owasp)}")
    decoder_text = (ROOT / "wazuh/decoders/110-project-mati-sysmon-linux.xml").read_text()
    ET.fromstring(f"<root>{decoder_text}</root>")
    ET.parse(ROOT / "wazuh/config/sysmon-linux-web.xml")

    cases = json.loads((ROOT / "wazuh/fixtures/cases.json").read_text())
    failures = []
    for case in cases:
        actual = matches(case["fields"], case.get("decoder", "windows_eventchannel"), case.get("repeat", 1))
        expected = [] if case["expect"] is None else [case["expect"]]
        if actual != expected:
            failures.append({"name": case["name"], "expected": expected, "actual": actual})
    print(json.dumps({"fixtures": len(cases), "passed": len(cases) - len(failures), "owasp_categories": len(owasp), "deployable_rule_ids": sorted(deployable), "failures": failures}, indent=2))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
