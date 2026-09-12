# Project_Mati detection catalog

Project_Mati is the authoritative source. The Sigma files express detection intent; `wazuh/rules/110-project-mati.xml` is the reviewed deployment artifact. Wazuh retains raw endpoint telemetry. NorthGate RMM receives only allowlisted alert context.

No supporting decoder is required for this release: Windows events use Wazuh's `windows_eventchannel` decoder and Linux sudo events use its `sudo` decoder. Field names were checked against the NorthGate canaries before deployment; the Windows rules require Security 4688 command-line auditing and System 7045 collection, while Linux requires auth log collection.

## PM-WIN-PS-001 v1.0.0 — Suspicious PowerShell encoded or download execution

- Purpose: find PowerShell process creation using encoded commands or download-plus-in-memory execution, not ordinary administration.
- Telemetry: Windows Security event 4688; `win.eventdata.newProcessName` and the canary-verified `win.eventdata.commandLine`.
- ATT&CK: T1059.001, PowerShell. Severity: high (Wazuh level 12).
- False positives: approved deployment tooling that intentionally uses encoded PowerShell. Tune by an exact signed parent, service account, or deployment window only after review; do not globally exclude PowerShell.
- Investigate: identify user and parent; decode without execution; review network/child processes; confirm approval.

## PM-WIN-SVC-001 v1.0.0 — Suspicious Windows service image path

- Purpose: find service creation from user-writable, temporary, administrative-share, or proxy-execution paths. A normal 7045 alone does not alert.
- Telemetry: Windows System event 7045; `win.eventdata.serviceFileName`, with service name/account retained when available.
- ATT&CK: T1543.003, Windows Service. Severity: high (Wazuh level 12).
- False positives: a reviewed signed installer that stages a service in Windows Temp. Tune on exact signer/path/package, never all service installation.
- Investigate: verify service/binary; inspect signature and origin; identify installer/account; retain evidence before authorized removal.

## PM-WIN-DEF-001 v1.0.0 — Microsoft Defender protection reduction command

- Purpose: find explicit PowerShell commands disabling Defender protection or adding a drive-wide exclusion. Querying Defender status does not alert.
- Telemetry: Windows Security event 4688 with process command line.
- ATT&CK: T1562.001, Impair Defenses. Severity: critical (Wazuh level 14).
- False positives: approved, time-bounded troubleshooting that is reverted. Tune only on a documented change identity and window.
- Investigate: identify actor/authorization; verify current Defender state; review adjacent execution; restore protection through an approved action if changed.

## PM-LNX-PRIV-001 v1.0.0 — Sudo root shell or privileged ownership change

- Purpose: find sudo starting a root shell or modifying root ownership/setuid state. Routine sudo package work does not alert.
- Telemetry: Linux auth log decoded by Wazuh sudo fields `srcuser`, `dstuser`, and `command`.
- ATT&CK: T1548.003, Sudo and Sudo Caching. Severity: high (Wazuh level 12).
- False positives: approved emergency maintenance that explicitly starts a root shell. Tune by exact approved automation identity and command, not all sudo.
- Investigate: validate user/sudo policy; inspect exact command/PWD; review history and descendants; confirm approval.

## Validation and deployment

Run `python tools/validate_wazuh.py` for repository contract and positive/negative fixtures. Before promotion, use `wazuh-logtest` on the target manager, verify a real canary event's decoded fields, then restart only `wazuh-manager` after `wazuh-analysisd -t` succeeds. The cloud placeholder is intentionally not deployable until representative telemetry exists.
