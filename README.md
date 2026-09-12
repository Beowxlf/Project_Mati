# Project_Mati

Project_Mati is the authoritative detection source for the NorthGate Wazuh-to-case workflow. Reviewed Sigma intent is under `rules/`; deployable Wazuh XML, the detection manifest, and validation fixtures are under `wazuh/`. See `docs/Detections.md` for telemetry, ATT&CK, false-positive, tuning, and investigation guidance.

**Project_Mati** is a detection engineering repository that combines Sigma detection rules, adversary simulation labs, and structured technical notes. The goal is to develop comprehensive detection capabilities mapped to the MITRE ATT&CK framework, supported by deep technical knowledge of Windows internals, network protocols, and logging systems.

---

## **Repository Overview**

| Folder/File | Description |
|-------------|-------------|
| `/rules/` | Sigma detection rules categorized by operating system (Windows, Linux, Cloud). |
| `/labs/` | Lab simulations demonstrating attack techniques and corresponding detection logic. |
| `/docs/` | Guides on Sigma rule writing, SIEM pipelines, and detection engineering practices. |
| `/lesson_sets/` | Deep-dive technical notes covering critical cybersecurity and detection concepts. |
| `/tools/config/` | Sigma configuration files for backends like Wazuh, Splunk, and Elastic. |

---

## **Lesson Sets**

Extensive technical notes that build foundational and advanced knowledge essential for SOC analysts and detection engineers:

- **SMB & File Sharing**: Covers SMB protocol, NTFS permissions, share permissions, mapping drives, and detection use cases like NTLM Relay and file access abuse.
- **Windows Networking Stack**: Includes OSI model, IP addressing, ARP, DNS resolution, Windows firewall, and diagnostic tools.
- **DNS Records**: Deep dive into DNS record types and their security implications.
- **Windows Event Logs**: Explains Event ID taxonomy, Sysmon configurations, Kerberos logs, DC Sync attacks, and relevant Sigma rules.
- **Windows Internals**: Explores boot processes, Windows processes/threads, handles/tokens, registry persistence, DLL injection, AV logs, WMI, and key Event IDs for detection.
- **Windows Kernel**: Examines kernel architecture, syscall tables, ETW, PatchGuard, and detection of kernel-level attack techniques like DKOM.

These notes provide the detection rationale that informs Sigma rule development and SIEM-based detection pipelines.

---

## **Current Sigma Rules**

| Rule File | Description | MITRE ATT&CK |
|-----------|-------------|--------------|
| `suspicious_powershell.yml` | Detects use of PowerShell EncodedCommand flag. | T1059.001 |
| `service_creation.yml` | Identifies suspicious Windows service creation. | T1543.003 |
| `defender_bypass.yml` | Detects command-line Defender bypass attempts. | T1562.001 |

---

## **Lab Simulations**

- **Encoded PowerShell Command**: Obfuscation detection via Sysmon.
- **HoneyUser Detection**: Trap-based detection for unauthorized account enumeration.

Detailed PDFs are available in the `/labs/` directory, documenting step-by-step simulations and detection strategies.

---

## **Documentation**

- **Rule-Writing Guide**: Process for developing effective Sigma rules.
- **SIEM Pipeline Guide**: End-to-end data flow from log collection to alerting and SOAR integration.

---

## **Author**

Brayden Thompson  
[LinkedIn](https://www.linkedin.com/in/brayden-thompson-093238214) | [GitHub](https://github.com/Beowxlf)

> **Stay Watchful. Find What Hides. Defend What Matters.**
