# Website detection deployment

## Log contract

Rules consume `request.remote_ip`, `request.method`, `request.uri`, `request.host`, optional `request.proto` and `request.tls.version`, plus `status`, `duration` and optional `user_id`. Caddy already emits this nested JSON shape. For nginx, define an escaped JSON format in `http` and enable it only in application `server` blocks:

```nginx
log_format project_mati escape=json '{"ts":"$time_iso8601","request":{"remote_ip":"$remote_addr","method":"$request_method","uri":"$request_uri","host":"$host","proto":"$server_protocol","tls":{"version":"$ssl_protocol"}},"status":$status,"duration":$request_time,"size":$body_bytes_sent,"user_id":"$remote_user"}';
access_log /var/log/nginx/project-mati-access.json project_mati;
```

Do not log bodies, cookies, authorization headers or client certificates. Applications must not place secrets in URLs. `$request_uri` retains path/query for analysis, so raw Wazuh access remains restricted.

Agent collection:

```xml
<localfile><location>/var/log/nginx/project-mati-access.json</location><log_format>json</log_format></localfile>
<localfile><location>/var/log/project-mati/web-health.jsonl</location><log_format>json</log_format></localfile>
```

Sysmon for Linux normally reaches Wazuh through journal/syslog and the Project_Mati manager decoder.

## Sysmon scope and rollout

`wazuh/config/sysmon-linux-web.xml` is narrow: children of named website runtimes, file creation under app/security paths, and connections from common transfer tools. It explicitly disables ProcessTerminate because Linux Sysmon otherwise emitted thousands of low-value Event ID 5 records during canary testing. It uses SHA-256 and captures no file contents, request bodies, credentials or deleted-file archives. Validate its schema against installed `sysmon -s` before applying. Sysmon 1.5.3 on the Debian 12 canary segfaulted when the documented `FieldSizes` element was present, so this release relies on narrow filters and does not claim an event-size cap; monitor journal/Wazuh truncation and retest the cap after a fixed upstream release.

Install only official Microsoft Sysmon for Linux and SysinternalsEBPF release packages, verify their published version and a locally approved SHA-256 before installation, and satisfy package dependencies such as Debian's `libjson-glib-1.0-0`. Back up exact Wazuh/web/Sysmon configuration, validate `nginx -t` or `caddy validate`, load Sysmon configuration, and restart only affected services.

Keep the vendor `sysmon.service` disabled at boot and enable `project-mati-sysmon-start.timer`. The timer starts Sysmon two minutes after boot, disables the vendor boot link again after a successful start, and rechecks every 15 minutes. This avoids an observed Debian/Hyper-V cold-boot failure where the eBPF perf buffer returned `ENOMEM` while the dynamic-memory VM still had only its 1 GiB startup allocation. The affected four-vCPU canary required a 2 GiB minimum/startup allocation; establish a measured host-specific minimum instead of assuming that value for every server. `project-mati-web-log-health` reports `sysmon_inactive` if delayed startup does not succeed.

Canary gates: validate rules/decoders with `wazuh-analysisd -t`; confirm web and Wazuh health; generate a harmless nonexistent sensitive-file request and temporary test-path Sysmon event; confirm Wazuh alert and automatic RMM case; replay identical delivery and prove no second case; promote one host at a time. Management UIs and non-application hosts are not implicit website targets.
