# OWASP Top 10:2025 web detection catalog

OWASP Top 10 is an awareness model, not a promise that runtime monitoring can prove an application safe. These rules detect selected abuse and control-failure signals; secure design, code review, dependency governance, configuration review, and application testing remain required.

All qualifying rules are Wazuh level 10 or higher. Raw access and Sysmon telemetry stays in Wazuh. NorthGate RMM receives only allowlisted investigation fields. Related alerts group by endpoint plus detection ID for the manifest's bounded window; a closed case is not reopened.

## PM-WEB-A01-001 v1.0.0 — repeated restricted-endpoint denials

- Purpose/telemetry: identify access-control discovery or bypass attempts from normalized source, method, URI and response status without treating one denial as malicious.
- Mapping/severity: OWASP A01 Broken Access Control; ATT&CK T1190; high, Wazuh 10. Six 401/403/404 responses to restricted endpoints from one source in 120 seconds.
- False positives/tuning: approved scanners and permission tests. Tune exact sources or application routes after ownership review; do not exclude all administrative traffic.
- Investigate: review denied paths and adjacent successes, identify authenticated identity where available, and verify the control with the application owner.

## PM-WEB-A02-001 v1.0.0 — sensitive configuration probe

- Purpose/telemetry: detect requests for configuration, repository, diagnostic or credential artifacts using normalized URI, status, source and host.
- Mapping/severity: OWASP A02 Security Misconfiguration; ATT&CK T1595.002; high, Wazuh 10.
- False positives/tuning: approved web scanners. Tune exact scanner identity and window, not the filename.
- Investigate: confirm response status/size, verify the object is not exposed, and review surrounding requests.

## PM-WEB-A03-001 v1.0.0 — dependency or release artifact change

- Purpose/telemetry: detect package, download, shell or runtime tools creating dependency/lock artifacts in deployed paths using Sysmon for Linux Event 11.
- Mapping/severity: OWASP A03 Software Supply Chain Failures; ATT&CK T1195.002; high, Wazuh 10.
- False positives/tuning: approved deployments. Tune exact deploy identity, path and change window.
- Investigate: compare file/hash with the trusted repository and lockfile, validate the deployment, and inspect ancestry/outbound connections.

## PM-WEB-A04-001 v1.0.0 — obsolete TLS on a sensitive endpoint

- Purpose/telemetry: detect TLS 1.0/1.1 negotiated for authentication, session, token or administrative paths using access-log TLS version and URI.
- Mapping/severity: OWASP A04 Cryptographic Failures; no forced ATT&CK mapping; critical, Wazuh 12.
- False positives/tuning: documented legacy clients. Prefer removing obsolete protocol support over suppression.
- Investigate: identify listener/client, verify proxy/application policy, and implement approved TLS hardening.

## PM-WEB-A05-001 v1.0.0 — injection or traversal request

- Purpose/telemetry: detect narrow SQL injection, command injection, XSS and path-traversal shapes in URI metadata. Bodies and authorization headers are not collected.
- Mapping/severity: OWASP A05 Injection; ATT&CK T1190; critical, Wazuh 12.
- False positives/tuning: encoded search examples or approved scanners. Tune exact route/source/time after raw-event review.
- Investigate: preserve metadata, inspect adjacent activity and application/database effects, and never replay against live data.

## PM-WEB-A06-001 v1.0.0 — privileged workflow burst

- Purpose/telemetry: surface missing workflow/rate controls using method, route, status, source and timing. Twenty successful privileged/bulk changes in 60 seconds qualify; one does not.
- Mapping/severity: OWASP A06 Insecure Design; ATT&CK T1190; high, Wazuh 10.
- False positives/tuning: approved bulk administration. Tune application route and documented automation identity.
- Investigate: identify actor/objects, verify authorization and intended limits, and escalate design remediation.

## PM-WEB-A07-001 v1.0.0 — repeated authentication failures

- Purpose/telemetry: detect password guessing without alerting on one typo. Six 401/403 results on named auth routes from one source in 120 seconds qualify.
- Mapping/severity: OWASP A07 Authentication Failures; ATT&CK T1110; high, Wazuh 10.
- False positives/tuning: broken clients or shared NAT. Tune route/threshold only after review.
- Investigate: review timing, protected identity logs, targeted accounts and later successes.

## PM-WEB-A08-001 v1.0.0 — security-sensitive code/config change

- Purpose/telemetry: detect interactive, scripting or transfer tools changing auth, authorization, session, middleware or security files through Sysmon for Linux Event 11.
- Mapping/severity: OWASP A08 Software or Data Integrity Failures; ATT&CK T1554; critical, Wazuh 12.
- False positives/tuning: approved releases/emergency fixes. Tune exact deploy identity, path and window.
- Investigate: preserve/hash the file, compare with the trusted source, identify process/user, and verify post-change controls.

## PM-WEB-A09-001 v1.0.0 — logging change or health failure

- Purpose/telemetry: detect logging configuration changes via Sysmon Event 11 and explicit five-minute service/access-log health failures. Quiet periods alone are not failures.
- Mapping/severity: OWASP A09 Security Logging and Alerting Failures; ATT&CK T1562.001; critical, Wazuh 12.
- False positives/tuning: approved logging changes. Tune exact identity/window; do not suppress missing/unreadable-log failures without replacement coverage.
- Investigate: identify the change, verify Wazuh collection/delivery, preserve logs, and restore reviewed configuration if unauthorized.

## PM-WEB-A10-001 v1.0.0 — repeated server errors by source

- Purpose/telemetry: identify sequences producing exceptional responses without treating one 5xx as malicious. Five 5xx responses from one source in 120 seconds qualify.
- Mapping/severity: OWASP A10 Mishandling of Exceptional Conditions; ATT&CK T1499 is contextual; critical, Wazuh 12.
- False positives/tuning: application defects or unhealthy dependencies. Tune a route only after the defect is tracked.
- Investigate: correlate application errors/resource impact, determine fail-open or disclosure behavior, and capture a safe reproduction.

## Validation boundary

Fixtures include a positive and negative for every category. Live acceptance additionally requires decoded field confirmation, a safe canary event, manager validation, automatic case creation/update, and duplicate-delivery proof. Unsafe server errors, obsolete TLS, or state mutation may remain fixture-only; reports must say so.
