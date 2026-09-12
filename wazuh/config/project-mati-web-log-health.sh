#!/bin/sh
set -eu

CONFIG_FILE="${PROJECT_MATI_HEALTH_CONFIG:-/etc/project-mati/web-log-health.conf}"
OUTPUT_DIR=/var/log/project-mati
OUTPUT_FILE="$OUTPUT_DIR/web-health.jsonl"

if [ -r "$CONFIG_FILE" ]; then
  # The root-owned file is limited to simple variable assignments.
  . "$CONFIG_FILE"
fi

: "${PROJECT_MATI_SERVER:?PROJECT_MATI_SERVER is required}"
: "${PROJECT_MATI_SERVICE:?PROJECT_MATI_SERVICE is required}"
: "${PROJECT_MATI_ACCESS_LOG:?PROJECT_MATI_ACCESS_LOG is required}"
: "${PROJECT_MATI_SYSMON_SERVICE:=sysmon}"

healthy=true
reason=ok
if ! systemctl is-active --quiet "$PROJECT_MATI_SERVICE"; then
  healthy=false
  reason=service_inactive
elif ! systemctl is-active --quiet "$PROJECT_MATI_SYSMON_SERVICE"; then
  healthy=false
  reason=sysmon_inactive
elif [ -L "$PROJECT_MATI_ACCESS_LOG" ]; then
  healthy=false
  reason=access_log_is_symlink
elif [ ! -f "$PROJECT_MATI_ACCESS_LOG" ]; then
  healthy=false
  reason=access_log_missing
elif [ ! -r "$PROJECT_MATI_ACCESS_LOG" ]; then
  healthy=false
  reason=access_log_unreadable
fi

install -d -m 0750 -o root -g wazuh "$OUTPUT_DIR"
printf '{"project_mati":{"event":"web_log_health"},"server":"%s","service":"%s","log_path":"%s","healthy":%s,"reason":"%s","checked_at":"%s"}\n' \
  "$PROJECT_MATI_SERVER" "$PROJECT_MATI_SERVICE" "$PROJECT_MATI_ACCESS_LOG" "$healthy" "$reason" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$OUTPUT_FILE"
chown root:wazuh "$OUTPUT_FILE"
chmod 0640 "$OUTPUT_FILE"
