#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/common.sh"
require_lab_dir

OUT="${LAB_DIR}/03-services/mdns-services.csv"
SUMMARY="${LAB_DIR}/06-report/mdns-summary.md"
SECONDS_LIMIT="${LANPILOT_MDNS_SECONDS:-6}"
RAW="$(mktemp)"
trap 'rm -f "${RAW}"' EXIT
printf 'service_type,instance_name,hostname,observed_at,risk_note\n' > "${OUT}"

if has_cmd dns-sd; then
  dns-sd -B _services._dns-sd._udp local. > "${RAW}" 2>/dev/null &
  PID=$!
  sleep "${SECONDS_LIMIT}"
  kill "${PID}" 2>/dev/null || true
  wait "${PID}" 2>/dev/null || true
  awk '/_tcp\.|_udp\./ {type=$(NF-1); name=$NF; print type "\t" name}' "${RAW}" | sort -u |
    while IFS=$'\t' read -r type name; do
      csv_row "${type}" "${name}" "" "$(now_iso)" "Observed mDNS announcements may reveal device or service context." >> "${OUT}"
    done
  STATE="completed"
else
  STATE="limited"
fi
COUNT="$(awk 'END{print NR-1}' "${OUT}")"
{
  printf '# Bonjour / mDNS Observation\n\n'
  printf -- '- Observation duration: %s seconds\n' "${SECONDS_LIMIT}"
  printf -- '- Observed service announcements: %s\n' "${COUNT}"
  printf -- '- State: %s\n\n' "${STATE}"
  printf 'This short, non-persistent observation does not connect to announced services.\n'
} > "${SUMMARY}"
write_step_status "mdns_observation" "${STATE}" "Observed ${COUNT} mDNS service announcements"
