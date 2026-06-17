#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

require_lab_dir

ASSET_DIR="${LAB_DIR}/02-assets"
SERVICE_DIR="${LAB_DIR}/03-services"
REACHABLE="${ASSET_DIR}/reachable-client-ips.txt"
NMAP_OUT="${SERVICE_DIR}/reachable-common-services.nmap"
CSV_OUT="${SERVICE_DIR}/reachable-open-ports.csv"
SUMMARY="${SERVICE_DIR}/service-version-summary.txt"
RUN_SUMMARY="${SERVICE_DIR}/common-services-run-summary.txt"
TARGETS="${SERVICE_DIR}/reachable-targets.txt"
STAMP="$(now_iso)"
PORTS_SCANNED="22,80,135,139,443,445,3389,5900,8080"
NMAP_COMMAND="nmap -Pn -n -sT --version-light --max-retries 1 --host-timeout 30s -p ${PORTS_SCANNED} -iL ${TARGETS}"

mkdir -p "${SERVICE_DIR}"

write_run_summary() {
  local scanned_count="$1"
  local open_hosts_count="$2"
  local skipped_count="$3"
  local status="$4"
  {
    printf 'captured_at=%s\n' "${STAMP}"
    printf 'status=%s\n' "${status}"
    printf 'scanned_reachable_count=%s\n' "${scanned_count}"
    printf 'open_service_hosts_count=%s\n' "${open_hosts_count}"
    printf 'skipped_count=%s\n' "${skipped_count}"
    printf 'ports_scanned=%s\n' "${PORTS_SCANNED}"
    printf 'nmap_command_used=%s\n' "${NMAP_COMMAND}"
  } > "${RUN_SUMMARY}"
}

if ! has_cmd nmap; then
  append_note "${SUMMARY}" "nmap not found; common service detection skipped."
  total_candidates="$(tail -n +2 "${ASSET_DIR}/client-profile.csv" 2>/dev/null | wc -l | tr -d ' ')"
  write_run_summary "0" "0" "${total_candidates:-0}" "skipped-nmap-not-found"
  printf 'nmap not found; skipped common service detection.\n'
  exit 0
fi

sort -u "${REACHABLE}" | sed '/^$/d' > "${TARGETS}"
SCANNED_REACHABLE_COUNT="$(wc -l < "${TARGETS}" | tr -d ' ')"
TOTAL_CLIENT_CANDIDATES="$(awk -F, 'NR > 1 {gsub(/"/, "", $4); if ($4 != "true") c++} END {print c+0}' "${ASSET_DIR}/client-profile.csv" 2>/dev/null || printf '0')"
SKIPPED_COUNT=$((TOTAL_CLIENT_CANDIDATES - SCANNED_REACHABLE_COUNT))
if [[ "${SKIPPED_COUNT}" -lt 0 ]]; then
  SKIPPED_COUNT=0
fi

if [[ ! -s "${TARGETS}" ]]; then
  append_note "${SUMMARY}" "No reachable clients found; common service detection skipped."
  printf 'ip,port,protocol,state,service,version,detected_at,notes\n' > "${CSV_OUT}"
  write_run_summary "0" "0" "${SKIPPED_COUNT}" "skipped-no-reachable-clients"
  printf 'No reachable clients found. Run ./04-client-isolation.sh first.\n'
  exit 0
fi

{
  printf '# reachable common services captured_at=%s\n' "${STAMP}"
  printf '# command: %s\n\n' "${NMAP_COMMAND}"
  nmap -Pn -n -sT --version-light --max-retries 1 --host-timeout 30s \
    -p "${PORTS_SCANNED}" \
    -iL "${TARGETS}" 2>&1 || true
} > "${NMAP_OUT}"

printf 'ip,port,protocol,state,service,version,detected_at,notes\n' > "${CSV_OUT}"

awk -v stamp="${STAMP}" '
  /^Nmap scan report for / { ip=$NF; next }
  /^[0-9]+\/tcp[[:space:]]+open/ {
    split($1, pp, "/")
    port=pp[1]
    state=$2
    service=$3
    version=""
    for (i=4; i<=NF; i++) version = version (version ? " " : "") $i
    gsub(/"/, "\"\"", version)
    printf "\"%s\",\"%s\",\"tcp\",\"%s\",\"%s\",\"%s\",\"%s\",\"\"\n", ip, port, state, service, version, stamp
  }
' "${NMAP_OUT}" >> "${CSV_OUT}"

OPEN_SERVICE_HOSTS_COUNT="$(tail -n +2 "${CSV_OUT}" | awk -F, '{gsub(/"/, "", $1); if ($1 != "") seen[$1]=1} END {for (ip in seen) c++; print c+0}')"
write_run_summary "${SCANNED_REACHABLE_COUNT}" "${OPEN_SERVICE_HOSTS_COUNT}" "${SKIPPED_COUNT}" "completed"

{
  printf '# Service Version Summary\n\n'
  printf -- '- Captured at: %s\n' "${STAMP}"
  printf -- '- Targets file: %s\n' "${TARGETS}"
  printf -- '- Evidence file: %s\n\n' "${NMAP_OUT}"
  printf -- '- Run summary file: %s\n\n' "${RUN_SUMMARY}"
  awk -F, 'NR > 1 {print "- " $1 " tcp/" $2 " " $5 " " $6}' "${CSV_OUT}" | sed 's/"//g'
} > "${SUMMARY}"

write_kv_summary "common_services_checked_at" "${STAMP}"
write_kv_summary "open_common_port_count" "$(tail -n +2 "${CSV_OUT}" | wc -l | tr -d ' ')"

printf 'Common service detection saved to %s\n' "${NMAP_OUT}"
printf 'Open port CSV saved to %s\n' "${CSV_OUT}"
