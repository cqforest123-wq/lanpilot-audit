#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

require_lab_dir

SERVICE_DIR="${LAB_DIR}/03-services"
OPEN_PORTS="${SERVICE_DIR}/reachable-open-ports.csv"
SUMMARY="${SERVICE_DIR}/smb-posture-summary.txt"
TARGETS="${SERVICE_DIR}/smb-targets.txt"
DETAIL="${SERVICE_DIR}/smb-posture-detail.nmap"
STAMP="$(now_iso)"

mkdir -p "${SERVICE_DIR}"

awk -F, 'NR > 1 {
  ip=$1; port=$2
  gsub(/"/, "", ip); gsub(/"/, "", port)
  if (port == "445" || port == "139") print ip
}' "${OPEN_PORTS}" 2>/dev/null | sort -u > "${TARGETS}"

{
  printf '# SMB Posture Summary\n\n'
  printf -- '- Captured at: %s\n' "${STAMP}"
  printf -- '- Method: non-destructive SMB protocol and signing posture check\n\n'
} > "${SUMMARY}"

if [[ ! -s "${TARGETS}" ]]; then
  printf 'No SMB hosts found in this run. This does not prove no SMB exists in the network; it only means no SMB was found among currently detected reachable/open-service assets.\n' >> "${SUMMARY}"
  write_kv_summary "smb_posture_checked_at" "${STAMP}"
  write_kv_summary "smb_target_count" "0"
  printf 'No SMB hosts found. Run ./05-common-services.sh first.\n'
  exit 0
fi

if ! has_cmd nmap; then
  printf 'nmap not found; SMB posture check skipped.\n' >> "${SUMMARY}"
  printf 'nmap not found; skipped SMB posture check.\n'
  exit 0
fi

{
  printf '# smb posture captured_at=%s\n' "${STAMP}"
  printf '# command: nmap -Pn -n -sT --max-retries 1 --host-timeout 45s -p445 --script smb-protocols,smb2-security-mode -iL %s\n\n' "${TARGETS}"
  nmap -Pn -n -sT --max-retries 1 --host-timeout 45s \
    -p445 --script smb-protocols,smb2-security-mode \
    -iL "${TARGETS}" 2>&1 || true
} > "${DETAIL}"

{
  printf -- '- Targets file: %s\n' "${TARGETS}"
  printf -- '- Evidence file: %s\n\n' "${DETAIL}"
  awk '
    /^Nmap scan report for / { ip=$NF; print "## " ip; next }
    /SMBv1|Message signing|message_signing|signing/ { print "- " $0 }
  ' "${DETAIL}"
} >> "${SUMMARY}"

write_kv_summary "smb_posture_checked_at" "${STAMP}"
write_kv_summary "smb_target_count" "$(wc -l < "${TARGETS}" | tr -d ' ')"

printf 'SMB posture summary saved to %s\n' "${SUMMARY}"
