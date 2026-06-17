#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

require_lab_dir

ASSET_DIR="${LAB_DIR}/02-assets"
PROFILE="${ASSET_DIR}/client-profile.csv"
REACHABLE="${ASSET_DIR}/reachable-client-ips.txt"
UNREACHABLE="${ASSET_DIR}/unreachable-client-ips.txt"
GATEWAY="$(cat "${LAB_DIR}/00-scope/gateway-ip.txt" 2>/dev/null || true)"
STAMP="$(now_iso)"

: > "${REACHABLE}"
: > "${UNREACHABLE}"

TMP_PROFILE="$(mktemp)"
printf 'ip,mac,interface,is_gateway,icmp_reachable,common_ports_open,smb_present,web_present,risk_hint,notes\n' > "${TMP_PROFILE}"

tail -n +2 "${PROFILE}" | awk -F, '!seen[$1]++ {print}' | while IFS=, read -r ip mac iface is_gateway _common ports smb web risk_hint notes; do
  ip="${ip%\"}"; ip="${ip#\"}"
  mac="${mac%\"}"; mac="${mac#\"}"
  iface="${iface%\"}"; iface="${iface#\"}"
  [[ -n "${ip}" ]] || continue

  if [[ "${ip}" == "${GATEWAY}" || "${is_gateway}" == '"true"' || "${is_gateway}" == "true" ]]; then
    csv_row "${ip}" "${mac}" "${iface}" "true" "skipped-gateway" "" "unknown" "unknown" "gateway handled separately" "client isolation check skipped for gateway" >> "${TMP_PROFILE}"
    continue
  fi

  if ping -c 1 -W 1000 "${ip}" >/dev/null 2>&1; then
    printf '%s\n' "${ip}" >> "${REACHABLE}"
    csv_row "${ip}" "${mac}" "${iface}" "false" "true" "" "unknown" "unknown" "reachable client requires service posture check" "single ICMP echo reply at ${STAMP}" >> "${TMP_PROFILE}"
  else
    printf '%s\n' "${ip}" >> "${UNREACHABLE}"
    csv_row "${ip}" "${mac}" "${iface}" "false" "false" "" "unknown" "unknown" "not reachable by single ICMP check" "single ICMP echo did not reply at ${STAMP}" >> "${TMP_PROFILE}"
  fi
done

mv "${TMP_PROFILE}" "${PROFILE}"

write_kv_summary "client_isolation_checked_at" "${STAMP}"
write_kv_summary "reachable_client_count" "$(sort -u "${REACHABLE}" | wc -l | tr -d ' ')"
write_kv_summary "unreachable_client_count" "$(sort -u "${UNREACHABLE}" | wc -l | tr -d ' ')"

printf 'Client isolation profile updated: %s\n' "${PROFILE}"
printf 'Reachable clients: %s\n' "$(sort -u "${REACHABLE}" | wc -l | tr -d ' ')"
printf 'Unreachable clients: %s\n' "$(sort -u "${UNREACHABLE}" | wc -l | tr -d ' ')"
