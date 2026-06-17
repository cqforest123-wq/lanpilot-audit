#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

require_lab_dir

ASSET_DIR="${LAB_DIR}/02-assets"
SCOPE_DIR="${LAB_DIR}/00-scope"
mkdir -p "${ASSET_DIR}"

OUT_ASSETS="${ASSET_DIR}/passive-arp-assets.csv"
OUT_CANDIDATES="${ASSET_DIR}/passive-neighbor-candidates.csv"
OUT_PROFILE="${ASSET_DIR}/client-profile.csv"
SNAPSHOT="${ASSET_DIR}/arp-snapshot-$(date +%Y%m%d-%H%M%S).txt"
OBSERVED_AT="$(now_iso)"
GATEWAY="$(cat "${SCOPE_DIR}/gateway-ip.txt" 2>/dev/null || default_gateway || true)"
IFACE="$(cat "${SCOPE_DIR}/default-interface.txt" 2>/dev/null || default_interface || true)"

arp -an 2>&1 | tee "${SNAPSHOT}" >/dev/null || true

printf 'ip,mac,interface,source,first_seen,last_seen,notes\n' > "${OUT_ASSETS}"
printf 'ip,mac,interface,relationship,source,observed_at,notes\n' > "${OUT_CANDIDATES}"
printf 'ip,mac,interface,is_gateway,icmp_reachable,common_ports_open,smb_present,web_present,risk_hint,notes\n' > "${OUT_PROFILE}"

awk '
  {
    ip=$2
    mac=$4
    iface=""
    gsub(/[()]/, "", ip)
    for (i=1; i<=NF; i++) {
      if ($i == "on" && (i + 1) <= NF) iface=$(i + 1)
    }
    if (ip ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ && mac != "(incomplete)" && mac != "") {
      print ip "," mac "," iface
    }
  }
' "${SNAPSHOT}" | sort -u | while IFS=, read -r ip mac seen_iface; do
  [[ -n "${ip}" ]] || continue
  relationship="client"
  is_gateway="false"
  if [[ "${ip}" == "${GATEWAY}" ]]; then
    relationship="gateway"
    is_gateway="true"
  fi

  csv_row "${ip}" "${mac}" "${seen_iface:-${IFACE}}" "arp-cache" "${OBSERVED_AT}" "${OBSERVED_AT}" "" >> "${OUT_ASSETS}"
  csv_row "${ip}" "${mac}" "${seen_iface:-${IFACE}}" "${relationship}" "arp-cache" "${OBSERVED_AT}" "" >> "${OUT_CANDIDATES}"
  csv_row "${ip}" "${mac}" "${seen_iface:-${IFACE}}" "${is_gateway}" "unknown" "" "unknown" "unknown" "pending isolation and service checks" "" >> "${OUT_PROFILE}"
done

write_kv_summary "passive_assets_captured_at" "${OBSERVED_AT}"
write_kv_summary "passive_asset_count" "$(tail -n +2 "${OUT_ASSETS}" | wc -l | tr -d ' ')"

printf 'Passive ARP assets saved to %s\n' "${OUT_ASSETS}"
printf 'Snapshot saved to %s\n' "${SNAPSHOT}"
