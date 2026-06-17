#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

require_lab_dir

BASELINE_DIR="${LAB_DIR}/01-baseline"
SCOPE_DIR="${LAB_DIR}/00-scope"
mkdir -p "${BASELINE_DIR}" "${SCOPE_DIR}"

ROUTE_DEFAULT_IFACE="$(default_interface || true)"
IFACE="$(audit_interface || true)"
IFACE_REASON="$(audit_interface_reason || true)"
GATEWAY="$(gateway_for_interface "${IFACE}" || true)"
if [[ -z "${GATEWAY}" ]]; then
  GATEWAY="$(default_gateway || true)"
fi
LOCAL_IP=""
NETMASK_HEX=""
PREFIX=""
CIDR=""

if [[ -n "${IFACE}" ]]; then
  LOCAL_IP="$(interface_ipv4 "${IFACE}" || true)"
  NETMASK_HEX="$(interface_netmask_hex "${IFACE}" || true)"
  if [[ -n "${NETMASK_HEX}" ]]; then
    PREFIX="$(hex_netmask_to_prefix "${NETMASK_HEX}")"
  fi
fi

if [[ -n "${LOCAL_IP}" && -n "${PREFIX}" ]]; then
  CIDR="${LOCAL_IP}/${PREFIX}"
fi

{
  printf '%s %s baseline\n' "${KIT_NAME}" "${KIT_VERSION}"
  printf 'captured_at=%s\n' "$(now_iso)"
  printf 'operator=%s\n' "$(id -un)"
  printf 'audit_interface=%s\n' "${IFACE}"
  printf 'audit_interface_reason=%s\n' "${IFACE_REASON}"
  printf 'route_default_interface=%s\n' "${ROUTE_DEFAULT_IFACE}"
  printf 'local_ipv4=%s\n' "${LOCAL_IP}"
  printf 'netmask_hex=%s\n' "${NETMASK_HEX}"
  printf 'prefix=%s\n' "${PREFIX}"
  printf 'local_cidr=%s\n' "${CIDR}"
  printf 'default_gateway=%s\n' "${GATEWAY}"
  printf '\n## ifconfig %s\n' "${IFACE:-all}"
  if [[ -n "${IFACE}" ]]; then
    ifconfig "${IFACE}" 2>&1 || true
  else
    ifconfig 2>&1 || true
  fi
} > "${BASELINE_DIR}/baseline.txt"

{
  printf '# route captured_at=%s\n' "$(now_iso)"
  netstat -rn 2>&1 || true
  printf '\n# route get default\n'
  route -n get default 2>&1 || true
} > "${BASELINE_DIR}/route.txt"

{
  printf '# dns captured_at=%s\n' "$(now_iso)"
  scutil --dns 2>&1 || true
} > "${BASELINE_DIR}/dns.txt"

{
  printf '# local listening ports captured_at=%s\n' "$(now_iso)"
  if has_cmd lsof; then
    lsof -nP -iTCP -sTCP:LISTEN 2>&1 || true
  else
    netstat -anv -p tcp 2>&1 | awk '$6 == "LISTEN" {print}' || true
  fi
} > "${BASELINE_DIR}/local-listening-ports.txt"

{
  printf '# arp captured_at=%s\n' "$(now_iso)"
  arp -an 2>&1 || true
} > "${BASELINE_DIR}/arp-snapshot.txt"

printf '%s\n' "${GATEWAY}" > "${SCOPE_DIR}/gateway-ip.txt"
printf '%s\n' "${IFACE}" > "${SCOPE_DIR}/default-interface.txt"
printf '%s\n' "${IFACE}" > "${SCOPE_DIR}/audit-interface.txt"
printf '%s\n' "${CIDR}" > "${SCOPE_DIR}/local-cidr.txt"

write_kv_summary "baseline_captured_at" "$(now_iso)"
write_kv_summary "audit_interface" "${IFACE}"
write_kv_summary "audit_interface_reason" "${IFACE_REASON}"
write_kv_summary "route_default_interface" "${ROUTE_DEFAULT_IFACE}"
write_kv_summary "local_ipv4" "${LOCAL_IP}"
write_kv_summary "local_cidr" "${CIDR}"
write_kv_summary "default_gateway" "${GATEWAY}"

printf 'Baseline saved to %s\n' "${BASELINE_DIR}"
printf 'Detected audit_interface=%s local_cidr=%s gateway=%s\n' "${IFACE}" "${CIDR}" "${GATEWAY}"
printf 'Selection reason: %s\n' "${IFACE_REASON}"
