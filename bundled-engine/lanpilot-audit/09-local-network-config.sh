#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/common.sh"
require_lab_dir

OUT="${LAB_DIR}/01-baseline/local-network-config.json"
SUMMARY="${LAB_DIR}/06-report/local-network-config-summary.md"
IFACE="$(audit_interface || true)"
IP="$(interface_ipv4 "${IFACE}" || true)"
MASK="$(interface_netmask_hex "${IFACE}" || true)"
PREFIX="$(hex_netmask_to_prefix "${MASK}")"
GATEWAY="$(gateway_for_interface "${IFACE}" || default_gateway || true)"
DNS="$(scutil --dns 2>/dev/null | awk '/nameserver\[[0-9]+\]/{print $3}' | sort -u | paste -sd ';' - || true)"
SEARCH="$(scutil --dns 2>/dev/null | awk '/search domain\[[0-9]+\]/{print $3}' | sort -u | paste -sd ';' - || true)"
DHCP=""
SSID=""
VPN="false"

if [[ -n "${IFACE}" ]]; then
  DHCP="$(ipconfig getpacket "${IFACE}" 2>/dev/null | awk '/server_identifier/{gsub(/[{}]/,"",$3); print $3; exit}' || true)"
fi
if has_cmd networksetup; then
  SSID="$(networksetup -getairportnetwork "${IFACE}" 2>/dev/null | sed 's/^Current Wi-Fi Network: //' || true)"
fi
if ifconfig -l 2>/dev/null | tr ' ' '\n' | grep -Eq '^(utun|ppp|ipsec|tun|tap)[0-9]*$'; then VPN="true"; fi

python3 - "${OUT}" "${IFACE}" "${IP}" "${PREFIX}" "${GATEWAY}" "${DNS}" "${DHCP}" "${SEARCH}" "${SSID}" "${VPN}" <<'PY'
import json, pathlib, sys
keys = ["interface","local_ip","prefix_length","default_gateway","dns_servers","dhcp_server","search_domains","wifi_ssid","vpn_route_warning"]
values = sys.argv[2:]
data = dict(zip(keys, values))
data["dns_servers"] = [x for x in data["dns_servers"].split(";") if x]
data["search_domains"] = [x for x in data["search_domains"].split(";") if x]
data["vpn_route_warning"] = data["vpn_route_warning"] == "true"
pathlib.Path(sys.argv[1]).write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
PY

{
  printf '# Local Network Configuration Observation\n\n'
  printf -- '- Interface confirmed: %s\n' "${IFACE:-Unknown}"
  printf -- '- Local address: %s/%s\n' "${IP:-Unknown}" "${PREFIX:-Unknown}"
  printf -- '- Gateway identified: %s\n' "${GATEWAY:-Unknown}"
  printf -- '- DNS configuration observed: %s\n' "${DNS:-Unknown}"
  printf -- '- DHCP configuration observed: %s\n' "${DHCP:-Unknown}"
  printf -- '- Search domains: %s\n' "${SEARCH:-None observed}"
  printf -- '- Wi-Fi SSID: %s\n' "${SSID:-Unavailable}"
  printf -- '- VPN route warning: %s\n\n' "${VPN}"
  printf 'This is a read-only observation of the current Mac network configuration.\n'
} > "${SUMMARY}"
write_step_status "local_network_config" "completed" "Local network configuration observed"
