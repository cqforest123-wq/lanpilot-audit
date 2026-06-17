#!/usr/bin/env bash

KIT_NAME="LANPilot Audit"
KIT_VERSION="1.3.0"
ROOT_DIR="${LANPILOT_AUDIT_ROOT:-$HOME}"
LAB_DIR="${LANPILOT_LAB_DIR:-${ROOT_DIR}/lanpilot-audit-latest}"

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

require_lab_dir() {
  if [[ ! -d "${LAB_DIR}" ]]; then
    die "lab directory not found: ${LAB_DIR}. Run ./01-init-lab.sh first."
  fi
}

now_iso() {
  date '+%Y-%m-%d %H:%M:%S %Z'
}

has_cmd() {
  command -v "$1" >/dev/null 2>&1
}

append_note() {
  local file="$1"
  shift
  {
    printf '\n[%s] ' "$(now_iso)"
    printf '%s\n' "$*"
  } >> "${file}"
}

csv_escape() {
  local value="${1:-}"
  value="${value//$'\r'/ }"
  value="${value//$'\n'/ }"
  value="${value//\"/\"\"}"
  printf '"%s"' "${value}"
}

csv_row() {
  local first=1
  local value
  for value in "$@"; do
    if [[ "${first}" -eq 0 ]]; then
      printf ','
    fi
    csv_escape "${value}"
    first=0
  done
  printf '\n'
}

default_interface() {
  route -n get default 2>/dev/null | awk '/interface:/{print $2; exit}'
}

default_gateway() {
  route -n get default 2>/dev/null | awk '/gateway:/{print $2; exit}'
}

is_tunnel_interface() {
  case "${1:-}" in
    utun*|ppp*|ipsec*|tap*|tun*) return 0 ;;
    *) return 1 ;;
  esac
}

first_lan_interface() {
  local iface
  for iface in en0 en1 en2; do
    if [[ -n "$(interface_ipv4 "${iface}")" ]]; then
      printf '%s\n' "${iface}"
      return 0
    fi
  done

  ifconfig -l 2>/dev/null | tr ' ' '\n' | while read -r iface; do
    [[ -n "${iface}" ]] || continue
    case "${iface}" in
      lo*|utun*|ppp*|ipsec*|tap*|tun*|gif*|stf*|awdl*|llw*|bridge*) continue ;;
    esac
    if [[ -n "$(interface_ipv4 "${iface}")" ]]; then
      printf '%s\n' "${iface}"
      return 0
    fi
  done
}

audit_interface() {
  local requested="${LANPILOT_INTERFACE:-}"
  local default_iface fallback

  if [[ -n "${requested}" ]]; then
    printf '%s\n' "${requested}"
    return 0
  fi

  default_iface="$(default_interface || true)"
  if [[ -n "${default_iface}" ]] && ! is_tunnel_interface "${default_iface}"; then
    printf '%s\n' "${default_iface}"
    return 0
  fi

  fallback="$(first_lan_interface || true)"
  if [[ -n "${fallback}" ]]; then
    printf '%s\n' "${fallback}"
    return 0
  fi

  printf '%s\n' "${default_iface}"
}

audit_interface_reason() {
  local requested="${LANPILOT_INTERFACE:-}"
  local default_iface selected
  default_iface="$(default_interface || true)"
  selected="$(audit_interface || true)"

  if [[ -n "${requested}" ]]; then
    printf 'LANPILOT_INTERFACE override'
  elif [[ -n "${default_iface}" && "${selected}" == "${default_iface}" ]]; then
    printf 'default route interface'
  elif [[ -n "${default_iface}" ]] && is_tunnel_interface "${default_iface}"; then
    printf 'default route interface is tunnel/proxy (%s); selected LAN interface' "${default_iface}"
  else
    printf 'first non-tunnel IPv4 interface'
  fi
}

gateway_for_interface() {
  local iface="$1"
  if [[ -z "${iface}" ]]; then
    return 1
  fi
  netstat -rn -f inet 2>/dev/null | awk -v iface="${iface}" '
    ($1 == "default" || $1 == "0/1" || $1 == "128.0/1") && $NF == iface {
      print $2
      exit
    }
  '
}

interface_ipv4() {
  local iface="$1"
  ifconfig "${iface}" 2>/dev/null | awk '/inet /{print $2; exit}'
}

interface_netmask_hex() {
  local iface="$1"
  ifconfig "${iface}" 2>/dev/null | awk '
    /inet / {
      for (i=1; i<=NF; i++) {
        if ($i == "netmask" && (i + 1) <= NF) {
          print $(i + 1)
          exit
        }
      }
    }
  '
}

hex_netmask_to_prefix() {
  local mask="${1#0x}"
  local binary="" nibble char prefix
  local i
  for ((i = 0; i < ${#mask}; i++)); do
    char="${mask:$i:1}"
    case "${char}" in
      0) nibble="0000" ;;
      1) nibble="0001" ;;
      2) nibble="0010" ;;
      3) nibble="0011" ;;
      4) nibble="0100" ;;
      5) nibble="0101" ;;
      6) nibble="0110" ;;
      7) nibble="0111" ;;
      8) nibble="1000" ;;
      9) nibble="1001" ;;
      a|A) nibble="1010" ;;
      b|B) nibble="1011" ;;
      c|C) nibble="1100" ;;
      d|D) nibble="1101" ;;
      e|E) nibble="1110" ;;
      f|F) nibble="1111" ;;
      *) nibble="" ;;
    esac
    binary="${binary}${nibble}"
  done
  prefix=0
  for ((i = 0; i < ${#binary}; i++)); do
    [[ "${binary:$i:1}" == "1" ]] && prefix=$((prefix + 1))
  done
  printf '%s' "${prefix}"
}

cidr_from_default_interface() {
  local iface ip mask prefix
  iface="$(default_interface)"
  [[ -n "${iface}" ]] || return 1
  ip="$(interface_ipv4 "${iface}")"
  mask="$(interface_netmask_hex "${iface}")"
  [[ -n "${ip}" && -n "${mask}" ]] || return 1
  prefix="$(hex_netmask_to_prefix "${mask}")"
  printf '%s/%s\n' "${ip}" "${prefix}"
}

gateway_file() {
  printf '%s/00-scope/gateway-ip.txt' "${LAB_DIR}"
}

write_kv_summary() {
  local key="$1"
  local value="$2"
  local file="${LAB_DIR}/00-scope/network-summary.txt"
  if grep -q "^${key}=" "${file}" 2>/dev/null; then
    sed -i '' "s|^${key}=.*|${key}=${value}|" "${file}"
  else
    printf '%s=%s\n' "${key}" "${value}" >> "${file}"
  fi
}

write_step_status() {
  local step="$1" state="$2" message="$3"
  local status_dir="${LAB_DIR}/00-scope/step-status"
  mkdir -p "${status_dir}"
  printf '{"step":"%s","state":"%s","message":"%s","updated_at":"%s"}\n' \
    "${step}" "${state}" "${message//\"/\\\"}" "$(now_iso)" > "${status_dir}/${step}.json"
}
