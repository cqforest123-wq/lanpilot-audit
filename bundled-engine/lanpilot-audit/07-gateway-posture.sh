#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

require_lab_dir

SERVICE_DIR="${LAB_DIR}/03-services"
SUMMARY="${SERVICE_DIR}/gateway-service-version-summary.txt"
DETAIL="${SERVICE_DIR}/gateway-service-version.nmap"
HEADERS="${SERVICE_DIR}/gateway-web-headers.txt"
GATEWAY="$(cat "${LAB_DIR}/00-scope/gateway-ip.txt" 2>/dev/null || default_gateway || true)"
STAMP="$(now_iso)"

mkdir -p "${SERVICE_DIR}"

{
  printf '# Gateway Service Version Summary\n\n'
  printf -- '- Captured at: %s\n' "${STAMP}"
  printf -- '- Gateway: %s\n\n' "${GATEWAY}"
} > "${SUMMARY}"

if [[ -z "${GATEWAY}" ]]; then
  printf 'No default gateway detected. Run ./02-baseline.sh first.\n' >> "${SUMMARY}"
  printf 'No gateway detected.\n'
  exit 0
fi

if has_cmd nmap; then
  {
    printf '# gateway posture captured_at=%s\n' "${STAMP}"
    printf '# command: nmap -Pn -n -sT --version-light --max-retries 1 --host-timeout 30s -p 53,80,443,8080,8443 %s\n\n' "${GATEWAY}"
    nmap -Pn -n -sT --version-light --max-retries 1 --host-timeout 30s \
      -p 53,80,443,8080,8443 "${GATEWAY}" 2>&1 || true
  } > "${DETAIL}"
  printf -- '- Evidence file: %s\n' "${DETAIL}" >> "${SUMMARY}"
else
  printf 'nmap not found; gateway service detection skipped.\n' >> "${SUMMARY}"
fi

: > "${HEADERS}"
for scheme in http https; do
  for port in 80 443 8080 8443; do
    url="${scheme}://${GATEWAY}:${port}/"
    {
      printf '\n## %s\n' "${url}"
      curl -k -I --connect-timeout 2 --max-time 5 "${url}" 2>&1 || true
    } >> "${HEADERS}"
  done
done

{
  printf -- '- Web header evidence file: %s\n\n' "${HEADERS}"
  if [[ -f "${DETAIL}" ]]; then
    awk '/^[0-9]+\/tcp[[:space:]]+open/ {print "- " $0}' "${DETAIL}"
  fi
} >> "${SUMMARY}"

write_kv_summary "gateway_posture_checked_at" "${STAMP}"

printf 'Gateway posture summary saved to %s\n' "${SUMMARY}"
