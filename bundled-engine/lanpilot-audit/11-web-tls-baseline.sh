#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/common.sh"
require_lab_dir

PORTS="${LAB_DIR}/03-services/reachable-open-ports.csv"
WEB="${LAB_DIR}/03-services/web-baseline.csv"
TLS="${LAB_DIR}/03-services/tls-certificates.csv"
SUMMARY="${LAB_DIR}/06-report/web-tls-summary.md"
printf 'asset,port,status_code,server_header,title,hsts,x_frame_options,x_content_type_options,content_security_policy,observed_at\n' > "${WEB}"
printf 'asset,port,subject,issuer,not_before,not_after,days_until_expiry,protocol_info,observed_at\n' > "${TLS}"

if [[ -f "${PORTS}" ]] && has_cmd curl; then
  while IFS=, read -r ip port _proto _state _service _version _detected _notes; do
    ip="${ip//\"/}"; port="${port//\"/}"
    [[ "${ip}" == "ip" ]] && continue
    case "${port}" in 80|8080|443|8443) ;; *) continue ;; esac
    scheme="http"; [[ "${port}" == "443" || "${port}" == "8443" ]] && scheme="https"
    headers="$(curl -k -sS -I --max-time 4 "${scheme}://${ip}:${port}/" 2>/dev/null || true)"
    status="$(printf '%s\n' "${headers}" | awk 'NR==1{print $2}')"
    server="$(printf '%s\n' "${headers}" | awk -F': ' 'tolower($1)=="server"{gsub(/\r/,"",$2);print $2;exit}')"
    present() { printf '%s\n' "${headers}" | grep -qi "^$1:" && printf 'present' || printf 'not observed'; }
    csv_row "${ip}" "${port}" "${status}" "${server}" "" "$(present Strict-Transport-Security)" "$(present X-Frame-Options)" "$(present X-Content-Type-Options)" "$(present Content-Security-Policy)" "$(now_iso)" >> "${WEB}"
    if [[ "${scheme}" == "https" ]] && has_cmd openssl; then
      cert="$(printf '' | openssl s_client -connect "${ip}:${port}" -servername "${ip}" 2>/dev/null | openssl x509 -noout -subject -issuer -startdate -enddate 2>/dev/null || true)"
      subject="$(printf '%s\n' "${cert}" | sed -n 's/^subject=//p')"; issuer="$(printf '%s\n' "${cert}" | sed -n 's/^issuer=//p')"
      before="$(printf '%s\n' "${cert}" | sed -n 's/^notBefore=//p')"; after="$(printf '%s\n' "${cert}" | sed -n 's/^notAfter=//p')"
      days=""
      if [[ -n "${after}" ]]; then days="$(( ($(date -j -f '%b %e %T %Y %Z' "${after}" '+%s' 2>/dev/null || date '+%s') - $(date '+%s')) / 86400 ))"; fi
      csv_row "${ip}" "${port}" "${subject}" "${issuer}" "${before}" "${after}" "${days}" "TLS certificate handshake observed" "$(now_iso)" >> "${TLS}"
    fi
  done < "${PORTS}"
fi
WEB_COUNT="$(awk 'END{print NR-1}' "${WEB}")"; TLS_COUNT="$(awk 'END{print NR-1}' "${TLS}")"
{
  printf '# Web and TLS Baseline Observation\n\n'
  printf -- '- Web endpoints observed: %s\n' "${WEB_COUNT}"
  printf -- '- TLS certificates observed: %s\n\n' "${TLS_COUNT}"
  printf 'Checks use short requests against already-observed Web services. No crawling or service login is performed.\n'
} > "${SUMMARY}"
write_step_status "web_tls_baseline" "completed" "Observed ${WEB_COUNT} Web endpoints and ${TLS_COUNT} TLS certificates"
