#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

require_lab_dir

RISK_DIR="${LAB_DIR}/04-risk"
REPORT_DIR="${LAB_DIR}/06-report"
REMEDIATION_DIR="${LAB_DIR}/05-remediation"
ASSET_DIR="${LAB_DIR}/02-assets"
SERVICE_DIR="${LAB_DIR}/03-services"
ISSUES="${RISK_DIR}/network-issues-register.csv"
RANKING="${RISK_DIR}/client-risk-ranking.csv"
HIGH="${RISK_DIR}/high-risk-findings.md"
ROADMAP="${REMEDIATION_DIR}/remediation-roadmap.md"
MATRIX="${REMEDIATION_DIR}/remediation-authority-matrix.csv"
STAMP="$(now_iso)"
ISSUE_TSV="$(mktemp)"
SMB_REMEDIATION_NEEDED="false"
trap 'rm -f "${ISSUE_TSV}"' EXIT

mkdir -p "${RISK_DIR}" "${REPORT_DIR}" "${REMEDIATION_DIR}"
printf 'issue_id,severity,asset,category,finding,evidence_file,business_risk,remediation_owner,recommended_action,validation_method,status\n' > "${ISSUES}"
printf 'rank,ip,mac,risk_level,score,drivers,recommended_priority,notes\n' > "${RANKING}"
printf 'item,owner_role,requires_network_admin,requires_endpoint_admin,requires_vendor,change_window_required,approval_notes\n' > "${MATRIX}"

issue_num=1
add_issue() {
  local severity="$1" asset="$2" category="$3" finding="$4" evidence="$5" business_risk="$6" owner="$7" action="$8" validation="$9"
  csv_row "NG-$(printf '%03d' "${issue_num}")" "${severity}" "${asset}" "${category}" "${finding}" "${evidence}" "${business_risk}" "${owner}" "${action}" "${validation}" "open" >> "${ISSUES}"
  printf '%s\t%s\t%s\t%s\t%s\n' "${severity}" "${asset}" "${category}" "${finding}" "${action}" >> "${ISSUE_TSV}"
  issue_num=$((issue_num + 1))
}

OPEN_PORTS="${SERVICE_DIR}/reachable-open-ports.csv"
if [[ -f "${OPEN_PORTS}" ]]; then
  while IFS=, read -r ip port proto state service version detected_at notes; do
    [[ "${ip}" == "ip" || -z "${ip}" ]] && continue
    clean_ip="${ip//\"/}"
    clean_port="${port//\"/}"
    clean_service="${service//\"/}"
    case "${clean_port}" in
      445|139)
        SMB_REMEDIATION_NEEDED="true"
        add_issue "High" "${clean_ip}" "Endpoint service exposure" "SMB service is reachable from peer client network" "${OPEN_PORTS}" "Increases exposure to malware propagation, unauthorized file service discovery, and compliance exceptions." "Endpoint administrator" "Disable unnecessary SMB exposure, segment clients, and enforce SMB signing where SMB is required." "Re-run 05-common-services and 06-smb-posture after remediation."
        ;;
      135)
        SMB_REMEDIATION_NEEDED="true"
        add_issue "Medium" "${clean_ip}" "Windows service exposure" "Windows RPC endpoint tcp/135 is reachable from peer client network" "${OPEN_PORTS}" "Windows management service exposure should be limited to approved management networks." "Endpoint administrator" "Restrict Windows management service exposure to approved management subnets." "Re-run common service detection from the client network."
        ;;
      3389|5900)
        add_issue "Medium" "${clean_ip}" "Remote administration exposure" "Remote administration service tcp/${clean_port} is reachable" "${OPEN_PORTS}" "Remote administration surfaces should be limited to managed administration networks." "Endpoint administrator" "Restrict remote administration to approved management subnets and enforce strong access controls." "Re-run common service detection from the client network."
        ;;
      80|443|8080)
        add_issue "Low" "${clean_ip}" "Client web service exposure" "Web service tcp/${clean_port} is reachable on a client asset" "${OPEN_PORTS}" "Unexpected local web services may expose management consoles or test applications." "Asset owner" "Confirm business purpose and restrict or remove unnecessary service exposure." "Confirm service owner and re-run common service detection."
        ;;
    esac
  done < "${OPEN_PORTS}"
fi

SMB_SUMMARY="${SERVICE_DIR}/smb-posture-summary.txt"
if [[ -f "${SMB_SUMMARY}" ]]; then
  if grep -qi 'SMBv1.*enabled\|dialects.*NT LM 0.12\|NT LM 0.12' "${SMB_SUMMARY}"; then
    SMB_REMEDIATION_NEEDED="true"
    add_issue "High" "SMB hosts" "SMB protocol posture" "SMBv1 appears to be enabled on one or more SMB hosts" "${SMB_SUMMARY}" "SMBv1 is obsolete and materially increases ransomware and legacy protocol risk." "Endpoint administrator" "Disable SMBv1 and validate required business systems use SMBv2 or newer." "Re-run 06-smb-posture and confirm SMBv1 is absent."
  fi
  if grep -qi 'message signing.*disabled\|signing.*disabled\|not required' "${SMB_SUMMARY}"; then
    SMB_REMEDIATION_NEEDED="true"
    add_issue "Medium" "SMB hosts" "SMB protocol posture" "SMB signing is not enforced on one or more SMB hosts" "${SMB_SUMMARY}" "Unsigned SMB increases exposure to relay and integrity risks on local networks." "Endpoint administrator" "Require SMB signing where operationally feasible and validate compatibility." "Re-run 06-smb-posture and confirm signing requirement."
  fi
fi

GATEWAY_SUMMARY="${SERVICE_DIR}/gateway-service-version-summary.txt"
if [[ -f "${GATEWAY_SUMMARY}" ]]; then
  if grep -Eq '(^- |^[0-9]+/tcp[[:space:]]+open).*(80|443|8080|8443|domain|http)' "${GATEWAY_SUMMARY}"; then
    add_issue "Medium" "Default gateway" "Gateway service posture" "Gateway exposes management or infrastructure services to the local client network" "${GATEWAY_SUMMARY}" "Gateway services should be limited to required infrastructure and managed administration paths." "Network administrator" "Confirm each exposed service is required, restrict administrative interfaces, and document owner and firmware status." "Re-run 07-gateway-posture and review headers/service list."
  fi
fi

REACHABLE_COUNT="$(sort -u "${ASSET_DIR}/reachable-client-ips.txt" 2>/dev/null | sed '/^$/d' | wc -l | tr -d ' ')"
UNREACHABLE_COUNT="$(sort -u "${ASSET_DIR}/unreachable-client-ips.txt" 2>/dev/null | sed '/^$/d' | wc -l | tr -d ' ')"
if [[ "${REACHABLE_COUNT:-0}" -gt 0 ]]; then
  add_issue "Medium" "Client network" "Client isolation" "${REACHABLE_COUNT} client asset(s) responded to single-packet ICMP from peer network position" "${ASSET_DIR}/reachable-client-ips.txt" "Peer reachability may indicate insufficient client isolation and increases propagation risk." "Network administrator" "Review wireless and wired client isolation policy, VLAN ACLs, and firewall rules." "Re-run 04-client-isolation from the same network position."
fi

awk -F, '
  NR > 1 {
    sev=$2; asset=$3; cat=$4; gsub(/"/, "", sev); gsub(/"/, "", asset); gsub(/"/, "", cat)
    score[asset] += (sev == "High" ? 100 : sev == "Medium" ? 40 : 10)
    drivers[asset] = drivers[asset] (drivers[asset] ? "; " : "") cat ":" sev
  }
  END {
    for (asset in score) print score[asset] "," asset "," drivers[asset]
  }
' "${ISSUES}" | sort -rn | awk -F, '
  BEGIN { rank=1 }
  {
    level=($1 >= 100 ? "High" : $1 >= 40 ? "Medium" : "Low")
    priority=(level == "High" ? "Immediate" : level == "Medium" ? "Planned" : "Routine")
    gsub(/"/, "\"\"", $2); gsub(/"/, "\"\"", $3)
    printf "\"%d\",\"%s\",\"\",\"%s\",\"%s\",\"%s\",\"%s\",\"\"\n", rank, $2, level, $1, $3, priority
    rank++
  }
' >> "${RANKING}"

HIGH_COUNT="$(awk -F, 'NR>1 {gsub(/"/,"",$2); if ($2=="High") c++} END{print c+0}' "${ISSUES}")"
MED_COUNT="$(awk -F, 'NR>1 {gsub(/"/,"",$2); if ($2=="Medium") c++} END{print c+0}' "${ISSUES}")"
LOW_COUNT="$(awk -F, 'NR>1 {gsub(/"/,"",$2); if ($2=="Low") c++} END{print c+0}' "${ISSUES}")"

{
  printf '# High Risk Findings\n\n'
  printf -- '- Generated at: %s\n' "${STAMP}"
  printf -- '- High findings: %s\n\n' "${HIGH_COUNT}"
  awk -F, 'NR>1 {gsub(/"/,"",$2); if ($2=="High") print "- " $1 " " $3 " " $5}' "${ISSUES}" | sed 's/"//g'
} > "${HIGH}"

csv_row "Client isolation policy" "Network administrator" "yes" "no" "possible" "yes" "Coordinate with business network owner before enforcement." >> "${MATRIX}"
if [[ "${SMB_REMEDIATION_NEEDED}" == "true" ]]; then
  csv_row "Windows SMB hardening" "Endpoint administrator" "no" "yes" "possible" "yes" "Validate legacy application compatibility before changing SMB posture." >> "${MATRIX}"
fi
csv_row "Gateway service review" "Network administrator" "yes" "no" "possible" "yes" "Confirm vendor support and maintenance window." >> "${MATRIX}"

{
  printf '# Remediation Roadmap\n\n'
  printf -- '- Generated at: %s\n' "${STAMP}"
  printf -- '- Risk summary: High %s / Medium %s / Low %s\n\n' "${HIGH_COUNT}" "${MED_COUNT}" "${LOW_COUNT}"
  if [[ "${HIGH_COUNT}" -gt 0 ]]; then
    printf '## 0-7 days\n\n'
    awk -F '\t' '$1 == "High" {printf "- %s: %s. Recommended action: %s\n", $2, $4, $5}' "${ISSUE_TSV}"
    printf '\n'
  fi
  if [[ "${MED_COUNT}" -gt 0 ]]; then
    printf '## 8-30 days\n\n'
    awk -F '\t' '$1 == "Medium" {printf "- %s: %s. Recommended action: %s\n", $2, $4, $5}' "${ISSUE_TSV}"
    printf '\n'
  fi
  if [[ "${LOW_COUNT}" -gt 0 ]]; then
    printf '## 31-90 days\n\n'
    awk -F '\t' '$1 == "Low" {printf "- %s: %s. Recommended action: %s\n", $2, $4, $5}' "${ISSUE_TSV}"
    printf '\n'
  fi
  if [[ "${HIGH_COUNT}" -eq 0 && "${MED_COUNT}" -eq 0 && "${LOW_COUNT}" -eq 0 ]]; then
    printf 'No open remediation items were generated from the current evidence set.\n'
  fi
} > "${ROADMAP}"

if [[ "${SMB_REMEDIATION_NEEDED}" == "true" ]]; then
  {
    printf '# Windows SMB Remediation Ticket\n\n'
    printf '## Objective\n\nReduce confirmed Windows SMB or adjacent Windows service exposure identified in this run.\n\n'
    printf '## Evidence\n\n- %s\n- %s\n\n' "${OPEN_PORTS}" "${SMB_SUMMARY}"
    printf '## Validation\n\nRe-run `./05-common-services.sh` and `./06-smb-posture.sh`, then confirm SMB exposure and protocol posture in the generated summaries.\n'
  } > "${REMEDIATION_DIR}/windows-smb-remediation-ticket.md"
else
  {
    printf '# Windows SMB Remediation Ticket\n\n'
    printf 'No SMB remediation ticket was generated for this run because no SMB, tcp/135, tcp/139, tcp/445, SMBv1, or SMB signing finding was present in the current evidence set.\n'
  } > "${REMEDIATION_DIR}/windows-smb-remediation-ticket.md"
fi

{
  printf '# Client Isolation Remediation Ticket\n\n'
  printf '## Objective\n\nReduce peer-to-peer client reachability according to the approved network segmentation policy.\n\n'
  printf '## Evidence\n\n- %s\n- %s\n\n' "${ASSET_DIR}/reachable-client-ips.txt" "${ASSET_DIR}/client-profile.csv"
  printf '## Validation\n\nRe-run `./04-client-isolation.sh` from the same network position and compare reachable and unreachable client counts.\n'
} > "${REMEDIATION_DIR}/client-isolation-remediation-ticket.md"

{
  printf '# Executive Summary\n\n'
  printf -- '- Generated at: %s\n' "${STAMP}"
  printf -- '- Lab directory: %s\n' "${LAB_DIR}"
  printf -- '- Risk summary: High %s / Medium %s / Low %s\n' "${HIGH_COUNT}" "${MED_COUNT}" "${LOW_COUNT}"
  printf -- '- Reachable clients: %s\n' "${REACHABLE_COUNT:-0}"
  printf -- '- Unreachable clients: %s\n\n' "${UNREACHABLE_COUNT:-0}"
  printf 'This report summarizes authorized network governance observations, prioritized risks, and remediation actions. It does not include exploit activity, credential testing, or unauthorized configuration changes.\n'
  printf '\nFindings are point-in-time observations based on current ARP cache, ICMP reachability, and low-intensity common service checks.\n'
} > "${REPORT_DIR}/executive-summary.md"

{
  printf '# Technical Report\n\n'
  printf -- '- Generated at: %s\n' "${STAMP}"
  printf -- '- Evidence root: %s\n\n' "${LAB_DIR}"
  printf '## Evidence\n\n'
  printf -- '- Baseline: %s\n' "${LAB_DIR}/01-baseline"
  printf -- '- Assets: %s\n' "${ASSET_DIR}"
  printf -- '- Services: %s\n' "${SERVICE_DIR}"
  printf -- '- Risk register: %s\n' "${ISSUES}"
  printf -- '- Remediation roadmap: %s\n\n' "${ROADMAP}"
  printf '## Risk Summary\n\nHigh %s / Medium %s / Low %s\n' "${HIGH_COUNT}" "${MED_COUNT}" "${LOW_COUNT}"
} > "${REPORT_DIR}/technical-report.md"

{
  printf '# Evidence Index\n\n'
  find "${LAB_DIR}" -type f | sort | while read -r file; do
    printf -- '- %s\n' "${file}"
  done
} > "${REPORT_DIR}/evidence-index.md"

write_kv_summary "report_generated_at" "${STAMP}"
write_kv_summary "risk_summary" "High ${HIGH_COUNT} / Medium ${MED_COUNT} / Low ${LOW_COUNT}"

printf 'Report package generated in %s\n' "${REPORT_DIR}"
printf 'Risk summary: High %s / Medium %s / Low %s\n' "${HIGH_COUNT}" "${MED_COUNT}" "${LOW_COUNT}"
