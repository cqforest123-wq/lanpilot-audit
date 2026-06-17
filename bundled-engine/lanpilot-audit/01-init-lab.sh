#!/usr/bin/env bash
set -euo pipefail

KIT_NAME="LANPilot Audit"
KIT_VERSION="1.3.0"
ROOT_DIR="${LANPILOT_AUDIT_ROOT:-$HOME}"
OPERATOR="${LANPILOT_OPERATOR:-$(id -un)}"
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
LAB_DIR="${ROOT_DIR}/lanpilot-audit-run-${TIMESTAMP}"

umask 077

create_directories() {
  mkdir -p \
    "${LAB_DIR}/00-scope" \
    "${LAB_DIR}/01-baseline" \
    "${LAB_DIR}/02-assets" \
    "${LAB_DIR}/03-services" \
    "${LAB_DIR}/04-risk" \
    "${LAB_DIR}/05-remediation" \
    "${LAB_DIR}/06-report" \
    "${LAB_DIR}/07-history" \
    "${LAB_DIR}/00-scope/step-status"
}

write_authorization_note() {
  cat > "${LAB_DIR}/00-scope/authorization-note.md" <<EOF
# 授权与范围记录

- 工具包：${KIT_NAME}
- 版本：${KIT_VERSION}
- 实验目录：${LAB_DIR}
- 创建时间：$(date '+%Y-%m-%d %H:%M:%S %Z')
- 操作者：${OPERATOR}

## 审计定位

本次工作定位为中小企业网络安全治理审计，仅用于授权范围内的资产记录、客户端隔离验证、服务暴露记录、风险台账和整改建议生成。

## 授权范围

- 授权单位：
- 授权联系人：
- 授权网络位置：
- 授权网段：
- 授权时间窗口：
- 允许检测项：
- 排除资产：

## 明确禁止事项

- 默认密码测试
- 爆破
- exploit
- NSE vuln 全量漏洞脚本
- 横向移动
- 未授权登录
- 未授权修改设备配置

## 操作确认

- [ ] 已确认当前网络为授权网络
- [ ] 已确认检测时间在授权窗口内
- [ ] 已确认不会修改网络设备或客户端配置
- [ ] 已确认输出仅用于治理审计和整改复测
EOF
}

write_network_summary_placeholder() {
  cat > "${LAB_DIR}/00-scope/network-summary.txt" <<EOF
${KIT_NAME} ${KIT_VERSION}
created_at=$(date '+%Y-%m-%d %H:%M:%S %Z')
operator=${OPERATOR}
lab_dir=${LAB_DIR}

This file will be updated by later steps with local network, gateway, DNS, route, and scope summary details.
EOF
}

write_csv_headers() {
  printf 'ip,mac,interface,source,first_seen,last_seen,notes\n' > "${LAB_DIR}/02-assets/passive-arp-assets.csv"
  printf 'ip,mac,interface,relationship,source,observed_at,notes\n' > "${LAB_DIR}/02-assets/passive-neighbor-candidates.csv"
  printf 'ip,mac,interface,is_gateway,icmp_reachable,common_ports_open,smb_present,web_present,risk_hint,notes\n' > "${LAB_DIR}/02-assets/client-profile.csv"
  printf 'ip,port,protocol,state,service,version,detected_at,notes\n' > "${LAB_DIR}/03-services/reachable-open-ports.csv"
  printf 'issue_id,severity,asset,category,finding,evidence_file,business_risk,remediation_owner,recommended_action,validation_method,status\n' > "${LAB_DIR}/04-risk/network-issues-register.csv"
  printf 'rank,ip,mac,risk_level,score,drivers,recommended_priority,notes\n' > "${LAB_DIR}/04-risk/client-risk-ranking.csv"
  printf 'item,owner_role,requires_network_admin,requires_endpoint_admin,requires_vendor,change_window_required,approval_notes\n' > "${LAB_DIR}/05-remediation/remediation-authority-matrix.csv"
  printf 'ip,mac,vendor,reachability,observed_services,device_category_guess,risk_level,first_seen,last_seen\n' > "${LAB_DIR}/02-assets/asset-inventory.csv"
  printf 'asset,service,port,protocol,exposure_type,business_justification_status,recommended_owner,risk_level,recommended_action\n' > "${LAB_DIR}/03-services/service-exposure-matrix.csv"
  printf 'service_type,instance_name,hostname,observed_at,risk_note\n' > "${LAB_DIR}/03-services/mdns-services.csv"
  printf 'asset,port,status_code,server_header,title,hsts,x_frame_options,x_content_type_options,content_security_policy,observed_at\n' > "${LAB_DIR}/03-services/web-baseline.csv"
  printf 'asset,port,subject,issuer,not_before,not_after,days_until_expiry,protocol_info,observed_at\n' > "${LAB_DIR}/03-services/tls-certificates.csv"
  printf 'finding_id,owner,due_date,status,notes,priority,business_justification\n' > "${LAB_DIR}/05-remediation/remediation-tracking.csv"
}

write_placeholders() {
  : > "${LAB_DIR}/01-baseline/baseline.txt"
  : > "${LAB_DIR}/01-baseline/local-listening-ports.txt"
  : > "${LAB_DIR}/01-baseline/route.txt"
  : > "${LAB_DIR}/01-baseline/dns.txt"
  : > "${LAB_DIR}/02-assets/reachable-client-ips.txt"
  : > "${LAB_DIR}/02-assets/unreachable-client-ips.txt"
  : > "${LAB_DIR}/03-services/reachable-common-services.nmap"
  : > "${LAB_DIR}/03-services/common-services-run-summary.txt"
  : > "${LAB_DIR}/03-services/service-version-summary.txt"
  : > "${LAB_DIR}/03-services/gateway-service-version-summary.txt"
  : > "${LAB_DIR}/03-services/smb-posture-summary.txt"
  : > "${LAB_DIR}/04-risk/high-risk-findings.md"
  : > "${LAB_DIR}/05-remediation/remediation-roadmap.md"
  : > "${LAB_DIR}/05-remediation/windows-smb-remediation-ticket.md"
  : > "${LAB_DIR}/05-remediation/client-isolation-remediation-ticket.md"
  : > "${LAB_DIR}/06-report/executive-summary.md"
  : > "${LAB_DIR}/06-report/technical-report.md"
  : > "${LAB_DIR}/06-report/evidence-index.md"
  : > "${LAB_DIR}/06-report/lanpilot-audit-report.html"
  : > "${LAB_DIR}/06-report/lanpilot-audit-report.xlsx"
  : > "${LAB_DIR}/06-report/asset-inventory-summary.md"
  : > "${LAB_DIR}/06-report/service-exposure-summary.md"
  : > "${LAB_DIR}/06-report/local-network-config-summary.md"
  : > "${LAB_DIR}/06-report/mdns-summary.md"
  : > "${LAB_DIR}/06-report/web-tls-summary.md"
  : > "${LAB_DIR}/06-report/snapshot-diff.md"
  printf '{}\n' > "${LAB_DIR}/01-baseline/local-network-config.json"
  printf '{}\n' > "${LAB_DIR}/05-remediation/remediation-tracking.json"
  printf '{}\n' > "${LAB_DIR}/07-history/snapshot-diff.json"
}

main() {
  create_directories
  write_authorization_note
  write_network_summary_placeholder
  write_csv_headers
  write_placeholders

  ln -sfn "${LAB_DIR}" "${ROOT_DIR}/lanpilot-audit-latest"

  printf 'Created lab directory: %s\n' "${LAB_DIR}"
  printf 'Latest symlink: %s\n' "${ROOT_DIR}/lanpilot-audit-latest"
  printf 'Next step: review %s, then run ./02-baseline.sh when ready.\n' "${LAB_DIR}/00-scope/authorization-note.md"
}

main "$@"
