# Remediation Assistant

LANPilot Audit turns structured findings into a local remediation pack. It helps an authorized administrator assign ownership, document manual decisions, plan validation, and enter the existing authorized retest workflow.

The assistant does not apply changes, log in to services, accept arbitrary commands, or bypass the audit authorization flow. Recommendations are guidance for qualified administrators to evaluate and carry out manually under their own change-control process.

Generated files in `05-remediation/`:

- `remediation-pack.json`
- `remediation-tickets.csv`
- `remediation-playbook.md`
- `remediation-verification-plan.md`
- `remediation-acceptance-records.csv`

An exported audit ZIP includes these files. Retest uses the same authorization confirmation and fixed allowlisted audit steps as a normal audit.

LANPilot 不执行自动整改、不登录服务、不接受任意命令，也不修改网络设备或客户端配置。整改助手只生成本地结构化建议、人工步骤、验证计划和治理记录；复测仍须重新确认授权。
