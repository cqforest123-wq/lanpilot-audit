# LANPilot Audit

中小企业网络安全治理审计工具包。

本工具包用于授权范围内的防守型网络治理检测，目标是形成资产记录、隔离验证、服务暴露记录、风险台账、整改路线图和复测依据。它不是攻击工具，不包含 exploit、默认密码测试、爆破、横向移动或未授权登录能力。

版本 1.3.0 增加只读本机网络配置观察、短时 Bonjour/mDNS 服务观察、
轻量 Web/TLS 基线、增强资产清单、服务暴露矩阵、审计快照对比和本地
整改跟踪。新增步骤仍为固定白名单，不接受任意命令，不登录服务，不修改
网络配置，也不自动执行整改。

## 使用流程

每次进入授权网络后，从一个干净终端运行：

```bash
cd ~/lanpilot-audit
./01-init-lab.sh
```

`01-init-lab.sh` 会生成新的审计目录：

```text
~/lanpilot-audit-run-YYYYMMDD-HHMMSS
```

可以使用统一运行器完成全部步骤：

```bash
LANPILOT_INTERFACE=en0 ./run-audit.sh
```

也可以按顺序单独运行：

```bash
./02-baseline.sh
./03-passive-assets.sh
./04-client-isolation.sh
./05-common-services.sh
./06-smb-posture.sh
./07-gateway-posture.sh
./08-build-report.sh
./09-local-network-config.sh
./10-mdns-observation.sh
./11-web-tls-baseline.sh
./12-build-enhanced-governance-report.py
./13-build-formats.py
```

如果本机开启了 Stash、VPN 或其他代理工具，macOS 默认路由可能落到 `utun*` 隧道接口。工具包会尽量自动选择有 IPv4 的 LAN 接口；如需固定审计接口，可以显式指定：

```bash
LANPILOT_INTERFACE=en0 ./02-baseline.sh
```

后续脚本会读取 baseline 写入的审计接口和网关信息。

当前 `1.3.0` 能力：

1. 自动识别网段
2. 自动生成被动资产表
3. 自动做客户端隔离验证
4. 自动做 reachable 客户端常见服务检测
5. 自动生成风险台账和整改路线图
6. 自动生成静态 HTML 和 Excel 报告
7. 统一运行器、进度文件、日志和自动化测试
8. 确定性 SHA-256 引擎清单与 GitHub Actions 发布检查

## 依赖

macOS 自带工具：

- `route`
- `ifconfig`
- `arp`
- `netstat`
- `scutil`
- `ping`
- `curl`

可选工具：

- `nmap`：用于常见服务轻量识别、SMB 姿态检测、网关服务识别。缺少时对应脚本会记录并跳过。
- `smbutil`：预留用于后续 SMB 辅助识别。

## 当前脚本

- `01-init-lab.sh`：新建实验目录，生成授权说明模板、固定目录结构和 CSV 表头。
- `02-baseline.sh`：采集本机接口、IP、路由、DNS、ARP 快照和本机监听端口。
- `03-passive-assets.sh`：根据本机 ARP 缓存生成被动资产表和初始客户端画像。
- `04-client-isolation.sh`：对被动资产中的非网关客户端执行单包 ICMP 可达性验证。
- `05-common-services.sh`：只对 reachable 客户端做低强度常见端口和轻量版本识别。
- `06-smb-posture.sh`：只对已发现 SMB 端口的主机做非破坏性 SMB 协议和签名姿态检测。
- `07-gateway-posture.sh`：对默认网关做轻量服务识别和 Web 头信息检查。
- `08-build-report.sh`：生成风险台账、客户端风险排序、整改路线图、工单模板和报告包。
- `09-local-network-config.sh`：只读观察本机网络配置。
- `10-mdns-observation.sh`：短时观察 Bonjour/mDNS 服务公告。
- `11-web-tls-baseline.sh`：对已发现 Web 服务进行轻量 HTTP/TLS 基线观察。
- `12-build-enhanced-governance-report.py`：生成资产清单、暴露矩阵、快照差异和整改跟踪初始台账。
- `13-build-formats.py`：根据结构化证据生成 HTML 与 Excel 报告。
- `run-audit.sh`：按固定顺序运行完整审计并写入进度和日志。
- `tests/run-tests.sh`：验证脚本语法、报告一致性、CSV 行宽和 Excel 文件结构。

## 稳定性检查

发布或封装 APP 前，建议检查是否误引入超出治理审计边界的能力说明或命令。检查时排除 `.git` 目录，避免历史提交对象干扰判断：

```bash
grep --exclude-dir=.git -RniE 'exploit|vuln|brute|default-password|smb-enum|共享枚举|登录尝试|配置修改' ~/lanpilot-audit
```

如命中内容属于 README 的禁止事项或本检查命令本身，应人工复核语境；脚本中不应出现默认密码测试、爆破、利用、共享枚举、登录尝试或配置修改能力。

## 授权边界

允许：

- 被动 ARP 资产记录
- 单包 ICMP 客户端隔离验证
- 常见端口低强度检测
- 服务版本轻量识别
- SMB 协议姿态检测
- 风险台账和整改建议生成

禁止：

- 默认密码测试
- 爆破
- exploit
- NSE vuln 全量漏洞脚本
- 横向移动
- 未授权登录
- 未授权修改设备配置

## 输出目录

每次审计输出目录固定如下：

```text
lanpilot-audit-run-YYYYMMDD-HHMMSS/
  00-scope/
    authorization-note.md
    network-summary.txt

  01-baseline/
    baseline.txt
    local-listening-ports.txt
    route.txt
    dns.txt

  02-assets/
    passive-arp-assets.csv
    passive-neighbor-candidates.csv
    client-profile.csv
    reachable-client-ips.txt
    unreachable-client-ips.txt

  03-services/
    reachable-common-services.nmap
    common-services-run-summary.txt
    reachable-open-ports.csv
    service-version-summary.txt
    gateway-service-version-summary.txt
    smb-posture-summary.txt

  04-risk/
    network-issues-register.csv
    client-risk-ranking.csv
    high-risk-findings.md

  05-remediation/
    remediation-authority-matrix.csv
    remediation-roadmap.md
    windows-smb-remediation-ticket.md
    client-isolation-remediation-ticket.md

  06-report/
    executive-summary.md
    technical-report.md
    evidence-index.md
    lanpilot-audit-report.html
    lanpilot-audit-report.xlsx
```

## CSV 字段约定

CSV 文件必须使用固定表头，后续脚本只能追加符合表头的行。

`passive-arp-assets.csv`

```csv
ip,mac,interface,source,first_seen,last_seen,notes
```

`passive-neighbor-candidates.csv`

```csv
ip,mac,interface,relationship,source,observed_at,notes
```

`client-profile.csv`

```csv
ip,mac,interface,is_gateway,icmp_reachable,common_ports_open,smb_present,web_present,risk_hint,notes
```

`reachable-open-ports.csv`

```csv
ip,port,protocol,state,service,version,detected_at,notes
```

`network-issues-register.csv`

```csv
issue_id,severity,asset,category,finding,evidence_file,business_risk,remediation_owner,recommended_action,validation_method,status
```

`client-risk-ranking.csv`

```csv
rank,ip,mac,risk_level,score,drivers,recommended_priority,notes
```

`remediation-authority-matrix.csv`

```csv
item,owner_role,requires_network_admin,requires_endpoint_admin,requires_vendor,change_window_required,approval_notes
```

## 脚本原则

- 默认只输出发现、风险、整改建议和复测方法。
- 默认不修改任何网络设备或客户端配置。
- 默认低强度、低频率、可解释。
- 如果缺少 `nmap`、`smbutil` 等依赖，脚本应记录依赖缺失并跳过对应检测。
- 报告语言使用企业治理语言，避免使用攻击化表达。

## 开发验收

```bash
./tests/run-tests.sh
./scripts/verify-release.sh
```

Mac 桌面应用位于独立项目 `~/lanpilot-audit-app`，使用本仓库作为内置审计引擎。
