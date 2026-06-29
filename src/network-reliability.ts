export type ReliabilityStatus = "healthy" | "warning" | "critical" | "unknown";
export type FaultDomain =
  | "none"
  | "physical_lan"
  | "interface"
  | "dhcp"
  | "gateway"
  | "local_dns"
  | "overlay_proxy"
  | "tailscale_exit_node"
  | "proxy_exit"
  | "external_path"
  | "local_service_exposure"
  | "unknown";

export interface PhysicalLanEvidence {
  activeInterface: string;
  interfaceKind: "wired" | "wifi" | "usb_ethernet" | "thunderbolt" | "iphone_usb" | "unknown";
  ipv4: string | null;
  ipv6?: string | null;
  subnetMask?: string | null;
  dhcpOk: boolean;
  dhcpServer?: string | null;
  dhcpRouter?: string | null;
  dhcpDns?: string[];
  dhcpLeaseSeconds?: number | null;
  gatewayIp?: string | null;
  gatewayPingLossPct?: number | null;
  gatewayPingMinMs?: number | null;
  gatewayPingAvgMs?: number | null;
  gatewayPingMaxMs?: number | null;
  gatewayPingStddevMs?: number | null;
  gatewayPingJitterMs?: number | null;
  gatewayPingP50Ms?: number | null;
  gatewayPingP95Ms?: number | null;
  gatewayPingP99Ms?: number | null;
  gatewayPingSamplesMs?: number[];
  gatewayPingSampleCount?: number | null;
  gatewayDnsMs?: number | null;
  gatewayDnsTimedOut?: boolean;
  arpSummary?: string;
  selfAssignedAddress?: boolean;
  iphoneHotspotLikely?: boolean;
  networkPathNotice?: string | null;
  multipleActiveInterfaces?: boolean;
}

export type ResolverQueryStatus = "ok" | "timeout" | "failed" | "not_tested";

export interface ResolverCheck {
  name: string;
  address: string;
  queryStatus: ResolverQueryStatus;
  responseMs?: number | null;
  resolvedIp?: string | null;
  viaOverlay?: boolean;
}

export interface LocalControlPlaneEvidence {
  systemDnsServers: string[];
  scopedResolvers: string[];
  resolverSummary: string;
  resolverChecks?: ResolverCheck[];
  mdnsSummary?: string;
  listeningServices: ListeningService[];
}

export interface ListeningService {
  name: string;
  bindAddress: string;
  port: number;
  process?: string;
}

export interface OverlayEvidence {
  defaultRouteInterface: string | null;
  defaultRouteGateway?: string | null;
  utunInterfaces: string[];
  hasProxyRange19818?: boolean;
  hasTailscaleRange10064?: boolean;
  hasTailscaleDns100100?: boolean;
  hasTailscaleIpv6Dns?: boolean;
  tailscaleRunning?: boolean;
  tailscaleExitNode?: boolean;
  tailscaleDnsEnabled?: boolean;
  stashDetected?: boolean;
  stashTunDetected?: boolean;
  stashPorts?: number[];
  clashDetected?: boolean;
  surgeDetected?: boolean;
  wireGuardDetected?: boolean;
  openVpnDetected?: boolean;
  multipleOverlayComponents?: boolean;
  dnsViaOverlay?: boolean;
}

export interface ExternalTargetTiming {
  group: "apple" | "developer" | "cdn" | "china_mainland" | "optional";
  url: string;
  dnsMs?: number | null;
  tcpConnectMs?: number | null;
  tlsMs?: number | null;
  ttfbMs?: number | null;
  totalMs?: number | null;
  status?: number | null;
  remoteIp?: string | null;
  failed?: boolean;
}

export interface ExternalEvidence {
  publicIp?: string | null;
  publicIpOrg?: string | null;
  publicIpLocation?: string | null;
  targets: ExternalTargetTiming[];
}

export interface NetworkReliabilityEvidence {
  profile: string;
  physicalLan: PhysicalLanEvidence;
  localControlPlane: LocalControlPlaneEvidence;
  overlay: OverlayEvidence;
  external: ExternalEvidence;
  rawEvidenceRefs?: string[];
  generatedAt?: string;
}

export interface NetworkReliabilityDiagnosis {
  overallStatus: ReliabilityStatus;
  physicalLanStatus: ReliabilityStatus;
  dnsStatus: ReliabilityStatus;
  overlayStatus: ReliabilityStatus;
  externalPathStatus: ReliabilityStatus;
  faultDomain: FaultDomain;
  faultPoint: string;
  currentPath: string;
  impact: string;
  evidence: string[];
  remediationAdvice: string[];
  retestPlan: string[];
  rawEvidenceRefs: string[];
}

export interface BaselineChange {
  field: string;
  before: string;
  after: string;
  possibleImpact: string;
  advice: string;
  retestPlan: string;
}

export const reliabilityThresholds = {
  gatewayLossWarningPct: 0,
  gatewayLossCriticalPct: 5,
  wiredGatewayWarningMs: 10,
  wiredGatewayCriticalMs: 50,
  wifiGatewayWarningMs: 30,
  gatewayDnsWarningMs: 100,
  systemDnsWarningMs: 200,
  httpsTotalWarningMs: 3000,
  httpsTotalCriticalMs: 8000,
  tcpConnectWarningMs: 1000,
  tlsWarningMs: 1500,
  ttfbWarningMs: 2000,
};

const exposedLocalPorts = new Set([3000, 5000, 5173, 6379, 7474, 7687, 5432, 3306, 8080]);

export function diagnoseNetworkReliability(evidence: NetworkReliabilityEvidence): NetworkReliabilityDiagnosis {
  const physicalLanStatus = physicalStatus(evidence.physicalLan);
  const dnsStatus = dnsStatusFromEvidence(evidence);
  const overlayStatus = overlayStatusFromEvidence(evidence.overlay);
  const externalPathStatus = externalStatusFromEvidence(evidence.external);
  const localExposure = exposedLocalService(evidence.localControlPlane.listeningServices);
  const allExternalFailed = evidence.external.targets.length > 0 && evidence.external.targets.every((target) => target.failed);
  const externalSlow = evidence.external.targets.some((target) => (target.totalMs ?? 0) > reliabilityThresholds.httpsTotalWarningMs || target.failed);
  const gatewayLoss = evidence.physicalLan.gatewayPingLossPct ?? 0;
  const gatewayLatency = evidence.physicalLan.gatewayPingAvgMs ?? 0;
  const gatewayDnsSlow = evidence.physicalLan.gatewayDnsTimedOut || (evidence.physicalLan.gatewayDnsMs ?? 0) > reliabilityThresholds.gatewayDnsWarningMs;
  const physicalHealthy = physicalLanStatus === "healthy";
  const defaultRouteOverlay = (evidence.overlay.defaultRouteInterface ?? "").startsWith("utun");
  const tailscaleDns = evidence.overlay.hasTailscaleDns100100 || evidence.overlay.hasTailscaleIpv6Dns;

  let faultDomain: FaultDomain = "none";
  let faultPoint = "No clear fault point detected.";
  let impact = "No immediate user-visible impact is indicated by the supplied observations.";
  const keyEvidence: string[] = [];
  const advice: string[] = [];
  const retest: string[] = [];

  if (!evidence.physicalLan.dhcpOk || evidence.physicalLan.selfAssignedAddress || !evidence.physicalLan.ipv4 || !evidence.physicalLan.gatewayIp) {
    faultDomain = "dhcp";
    faultPoint = "DHCP or local link issue detected.";
    impact = "The Mac may not have a usable local network path.";
    keyEvidence.push("The active interface does not have a complete DHCP address, router, and DNS set.");
    keyEvidence.push(`Interface ${evidence.physicalLan.activeInterface || "unknown"} has IPv4 ${evidence.physicalLan.ipv4 ?? "none"}.`);
    advice.push("Check the router DHCP service and the local link before testing external sites.");
    advice.push("Check cable, Wi-Fi association, adapter, or switch port outside LANPilot.");
    retest.push("Renew the lease outside LANPilot, then run Network Environment Check again.");
  } else if (gatewayLoss >= reliabilityThresholds.gatewayLossCriticalPct || gatewayLoss > reliabilityThresholds.gatewayLossWarningPct || gatewayLatencyCritical(evidence.physicalLan)) {
    faultDomain = "gateway";
    faultPoint = "Local gateway or physical link instability detected.";
    impact = "Local network instability can affect DNS, browsing, and app connectivity before traffic reaches the internet.";
    keyEvidence.push(`Gateway packet loss is ${gatewayLoss}%.`);
    keyEvidence.push(`Gateway average latency is ${gatewayLatency} ms.`);
    advice.push("Check Ethernet cable, switch port, router load, and USB Ethernet adapter.");
    advice.push("Retest with the current physical path isolated from overlay and proxy changes.");
    retest.push("Run gateway ping and gateway DNS timing again after the physical path is checked.");
  } else if (gatewayDnsSlow && physicalHealthy) {
    faultDomain = "local_dns";
    faultPoint = "Local DNS resolver or router DNS forwarding issue detected.";
    impact = "Name resolution can be slow even when the local gateway is reachable.";
    keyEvidence.push(`Gateway DNS timing is ${formatMs(evidence.physicalLan.gatewayDnsMs)}.`);
    keyEvidence.push(`Gateway ping loss is ${gatewayLoss}% with average latency ${gatewayLatency} ms.`);
    advice.push("Check router DNS forwarding and upstream DNS settings.");
    advice.push("Compare system DNS with direct gateway DNS, then review overlay DNS policy if present.");
    retest.push("Retest gateway DNS and system DNS separately.");
  } else if (evidence.overlay.tailscaleRunning && evidence.overlay.tailscaleExitNode && defaultRouteOverlay && tailscaleDns && externalSlow) {
    faultDomain = "tailscale_exit_node";
    faultPoint = "Tailscale Exit Node may be affecting external connectivity.";
    impact = "External traffic may be routed through a remote exit path instead of the local ISP path.";
    keyEvidence.push("Default route uses an overlay interface while Tailscale is running as an exit path.");
    keyEvidence.push("DNS uses Tailscale DNS and HTTPS timing is slow or failed.");
    advice.push("Disable Exit Node outside LANPilot and retest.");
    advice.push("Disable Tailscale DNS if it is not needed for this workflow.");
    advice.push("Keep Tailscale for remote access only if another proxy handles general internet access.");
    retest.push("Compare external HTTPS timing before and after the Exit Node change.");
  } else if (evidence.overlay.multipleOverlayComponents && defaultRouteOverlay && evidence.overlay.dnsViaOverlay) {
    faultDomain = "overlay_proxy";
    faultPoint = "Multiple overlay or proxy components are present and may conflict.";
    impact = "Routing and DNS may be controlled by different local components, causing inconsistent connectivity.";
    keyEvidence.push(`Default route interface is ${evidence.overlay.defaultRouteInterface ?? "unknown"}.`);
    keyEvidence.push("Multiple overlay components and overlay DNS were detected.");
    advice.push("Choose one component to control general internet access.");
    advice.push("Avoid enabling multiple overlay route controllers at the same time.");
    retest.push("Retest default route and DNS after changing overlay state outside LANPilot.");
  } else if (localExposure) {
    faultDomain = "local_service_exposure";
    faultPoint = "Local development service may be reachable from the LAN.";
    impact = "A local service that should be private may be visible to nearby network clients.";
    keyEvidence.push(`${localExposure.name} listens on ${localExposure.bindAddress}:${localExposure.port}.`);
    keyEvidence.push("The service is not limited to the loopback address.");
    advice.push("Bind development services to 127.0.0.1 if LAN access is not required.");
    advice.push("Avoid exposing local databases to the LAN unless it is intentional and documented.");
    retest.push("Retest local listening services after changing the service bind address outside LANPilot.");
  } else if (physicalHealthy && evidence.overlay.stashDetected && evidence.overlay.stashTunDetected && defaultRouteOverlay) {
    faultDomain = externalSlow ? "overlay_proxy" : "none";
    faultPoint = externalSlow ? "Proxy overlay path is the likely place to inspect." : "Physical LAN is healthy; internet path is currently handled by Stash TUN.";
    impact = externalSlow ? "External access may depend on proxy node, rule, DNS policy, or proxy exit quality." : "No physical LAN fault is indicated; traffic is intentionally using an overlay path.";
    keyEvidence.push("Physical LAN has DHCP, router, and stable gateway reachability.");
    keyEvidence.push("Default route uses an overlay interface and Stash indicators are present.");
    advice.push("If external access is slow, check Stash node, rule routing, DNS policy, and proxy exit.");
    advice.push("Compare direct gateway DNS with system DNS before blaming the router.");
    retest.push("Retest once with the overlay disabled outside LANPilot, then retest with Stash enabled.");
  } else if (physicalHealthy && allExternalFailed && defaultRouteOverlay) {
    faultDomain = "overlay_proxy";
    faultPoint = "External connectivity failure is likely in the overlay or proxy path.";
    impact = "Local LAN appears usable, but internet access through the overlay path fails.";
    keyEvidence.push("Gateway reachability and DNS are healthy.");
    keyEvidence.push("All external HTTPS targets failed while default route uses an overlay interface.");
    advice.push("Check proxy account, node health, firewall policy, and DNS policy.");
    advice.push("Retest direct gateway path outside LANPilot.");
    retest.push("Run Network Environment Check again after changing the overlay state outside LANPilot.");
  } else if (physicalHealthy && externalSlow) {
    faultDomain = defaultRouteOverlay ? "proxy_exit" : "external_path";
    faultPoint = defaultRouteOverlay ? "Proxy exit or external path performance issue detected." : "External path or remote service performance issue detected.";
    impact = "Local LAN checks are healthy, so user-visible slowness is likely beyond the local gateway.";
    keyEvidence.push("Gateway ping and local DNS are healthy.");
    keyEvidence.push("DNS, TCP, TLS, TTFB, or total HTTPS timing is slow for one or more external targets.");
    advice.push("Check proxy node, ISP route, target service status, and CDN region.");
    advice.push("Retest with proxy disabled and enabled outside LANPilot.");
    retest.push("Compare HTTPS timing across Apple, developer, CDN, and mainland reference targets.");
  }

  if (keyEvidence.length === 0) {
    keyEvidence.push("DHCP address, gateway, DNS, and external timing do not show a critical condition.");
    keyEvidence.push(`Current path: ${networkPath(evidence)}.`);
    advice.push("Save this result as a baseline for future comparison.");
    advice.push("If the user experience changes, compare a new snapshot against this baseline.");
    retest.push("Run the same check after any proxy, VPN, Wi-Fi, or adapter change.");
  }

  const overallStatus = [physicalLanStatus, dnsStatus, overlayStatus, externalPathStatus].includes("critical")
    ? "critical"
    : faultDomain !== "none" || [physicalLanStatus, dnsStatus, overlayStatus, externalPathStatus].includes("warning")
      ? "warning"
      : "healthy";

  return {
    overallStatus,
    physicalLanStatus,
    dnsStatus,
    overlayStatus,
    externalPathStatus,
    faultDomain,
    faultPoint,
    currentPath: networkPath(evidence),
    impact,
    evidence: keyEvidence,
    remediationAdvice: advice,
    retestPlan: retest,
    rawEvidenceRefs: evidence.rawEvidenceRefs ?? [],
  };
}

export function compareNetworkBaselines(previous: NetworkReliabilityEvidence, current: NetworkReliabilityEvidence): BaselineChange[] {
  const changes: BaselineChange[] = [];
  const add = (field: string, before: unknown, after: unknown, possibleImpact: string, advice: string, retestPlan: string) => {
    if (String(before ?? "") !== String(after ?? "")) changes.push({ field, before: String(before ?? "unknown"), after: String(after ?? "unknown"), possibleImpact, advice, retestPlan });
  };
  add("default route", previous.overlay.defaultRouteInterface, current.overlay.defaultRouteInterface, "Internet path may now be controlled by a different interface.", "Check whether the new route is expected for proxy, VPN, or physical LAN use.", "Retest default route, DNS, and external HTTPS timing.");
  add("DNS", previous.localControlPlane.systemDnsServers.join(","), current.localControlPlane.systemDnsServers.join(","), "Name resolution behavior may have changed.", "Compare system DNS with gateway DNS and overlay DNS.", "Retest DNS timing for gateway and system resolvers.");
  add("public IP", previous.external.publicIp, current.external.publicIp, "Traffic may be exiting through a different ISP, proxy, or exit node.", "Confirm whether the new public path is intentional.", "Retest Apple, developer, CDN, and mainland reference targets.");
  add("gateway", previous.physicalLan.gatewayIp, current.physicalLan.gatewayIp, "The local LAN or upstream router path may have changed.", "Check whether the device moved between home, office, hotel, or hotspot networks.", "Retest gateway latency and DHCP details.");
  add("interface", previous.physicalLan.activeInterface, current.physicalLan.activeInterface, "The physical adapter path changed.", "Confirm Wi-Fi, Ethernet, USB Ethernet, or tethering path is expected.", "Retest physical LAN before checking external targets.");
  add("Tailscale status", previous.overlay.tailscaleRunning, current.overlay.tailscaleRunning, "Remote access overlay state changed.", "Check Exit Node and DNS settings if external access changed.", "Retest with Tailscale state held constant.");
  add("Stash status", previous.overlay.stashDetected, current.overlay.stashDetected, "Proxy overlay state changed.", "Check proxy rules and exit node quality if timing changed.", "Retest with proxy state held constant.");
  add("gateway latency", previous.physicalLan.gatewayPingAvgMs, current.physicalLan.gatewayPingAvgMs, "Local LAN performance changed.", "Check cable, Wi-Fi quality, switch port, or router load.", "Retest gateway ping after local link checks.");
  add("local listening ports", servicePorts(previous).join(","), servicePorts(current).join(","), "Local service exposure changed.", "Confirm whether newly listening services are intentional.", "Retest local listening services after changing bind addresses.");
  return changes;
}

export function buildNetworkReliabilityMarkdown(diagnosis: NetworkReliabilityDiagnosis, evidence: NetworkReliabilityEvidence, language: "en" | "zh-CN" = "en"): string {
  const zh = language === "zh-CN";
  const heading = zh
    ? ["# 网络医生报告", "## 运行元数据", "## 总体诊断", "## 当前网络路径", "## 故障点", "## 影响判断", "## 关键证据", "## 根因候选", "## 反向证据", "## 处理建议", "## 复测方法", "## 物理网络", "## DNS", "## Overlay / 代理 / VPN", "## 外部网络", "## 本机监听服务", "## 原始证据"]
    : ["# Network Doctor Report", "## Run Metadata", "## Overall Diagnosis", "## Current Network Path", "## Fault Point", "## Impact", "## Key Evidence", "## Root Cause Candidates", "## Evidence Against", "## Troubleshooting Advice", "## Retest Plan", "## Physical LAN", "## DNS", "## Overlay / Proxy / VPN", "## External Internet", "## Local Listening Services", "## Raw Evidence"];
  const list = (values: string[]) => values.map((value) => `- ${value}`).join("\n") || "- None";
  const overlayInterface = evidence.overlay.defaultRouteInterface?.startsWith("utun") ? evidence.overlay.defaultRouteInterface : "none";
  return `${heading[0]}

${heading[1]}

- resultMode: real
- evidenceSource: local-collector
- lastRunAt: ${evidence.generatedAt ?? "unknown"}
- selectedInterface: ${evidence.physicalLan.activeInterface || "unknown"}
- physicalInterface: ${evidence.physicalLan.activeInterface || "unknown"}
- overlayInterface: ${overlayInterface}

${heading[2]}

${diagnosis.overallStatus}

${heading[3]}

${diagnosis.currentPath}

${heading[4]}

${diagnosis.faultPoint}

${heading[5]}

${diagnosis.impact}

${heading[6]}

${list(diagnosis.evidence)}

${heading[7]}

- ${diagnosis.faultDomain}: ${diagnosis.faultPoint}

${heading[8]}

- ${diagnosis.overallStatus === "healthy" ? "No strong counter-evidence is required for a healthy run." : "Compare gateway, DNS, overlay, and application timing before assigning ownership."}

${heading[9]}

${list(diagnosis.remediationAdvice)}

${heading[10]}

${list(diagnosis.retestPlan)}

${heading[11]}

- Interface: ${evidence.physicalLan.activeInterface}
- Gateway: ${evidence.physicalLan.gatewayIp ?? "unknown"}
- Gateway latency: ${formatMs(evidence.physicalLan.gatewayPingAvgMs)}

${heading[12]}

- System DNS: ${evidence.localControlPlane.systemDnsServers.join(", ") || "unknown"}
- Gateway DNS: ${formatMs(evidence.physicalLan.gatewayDnsMs)}

${heading[13]}

- Default route interface: ${evidence.overlay.defaultRouteInterface ?? "unknown"}
- Overlay components: ${overlayLabels(evidence.overlay).join(", ") || "none"}

${heading[14]}

${list(evidence.external.targets.map((target) => `${target.url}: total=${formatMs(target.totalMs)}, status=${target.status ?? "unknown"}`))}

${heading[15]}

${list(evidence.localControlPlane.listeningServices.map((service) => `${service.name} ${service.bindAddress}:${service.port}`))}

${heading[16]}

${list(diagnosis.rawEvidenceRefs)}
`;
}

function physicalStatus(evidence: PhysicalLanEvidence): ReliabilityStatus {
  if (!evidence.dhcpOk || evidence.selfAssignedAddress || !evidence.ipv4 || !evidence.gatewayIp) return "critical";
  const loss = evidence.gatewayPingLossPct ?? 0;
  if (loss >= reliabilityThresholds.gatewayLossCriticalPct || gatewayLatencyCritical(evidence)) return "critical";
  if (loss > reliabilityThresholds.gatewayLossWarningPct || gatewayLatencyWarning(evidence)) return "warning";
  return "healthy";
}

function dnsStatusFromEvidence(evidence: NetworkReliabilityEvidence): ReliabilityStatus {
  if (evidence.physicalLan.gatewayDnsTimedOut) return "critical";
  const systemDnsSlow = evidence.external.targets.some((target) => (target.dnsMs ?? 0) >= reliabilityThresholds.systemDnsWarningMs);
  if ((evidence.physicalLan.gatewayDnsMs ?? 0) > reliabilityThresholds.gatewayDnsWarningMs) return "warning";
  if (systemDnsSlow) return "warning";
  if (evidence.overlay.dnsViaOverlay || evidence.overlay.hasTailscaleDns100100 || evidence.overlay.hasTailscaleIpv6Dns) return "warning";
  return evidence.localControlPlane.systemDnsServers.length > 0 ? "healthy" : "unknown";
}

function overlayStatusFromEvidence(evidence: OverlayEvidence): ReliabilityStatus {
  if (evidence.multipleOverlayComponents && evidence.dnsViaOverlay) return "warning";
  if (evidence.tailscaleExitNode || evidence.stashTunDetected || (evidence.defaultRouteInterface ?? "").startsWith("utun")) return "warning";
  return "healthy";
}

function externalStatusFromEvidence(evidence: ExternalEvidence): ReliabilityStatus {
  if (evidence.targets.length === 0) return "unknown";
  if (evidence.targets.every((target) => target.failed)) return "critical";
  if (evidence.targets.some((target) => target.failed || (target.totalMs ?? 0) > reliabilityThresholds.httpsTotalWarningMs || (target.tcpConnectMs ?? 0) > reliabilityThresholds.tcpConnectWarningMs || (target.tlsMs ?? 0) > reliabilityThresholds.tlsWarningMs || (target.ttfbMs ?? 0) > reliabilityThresholds.ttfbWarningMs)) return "warning";
  return "healthy";
}

function gatewayLatencyWarning(evidence: PhysicalLanEvidence): boolean {
  const average = evidence.gatewayPingAvgMs ?? 0;
  const threshold = evidence.interfaceKind === "wifi" ? reliabilityThresholds.wifiGatewayWarningMs : reliabilityThresholds.wiredGatewayWarningMs;
  return average > threshold;
}

function gatewayLatencyCritical(evidence: PhysicalLanEvidence): boolean {
  return (evidence.gatewayPingAvgMs ?? 0) > reliabilityThresholds.wiredGatewayCriticalMs;
}

function exposedLocalService(services: ListeningService[]): ListeningService | null {
  return services.find((service) => exposedLocalPorts.has(service.port) && ["0.0.0.0", "*", "::"].includes(service.bindAddress)) ?? null;
}

function networkPath(evidence: NetworkReliabilityEvidence): string {
  const physical = `${evidence.physicalLan.activeInterface || "interface"}${evidence.physicalLan.ipv4 ? ` / ${evidence.physicalLan.ipv4}` : ""}`;
  const gateway = evidence.physicalLan.gatewayIp ?? "gateway not identified";
  if (evidence.overlay.tailscaleRunning && evidence.overlay.tailscaleExitNode) return `Mac -> ${physical} -> ${gateway} -> Tailscale / ${evidence.overlay.defaultRouteInterface ?? "utun"} -> Exit Node -> Internet`;
  if (evidence.overlay.stashDetected && evidence.overlay.stashTunDetected) return `Mac -> ${physical} -> ${gateway} -> Stash TUN / ${evidence.overlay.defaultRouteInterface ?? "utun"} -> Proxy exit -> Internet`;
  if ((evidence.overlay.defaultRouteInterface ?? "").startsWith("utun")) return `Mac -> ${physical} -> ${gateway} -> Overlay / ${evidence.overlay.defaultRouteInterface} -> Remote path -> Internet`;
  return `Mac -> ${physical} -> ${gateway} -> ISP -> Internet`;
}

function overlayLabels(evidence: OverlayEvidence): string[] {
  return [
    evidence.stashDetected ? "Stash" : "",
    evidence.tailscaleRunning ? "Tailscale" : "",
    evidence.wireGuardDetected ? "WireGuard" : "",
    evidence.openVpnDetected ? "OpenVPN" : "",
    evidence.clashDetected ? "Clash" : "",
    evidence.surgeDetected ? "Surge" : "",
  ].filter(Boolean);
}

function servicePorts(evidence: NetworkReliabilityEvidence): number[] {
  return evidence.localControlPlane.listeningServices.map((service) => service.port).sort((left, right) => left - right);
}

function formatMs(value?: number | null): string {
  return typeof value === "number" ? `${value} ms` : "unknown";
}
