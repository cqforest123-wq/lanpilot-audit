import type {
  ExternalTargetTiming,
  NetworkReliabilityEvidence,
  OverlayEvidence,
  ReliabilityStatus,
} from "./network-reliability";

export type DoctorMode = "quick" | "deep";
export type DiagnosticDomain =
  | "local_host"
  | "physical_interface"
  | "wifi_radio"
  | "ethernet_link"
  | "dhcp"
  | "gateway"
  | "local_dns"
  | "system_dns"
  | "route"
  | "overlay_proxy"
  | "tailscale"
  | "transport_tcp"
  | "transport_udp"
  | "tls"
  | "external_path"
  | "application_endpoint"
  | "router_health"
  | "unknown";
export type OsiLayer = "L1" | "L2" | "L3" | "L4" | "L5-L6" | "L7";
export type DoctorConfidence = "High" | "Medium" | "Low";
export type DoctorScoreState = "Excellent" | "Healthy" | "Acceptable" | "Warning" | "Critical";
export type TransportState = "reachable" | "refused" | "timeout" | "tls_failed" | "certificate_invalid" | "application_error" | "inconclusive";

export interface DoctorModeProfile {
  mode: DoctorMode;
  targetDurationSeconds: [number, number];
  gatewaySampleTarget: [number, number];
}

export interface DoctorLocalHostObservation {
  macosVersion?: string;
  listeningSummary?: string;
}

export interface DoctorPhysicalInterfaceObservation {
  name: string;
  kind: "wifi" | "ethernet" | "usb_ethernet" | "thunderbolt" | "iphone_usb" | "unknown";
  ipv4: string | null;
  ipv6?: string | null;
  selfAssigned?: boolean;
  multipleActivePhysicalInterfaces?: boolean;
}

export interface DoctorWifiObservation {
  active?: boolean;
  ssid?: string | null;
  rssiDbm?: number | null;
  noiseDbm?: number | null;
  snrDb?: number | null;
  channel?: number | null;
  band?: "2.4GHz" | "5GHz" | "6GHz" | "unknown";
  channelWidthMhz?: number | null;
  phyMode?: string | null;
  transmitRateMbps?: number | null;
  mcs?: number | null;
  associationChanges?: number;
  dfsChannel?: boolean;
  unavailableFields?: string[];
}

export interface DoctorDhcpObservation {
  ok: boolean;
  server?: string | null;
  router?: string | null;
  dnsServers?: string[];
}

export interface DoctorGatewayObservation {
  ip?: string | null;
  mac?: string | null;
  sampleCount: number;
  minMs?: number | null;
  avgMs?: number | null;
  maxMs?: number | null;
  stddevMs?: number | null;
  jitterMs?: number | null;
  p50Ms?: number | null;
  p95Ms?: number | null;
  p99Ms?: number | null;
  samplesMs?: number[];
  lossPct?: number | null;
  arpChanged?: boolean;
}

export interface DoctorDnsResolverCheck {
  name: string;
  address: string;
  icmpReachable?: boolean | null;
  queryStatus: "ok" | "timeout" | "failed" | "not_tested";
  responseMs?: number | null;
  resolvedIp?: string | null;
  viaOverlay?: boolean;
}

export interface DoctorDnsObservation {
  dhcpDnsServers?: string[];
  systemDnsServers?: string[];
  gatewayDnsServers?: string[];
  resolverChecks?: DoctorDnsResolverCheck[];
}

export interface DoctorRouteObservation {
  defaultInterface?: string | null;
  physicalInterface?: string | null;
  physicalGateway?: string | null;
  defaultUsesOverlay?: boolean;
}

export interface DoctorOverlayAttribution {
  interface: string;
  ownerType: "proxy" | "vpn" | "tailscale" | "unknown";
  ownerName: string;
  confidence: number;
  evidence: string[];
  controlsDefaultRoute?: boolean;
  controlsDns?: boolean;
  healthy?: boolean;
}

export interface DoctorPathTiming {
  name: string;
  pathType: "direct" | "system" | "explicit_proxy" | "remote_probe";
  publicIp?: string | null;
  country?: string | null;
  asn?: string | null;
  provider?: string | null;
  responseMs?: number | null;
  success: boolean;
}

export interface DoctorTransportCheck {
  name: string;
  protocol: "tcp" | "udp" | "quic";
  host: string;
  port: number;
  state: TransportState;
  latencyMs?: number | null;
}

export interface DoctorTlsCheck {
  name: string;
  host: string;
  state: "ok" | "handshake_failed" | "certificate_invalid" | "hostname_mismatch" | "expired" | "not_tested";
  handshakeMs?: number | null;
  expiresInDays?: number | null;
  protocolVersion?: string | null;
}

export interface DoctorApplicationCheck {
  group: string;
  url: string;
  state: TransportState;
  dnsMs?: number | null;
  tcpMs?: number | null;
  tlsMs?: number | null;
  ttfbMs?: number | null;
  totalMs?: number | null;
  status?: number | null;
  remoteIp?: string | null;
}

export interface DoctorRouterHealthObservation {
  enabled?: boolean;
  profile?: "generic_linux" | "asuswrt_merlin" | "openwrt" | "unknown_readonly";
  cpuLoad?: number | null;
  cpuCores?: number | null;
  memoryUsedPct?: number | null;
  storageUsedPct?: number | null;
  conntrackUsedPct?: number | null;
  wanState?: "up" | "down" | "unknown";
  evidence?: string[];
}

export interface NetworkDoctorObservations {
  localHost?: DoctorLocalHostObservation;
  physicalInterface?: Partial<DoctorPhysicalInterfaceObservation>;
  wifi?: DoctorWifiObservation;
  dhcp?: Partial<DoctorDhcpObservation>;
  gateway?: Partial<DoctorGatewayObservation>;
  dns?: DoctorDnsObservation;
  route?: DoctorRouteObservation;
  overlays?: DoctorOverlayAttribution[];
  pathTimings?: DoctorPathTiming[];
  transport?: DoctorTransportCheck[];
  tls?: DoctorTlsCheck[];
  applications?: DoctorApplicationCheck[];
  routerHealth?: DoctorRouterHealthObservation;
}

export interface NetworkDoctorEvidence {
  profile: string;
  mode?: DoctorMode;
  generatedAt?: string;
  observations?: NetworkDoctorObservations;
  rawEvidenceRefs?: string[];
}

interface CompleteNetworkDoctorEvidence extends NetworkDoctorEvidence {
  mode: DoctorMode;
  observations: {
    localHost: DoctorLocalHostObservation;
    physicalInterface: DoctorPhysicalInterfaceObservation;
    wifi: DoctorWifiObservation;
    dhcp: DoctorDhcpObservation;
    gateway: DoctorGatewayObservation;
    dns: Required<DoctorDnsObservation>;
    route: DoctorRouteObservation;
    overlays: DoctorOverlayAttribution[];
    pathTimings: DoctorPathTiming[];
    transport: DoctorTransportCheck[];
    tls: DoctorTlsCheck[];
    applications: DoctorApplicationCheck[];
    routerHealth: DoctorRouterHealthObservation;
  };
}

export interface DomainStatus {
  domain: DiagnosticDomain;
  status: ReliabilityStatus;
  score: number;
  confidence: DoctorConfidence;
  evidence: string[];
}

export interface OsiLayerMapping {
  domain: DiagnosticDomain;
  layers: OsiLayer[];
  explanation: string;
}

export interface DoctorGraphNode {
  id: string;
  label: string;
  domain: DiagnosticDomain;
  status: ReliabilityStatus;
  metrics: Record<string, string | number | null>;
  evidence: string[];
  confidence: DoctorConfidence;
  startedAt?: string;
  completedAt?: string;
}

export interface DoctorGraphEdge {
  from: string;
  to: string;
  relation: "uses" | "routes_through" | "resolves_via" | "tunnels_through" | "connects_to" | "depends_on";
}

export interface DiagnosisGraph {
  nodes: DoctorGraphNode[];
  edges: DoctorGraphEdge[];
}

export interface DoctorAdvice {
  action: string;
  reason: string;
  risk: string;
  expectedResult: string;
  verification: string;
}

export interface RootCauseCandidate {
  rank: number;
  faultDomain: DiagnosticDomain;
  title: string;
  probability: number;
  confidence: DoctorConfidence;
  impact: "High" | "Medium" | "Low";
  evidenceFor: string[];
  evidenceAgainst: string[];
  remediationAdvice: DoctorAdvice[];
  retestPlan: string[];
}

export interface DoctorScorecard {
  name: "Physical LAN" | "Wi-Fi" | "Gateway" | "DNS" | "Overlay / Proxy" | "External Path" | "Application Access";
  score: number;
  state: DoctorScoreState;
  status: ReliabilityStatus;
}

export interface RouterConnectorSafetyModel {
  defaultEnabled: false;
  readOnly: true;
  requiresExplicitAuthorization: true;
  storesSecretMaterialInKeychain: true;
  writesSecretMaterialToReports: false;
  allowlistedProfiles: DoctorRouterHealthObservation["profile"][];
}

export interface NetworkDoctorReport {
  mode: DoctorMode;
  modeProfile: DoctorModeProfile;
  actualDurationSeconds: number | null;
  overallScore: number;
  overallState: DoctorScoreState;
  overallStatus: ReliabilityStatus;
  currentNetworkPath: string;
  primaryFaultDomain: DiagnosticDomain;
  contributingDomains: DiagnosticDomain[];
  domainStatuses: DomainStatus[];
  osiLayerMapping: OsiLayerMapping[];
  scorecards: DoctorScorecard[];
  graph: DiagnosisGraph;
  rootCauseCandidates: RootCauseCandidate[];
  recommendedActions: DoctorAdvice[];
  retestPlan: string[];
  rawEvidenceRefs: string[];
  routerConnectorSafety: RouterConnectorSafetyModel;
}

const domainLayerMap: Record<DiagnosticDomain, OsiLayer[]> = {
  local_host: ["L7"],
  physical_interface: ["L1", "L2"],
  wifi_radio: ["L1", "L2"],
  ethernet_link: ["L1", "L2"],
  dhcp: ["L3"],
  gateway: ["L3"],
  local_dns: ["L7"],
  system_dns: ["L7"],
  route: ["L3"],
  overlay_proxy: ["L5-L6"],
  tailscale: ["L5-L6"],
  transport_tcp: ["L4"],
  transport_udp: ["L4"],
  tls: ["L5-L6"],
  external_path: ["L3", "L4"],
  application_endpoint: ["L7"],
  router_health: ["L3"],
  unknown: [],
};

const defaultEvidence: CompleteNetworkDoctorEvidence = {
  profile: "Healthy direct Ethernet",
  mode: "quick",
  rawEvidenceRefs: ["network-doctor-observations.json"],
  observations: {
    localHost: { macosVersion: "macOS demo", listeningSummary: "No notable local listeners" },
    physicalInterface: { name: "en5", kind: "ethernet", ipv4: "192.0.2.20", ipv6: null, selfAssigned: false, multipleActivePhysicalInterfaces: false },
    wifi: { active: false, unavailableFields: [] },
    dhcp: { ok: true, server: "192.0.2.1", router: "192.0.2.1", dnsServers: ["192.0.2.1"] },
    gateway: { ip: "192.0.2.1", mac: "hidden", sampleCount: 16, minMs: 1.8, avgMs: 2.4, maxMs: 4.2, stddevMs: 0.6, jitterMs: 0.8, lossPct: 0, arpChanged: false },
    dns: {
      dhcpDnsServers: ["192.0.2.1"],
      systemDnsServers: ["192.0.2.1"],
      gatewayDnsServers: ["192.0.2.1"],
      resolverChecks: [{ name: "Gateway DNS", address: "192.0.2.1", icmpReachable: true, queryStatus: "ok", responseMs: 8, resolvedIp: "203.0.113.10", viaOverlay: false }],
    },
    route: { defaultInterface: "en5", physicalInterface: "en5", physicalGateway: "192.0.2.1", defaultUsesOverlay: false },
    overlays: [],
    pathTimings: [{ name: "System path", pathType: "system", publicIp: "203.0.113.20", country: "Demo", asn: "AS64500", provider: "Demo ISP", responseMs: 520, success: true }],
    transport: [{ name: "GitHub TCP", protocol: "tcp", host: "github.com", port: 443, state: "reachable", latencyMs: 120 }],
    tls: [{ name: "GitHub TLS", host: "github.com", state: "ok", handshakeMs: 180, expiresInDays: 90, protocolVersion: "TLS 1.3" }],
    applications: [{ group: "GitHub", url: "https://github.com", state: "reachable", dnsMs: 20, tcpMs: 120, tlsMs: 180, ttfbMs: 260, totalMs: 720, status: 200, remoteIp: "203.0.113.10" }],
    routerHealth: { enabled: false, profile: "unknown_readonly", wanState: "unknown", evidence: [] },
  },
};

export function doctorModeProfile(mode: DoctorMode): DoctorModeProfile {
  return mode === "deep"
    ? { mode, targetDurationSeconds: [120, 300], gatewaySampleTarget: [100, 200] }
    : { mode, targetDurationSeconds: [20, 30], gatewaySampleTarget: [10, 20] };
}

export function diagnoseNetworkDoctor(input: NetworkDoctorEvidence | NetworkReliabilityEvidence, requestedMode?: DoctorMode): NetworkDoctorReport {
  const evidence = completeEvidence(input, requestedMode);
  const modeProfile = doctorModeProfile(evidence.mode);
  const domainStatuses = evaluateDomains(evidence);
  const primaryFaultDomain = pickPrimaryFaultDomain(domainStatuses);
  const contributingDomains = domainStatuses
    .filter((item) => item.domain !== primaryFaultDomain && item.status !== "healthy" && item.status !== "unknown")
    .map((item) => item.domain);
  const scorecards = buildScorecards(domainStatuses);
  const overallScore = calculateOverallScore(scorecards, domainStatuses);
  const rootCauseCandidates = rankRootCauses(evidence, domainStatuses, primaryFaultDomain);
  const graph = buildDiagnosisGraph(evidence, domainStatuses);

  return {
    mode: evidence.mode,
    modeProfile,
    actualDurationSeconds: actualDurationSeconds(evidence, modeProfile),
    overallScore,
    overallState: scoreState(overallScore),
    overallStatus: reliabilityStatusFromScore(overallScore),
    currentNetworkPath: currentNetworkPath(evidence),
    primaryFaultDomain,
    contributingDomains,
    domainStatuses,
    osiLayerMapping: [primaryFaultDomain, ...contributingDomains].map((domain) => ({
      domain,
      layers: domainLayerMap[domain],
      explanation: `${domain} maps to ${domainLayerMap[domain].join(" / ")} in the user-facing view.`,
    })),
    scorecards,
    graph,
    rootCauseCandidates,
    recommendedActions: rootCauseCandidates[0]?.remediationAdvice ?? [],
    retestPlan: rootCauseCandidates[0]?.retestPlan ?? [],
    rawEvidenceRefs: evidence.rawEvidenceRefs ?? [],
    routerConnectorSafety: {
      defaultEnabled: false,
      readOnly: true,
      requiresExplicitAuthorization: true,
      storesSecretMaterialInKeychain: true,
      writesSecretMaterialToReports: false,
      allowlistedProfiles: ["generic_linux", "asuswrt_merlin", "openwrt", "unknown_readonly"],
    },
  };
}

export function normalizeNetworkDoctorEvidence(input: NetworkDoctorEvidence | NetworkReliabilityEvidence): CompleteNetworkDoctorEvidence {
  return completeEvidence(input);
}

function completeEvidence(input: NetworkDoctorEvidence | NetworkReliabilityEvidence, requestedMode?: DoctorMode): CompleteNetworkDoctorEvidence {
  const source = hasDoctorObservations(input) ? input : fromReliabilityEvidence(input);
  const observations = source.observations ?? {};
  return {
    profile: source.profile || defaultEvidence.profile,
    mode: requestedMode ?? source.mode ?? defaultEvidence.mode,
    generatedAt: source.generatedAt,
    rawEvidenceRefs: source.rawEvidenceRefs ?? defaultEvidence.rawEvidenceRefs,
    observations: {
      localHost: { ...defaultEvidence.observations.localHost, ...observations.localHost },
      physicalInterface: { ...defaultEvidence.observations.physicalInterface, ...observations.physicalInterface },
      wifi: { ...defaultEvidence.observations.wifi, ...observations.wifi },
      dhcp: { ...defaultEvidence.observations.dhcp, ...observations.dhcp },
      gateway: { ...defaultEvidence.observations.gateway, ...observations.gateway },
      dns: { ...defaultEvidence.observations.dns, ...observations.dns },
      route: { ...defaultEvidence.observations.route, ...observations.route },
      overlays: observations.overlays ?? defaultEvidence.observations.overlays,
      pathTimings: observations.pathTimings ?? defaultEvidence.observations.pathTimings,
      transport: observations.transport ?? defaultEvidence.observations.transport,
      tls: observations.tls ?? defaultEvidence.observations.tls,
      applications: observations.applications ?? defaultEvidence.observations.applications,
      routerHealth: { ...defaultEvidence.observations.routerHealth, ...observations.routerHealth },
    },
  };
}

function hasDoctorObservations(input: NetworkDoctorEvidence | NetworkReliabilityEvidence): input is NetworkDoctorEvidence {
  return "observations" in input || "mode" in input;
}

function fromReliabilityEvidence(evidence: NetworkReliabilityEvidence): NetworkDoctorEvidence {
  const physical = evidence.physicalLan;
  const overlay = evidence.overlay;
  const gatewayJitter = physical.gatewayPingJitterMs ?? null;
  return {
    profile: evidence.profile,
    mode: "quick",
    generatedAt: evidence.generatedAt,
    rawEvidenceRefs: evidence.rawEvidenceRefs,
    observations: {
      physicalInterface: {
        name: physical.activeInterface,
        kind: physical.interfaceKind === "wired" ? "ethernet" : physical.interfaceKind,
        ipv4: physical.ipv4,
        ipv6: physical.ipv6,
        selfAssigned: physical.selfAssignedAddress,
        multipleActivePhysicalInterfaces: physical.multipleActiveInterfaces,
      },
      wifi: { active: physical.interfaceKind === "wifi" },
      dhcp: { ok: physical.dhcpOk, server: physical.dhcpServer, router: physical.dhcpRouter, dnsServers: physical.dhcpDns ?? [] },
      gateway: {
        ip: physical.gatewayIp,
        sampleCount: physical.gatewayPingSampleCount ?? 16,
        minMs: typeof physical.gatewayPingAvgMs === "number" && typeof gatewayJitter === "number" ? Math.max(0, physical.gatewayPingAvgMs - gatewayJitter) : null,
        avgMs: physical.gatewayPingAvgMs,
        maxMs: typeof physical.gatewayPingAvgMs === "number" && typeof gatewayJitter === "number" ? physical.gatewayPingAvgMs + gatewayJitter : null,
        stddevMs: gatewayJitter,
        jitterMs: gatewayJitter,
        lossPct: physical.gatewayPingLossPct,
        arpChanged: false,
      },
      dns: {
        dhcpDnsServers: physical.dhcpDns ?? [],
        systemDnsServers: evidence.localControlPlane.systemDnsServers,
        gatewayDnsServers: physical.gatewayIp ? [physical.gatewayIp] : [],
        resolverChecks: [
          {
            name: "Gateway DNS",
            address: physical.gatewayIp ?? "gateway",
            queryStatus: physical.gatewayDnsTimedOut ? "timeout" : "ok",
            responseMs: physical.gatewayDnsMs,
            viaOverlay: false,
          },
          ...evidence.localControlPlane.systemDnsServers.map((address) => ({
            name: "System DNS",
            address,
            queryStatus: "ok" as const,
            responseMs: firstNumber(evidence.external.targets.map((target) => target.dnsMs)),
            viaOverlay: evidence.overlay.dnsViaOverlay,
          })),
        ],
      },
      route: {
        defaultInterface: overlay.defaultRouteInterface,
        physicalInterface: physical.activeInterface,
        physicalGateway: physical.gatewayIp,
        defaultUsesOverlay: Boolean(overlay.defaultRouteInterface?.startsWith("utun")),
      },
      overlays: overlayAttributionsFromReliability(overlay),
      pathTimings: [{
        name: "System path",
        pathType: "system",
        publicIp: evidence.external.publicIp,
        provider: evidence.external.publicIpOrg,
        country: evidence.external.publicIpLocation,
        responseMs: firstNumber(evidence.external.targets.map((target) => target.totalMs)),
        success: !evidence.external.targets.every((target) => target.failed),
      }],
      transport: evidence.external.targets.map((target) => transportFromExternalTarget(target)),
      tls: evidence.external.targets.map((target) => ({
        name: target.url,
        host: hostFromUrl(target.url),
        state: target.failed && typeof target.tcpConnectMs === "number" ? "handshake_failed" as const : "ok" as const,
        handshakeMs: target.tlsMs,
        expiresInDays: null,
        protocolVersion: null,
      })),
      applications: evidence.external.targets.map((target) => applicationFromExternalTarget(target)),
    },
  };
}

function overlayAttributionsFromReliability(overlay: OverlayEvidence): DoctorOverlayAttribution[] {
  const overlays: DoctorOverlayAttribution[] = [];
  if (overlay.stashDetected || overlay.stashTunDetected) {
    overlays.push({
      interface: overlay.defaultRouteInterface ?? overlay.utunInterfaces[0] ?? "utun",
      ownerType: "proxy",
      ownerName: "Stash",
      confidence: overlay.hasProxyRange19818 && overlay.stashTunDetected ? 0.94 : 0.72,
      evidence: [
        overlay.hasProxyRange19818 ? "198.18.0.0/16 route observed" : "Stash process or port indicator observed",
        overlay.defaultRouteInterface?.startsWith("utun") ? "Default route uses a utun interface" : "Default route does not use Stash TUN",
      ],
      controlsDefaultRoute: overlay.defaultRouteInterface?.startsWith("utun"),
      controlsDns: overlay.dnsViaOverlay,
      healthy: !overlay.multipleOverlayComponents,
    });
  }
  if (overlay.tailscaleRunning) {
    overlays.push({
      interface: overlay.defaultRouteInterface ?? overlay.utunInterfaces[0] ?? "utun",
      ownerType: "tailscale",
      ownerName: "Tailscale",
      confidence: overlay.hasTailscaleDns100100 || overlay.hasTailscaleRange10064 ? 0.9 : 0.68,
      evidence: [
        overlay.hasTailscaleRange10064 ? "100.64.0.0/10 range observed" : "Tailscale process observed",
        overlay.hasTailscaleDns100100 ? "100.100.100.100 resolver observed" : "No Tailscale DNS resolver observed",
      ],
      controlsDefaultRoute: overlay.tailscaleExitNode,
      controlsDns: overlay.tailscaleDnsEnabled,
      healthy: !overlay.tailscaleExitNode,
    });
  }
  if (!overlays.length && overlay.defaultRouteInterface?.startsWith("utun")) {
    overlays.push({
      interface: overlay.defaultRouteInterface,
      ownerType: "unknown",
      ownerName: "Unknown overlay",
      confidence: 0.45,
      evidence: ["Default route uses a utun interface without a confident owner."],
      controlsDefaultRoute: true,
      controlsDns: overlay.dnsViaOverlay,
      healthy: false,
    });
  }
  return overlays;
}

function transportFromExternalTarget(target: ExternalTargetTiming): DoctorTransportCheck {
  return {
    name: target.url,
    protocol: "tcp",
    host: hostFromUrl(target.url),
    port: 443,
    state: target.failed ? "timeout" : "reachable",
    latencyMs: target.tcpConnectMs,
  };
}

function applicationFromExternalTarget(target: ExternalTargetTiming): DoctorApplicationCheck {
  return {
    group: target.group,
    url: target.url,
    state: target.failed ? "application_error" : "reachable",
    dnsMs: target.dnsMs,
    tcpMs: target.tcpConnectMs,
    tlsMs: target.tlsMs,
    ttfbMs: target.ttfbMs,
    totalMs: target.totalMs,
    status: target.status,
    remoteIp: target.remoteIp,
  };
}

function evaluateDomains(evidence: CompleteNetworkDoctorEvidence): DomainStatus[] {
  const observations = evidence.observations;
  const statuses: DomainStatus[] = [];
  const add = (domain: DiagnosticDomain, status: ReliabilityStatus, score: number, confidence: DoctorConfidence, evidenceItems: string[]) =>
    statuses.push({ domain, status, score, confidence, evidence: evidenceItems });

  const gateway = observations.gateway;
  const gatewayLoss = gateway.lossPct ?? 0;
  const gatewayAvg = gateway.avgMs ?? 0;
  const gatewayJitter = gateway.jitterMs ?? gateway.stddevMs ?? 0;
  const lowGatewaySamples = gateway.sampleCount < 3;
  const wifi = observations.wifi;
  const dnsChecks = observations.dns.resolverChecks;
  const queryFailures = dnsChecks.filter((check) => check.queryStatus === "timeout" || check.queryStatus === "failed");
  const slowDns = dnsChecks.filter((check) => check.queryStatus === "ok" && (check.responseMs ?? 0) >= 200);
  const overlays = observations.overlays;
  const overlayConflict = overlays.filter((item) => item.controlsDefaultRoute || item.controlsDns).length > 1;
  const applicationSlow = observations.applications.some((item) => (item.totalMs ?? 0) > 3000 || (item.ttfbMs ?? 0) > 2000);
  const allApplicationsFailed = observations.applications.length > 0 && observations.applications.every((item) => item.state !== "reachable");
  const tcpProblem = observations.transport.find((item) => item.protocol === "tcp" && (item.state === "timeout" || item.state === "refused"));
  const tlsProblem = observations.tls.find((item) => item.state !== "ok" && item.state !== "not_tested");
  const router = observations.routerHealth;

  add("local_host", "healthy", 92, "Medium", [observations.localHost.listeningSummary ?? "Local host observation completed."]);
  add("physical_interface", observations.physicalInterface.ipv4 && !observations.physicalInterface.selfAssigned ? "healthy" : "critical", observations.physicalInterface.ipv4 && !observations.physicalInterface.selfAssigned ? 90 : 20, "High", [
    `Interface ${observations.physicalInterface.name} has IPv4 ${observations.physicalInterface.ipv4 ?? "none"}.`,
  ]);
  add("ethernet_link", observations.physicalInterface.kind === "ethernet" || observations.physicalInterface.kind === "usb_ethernet" ? gatewayStatus(gateway) : "unknown", gatewayScore(gateway), lowGatewaySamples ? "Low" : "Medium", [
    `Gateway samples: ${gateway.sampleCount}, average ${formatMetric(gatewayAvg)} ms, loss ${formatMetric(gatewayLoss)}%.`,
  ]);
  add("wifi_radio", wifiStatus(wifi, gatewayJitter), wifiScore(wifi, gatewayJitter), wifi.active ? "Medium" : "Low", wifiEvidence(wifi, gatewayJitter));
  add("dhcp", observations.dhcp.ok && !observations.physicalInterface.selfAssigned ? "healthy" : "critical", observations.dhcp.ok && !observations.physicalInterface.selfAssigned ? 92 : 10, "High", [
    observations.dhcp.ok ? "DHCP supplied an address, router, and resolver set." : "DHCP did not supply a complete local configuration.",
  ]);
  add("gateway", gatewayStatus(gateway), gatewayScore(gateway), lowGatewaySamples ? "Low" : "High", [
    `Gateway ${gateway.ip ?? "unknown"} loss ${formatMetric(gatewayLoss)}%, average ${formatMetric(gatewayAvg)} ms, jitter ${formatMetric(gatewayJitter)} ms.`,
  ]);
  add("local_dns", dnsDomainStatus(queryFailures, slowDns, false), dnsScore(queryFailures, slowDns, false), "Medium", dnsEvidence(dnsChecks, false));
  add("system_dns", dnsDomainStatus(queryFailures, slowDns, true), dnsScore(queryFailures, slowDns, true), "Medium", dnsEvidence(dnsChecks, true));
  const unhealthyOverlayControl = overlays.some((item) => (item.controlsDefaultRoute || item.controlsDns) && item.healthy === false);
  const tailscaleExitIssue = overlays.some((item) => item.ownerType === "tailscale" && item.controlsDefaultRoute && item.healthy === false);
  add("route", observations.route.defaultUsesOverlay && unhealthyOverlayControl ? "warning" : "healthy", observations.route.defaultUsesOverlay && unhealthyOverlayControl ? 70 : 92, "Medium", [
    observations.route.defaultUsesOverlay ? `Default route intentionally uses ${observations.route.defaultInterface ?? "overlay"}.` : `Default route uses ${observations.route.defaultInterface ?? "unknown"}.`,
  ]);
  add("overlay_proxy", overlayConflict || overlays.some((item) => item.ownerType === "proxy" && item.healthy === false) ? "warning" : "healthy", overlayConflict ? 58 : overlays.some((item) => item.ownerType === "proxy" && item.healthy === false) ? 60 : 92, "Medium", overlayEvidence(overlays));
  add("tailscale", tailscaleExitIssue ? "critical" : "healthy", tailscaleExitIssue ? 35 : 90, "Medium", overlayEvidence(overlays.filter((item) => item.ownerType === "tailscale")));
  add("transport_tcp", tcpProblem ? tcpProblem.state === "timeout" ? "critical" : "warning" : "healthy", tcpProblem ? tcpProblem.state === "timeout" ? 28 : 62 : 90, "Medium", tcpProblem ? [`TCP ${tcpProblem.state} observed for ${tcpProblem.host}:${tcpProblem.port}.`] : ["TCP checks are reachable."]);
  add("transport_udp", observations.transport.some((item) => item.protocol !== "tcp" && item.state === "inconclusive") ? "unknown" : "healthy", 82, "Low", ["UDP and QUIC observations are treated as inconclusive unless a safe endpoint is available."]);
  add("tls", tlsProblem ? "critical" : "healthy", tlsProblem ? 34 : 90, "Medium", tlsProblem ? [`TLS state ${tlsProblem.state} observed for ${tlsProblem.host}.`] : ["TLS checks completed without a reported handshake or certificate issue."]);
  const externalPathStatus = tcpProblem || tlsProblem ? "warning" : allApplicationsFailed ? "critical" : applicationSlow ? "warning" : "healthy";
  const externalPathScore = tcpProblem || tlsProblem ? 66 : allApplicationsFailed ? 22 : applicationSlow ? 66 : 90;
  add("external_path", externalPathStatus, externalPathScore, "Medium", [
    applicationSlow || allApplicationsFailed ? "One or more external path timings are slow or failed." : "External path timings are inside the current baseline window.",
  ]);
  const applicationStatus = tcpProblem || tlsProblem ? "warning" : applicationProblemStatus(observations.applications);
  const applicationDomainScore = tcpProblem || tlsProblem ? Math.max(60, applicationScore(observations.applications)) : applicationScore(observations.applications);
  add("application_endpoint", applicationStatus, applicationDomainScore, "Medium", applicationEvidence(observations.applications));
  add("router_health", routerStatus(router), routerScore(router), router.enabled ? "Medium" : "Low", routerEvidence(router));
  add("unknown", "unknown", 70, "Low", ["No single observation fully explains every symptom."]);
  return statuses;
}

function pickPrimaryFaultDomain(statuses: DomainStatus[]): DiagnosticDomain {
  const priority: DiagnosticDomain[] = [
    "dhcp",
    "physical_interface",
    "wifi_radio",
    "gateway",
    "local_dns",
    "system_dns",
    "tailscale",
    "overlay_proxy",
    "transport_tcp",
    "tls",
    "application_endpoint",
    "external_path",
    "router_health",
  ];
  for (const domain of priority) {
    const item = statuses.find((status) => status.domain === domain);
    if (item?.status === "critical") return domain;
  }
  for (const domain of priority) {
    const item = statuses.find((status) => status.domain === domain);
    if (item?.status === "warning") return domain;
  }
  return "unknown";
}

function rankRootCauses(evidence: CompleteNetworkDoctorEvidence, statuses: DomainStatus[], primary: DiagnosticDomain): RootCauseCandidate[] {
  const candidates = new Map<DiagnosticDomain, RootCauseCandidate>();
  const add = (domain: DiagnosticDomain, probability: number, confidence: DoctorConfidence, impact: "High" | "Medium" | "Low") => {
    const status = statuses.find((item) => item.domain === domain);
    candidates.set(domain, buildCandidate(domain, status, evidence, probability, confidence, impact));
  };
  add(primary, primary === "unknown" ? 40 : 72, confidenceForPrimary(statuses, primary), primaryImpact(primary));

  const supporting = statuses
    .filter((item) => item.domain !== primary && item.status !== "healthy" && item.status !== "unknown")
    .sort((left, right) => left.score - right.score)
    .slice(0, 2);
  supporting.forEach((item, index) => add(item.domain, index === 0 ? 22 : 14, item.confidence, item.status === "critical" ? "Medium" : "Low"));

  if (candidates.size < 2) add(evidence.observations.route.defaultUsesOverlay ? "overlay_proxy" : "external_path", 18, "Low", "Low");
  if (candidates.size < 3) add("gateway", primary === "gateway" ? 72 : 8, primary === "gateway" ? confidenceForPrimary(statuses, primary) : "Low", primary === "gateway" ? "High" : "Low");

  return Array.from(candidates.values())
    .sort((left, right) => right.probability - left.probability)
    .map((candidate, index) => ({ ...candidate, rank: index + 1 }));
}

function buildCandidate(
  domain: DiagnosticDomain,
  status: DomainStatus | undefined,
  evidence: CompleteNetworkDoctorEvidence,
  probability: number,
  confidence: DoctorConfidence,
  impact: "High" | "Medium" | "Low",
): RootCauseCandidate {
  const physicalHealthy = statusesHealthy(evidence, ["dhcp", "gateway"]);
  const titles: Record<DiagnosticDomain, string> = {
    local_host: "Local host state requires review",
    physical_interface: "Physical interface is missing a usable address",
    wifi_radio: "Wi-Fi radio quality or channel conditions may be degrading the path",
    ethernet_link: "Ethernet link may be unstable",
    dhcp: "DHCP or local address assignment is incomplete",
    gateway: "Local gateway or first-hop path instability",
    local_dns: "Local gateway DNS forwarding is slow or unavailable",
    system_dns: "System DNS path differs from the local resolver path",
    route: "Default route differs from the expected physical path",
    overlay_proxy: "Overlay or proxy path is the likely inspection point",
    tailscale: "Tailscale exit path or DNS policy may be affecting access",
    transport_tcp: "TCP connection state explains the application failure",
    transport_udp: "UDP or QUIC result is inconclusive",
    tls: "TLS handshake or certificate validation is failing",
    external_path: "External ISP, CDN, or remote path degradation",
    application_endpoint: "Application endpoint is slow or returning errors",
    router_health: "Router resource pressure may affect forwarding",
    unknown: "No clear fault detected",
  };
  return {
    rank: 0,
    faultDomain: domain,
    title: titles[domain],
    probability,
    confidence,
    impact,
    evidenceFor: status?.evidence.length ? status.evidence : [],
    evidenceAgainst: evidenceAgainst(domain, evidence, physicalHealthy),
    remediationAdvice: adviceForDomain(domain),
    retestPlan: retestForDomain(domain),
  };
}

function buildScorecards(statuses: DomainStatus[]): DoctorScorecard[] {
  const byDomain = (domain: DiagnosticDomain) => statuses.find((item) => item.domain === domain)?.score ?? 70;
  const card = (name: DoctorScorecard["name"], score: number): DoctorScorecard => ({
    name,
    score,
    state: scoreState(score),
    status: reliabilityStatusFromScore(score),
  });
  return [
    card("Physical LAN", Math.min(byDomain("physical_interface"), byDomain("dhcp"), byDomain("gateway"))),
    card("Wi-Fi", byDomain("wifi_radio")),
    card("Gateway", byDomain("gateway")),
    card("DNS", Math.min(byDomain("local_dns"), byDomain("system_dns"))),
    card("Overlay / Proxy", Math.min(byDomain("overlay_proxy"), byDomain("tailscale"))),
    card("External Path", byDomain("external_path")),
    card("Application Access", Math.min(byDomain("transport_tcp"), byDomain("tls"), byDomain("application_endpoint"))),
  ];
}

function calculateOverallScore(scorecards: DoctorScorecard[], statuses: DomainStatus[]): number {
  const physicalCritical = statuses.some((item) => ["physical_interface", "dhcp", "gateway"].includes(item.domain) && item.status === "critical");
  const weighted = Math.round(
    scorecards.reduce((sum, card) => sum + card.score * scoreWeight(card.name), 0) /
    scorecards.reduce((sum, card) => sum + scoreWeight(card.name), 0),
  );
  return physicalCritical ? Math.min(weighted, 39) : weighted;
}

function buildDiagnosisGraph(evidence: CompleteNetworkDoctorEvidence, statuses: DomainStatus[]): DiagnosisGraph {
  const statusFor = (domain: DiagnosticDomain) => statuses.find((item) => item.domain === domain);
  const node = (id: string, label: string, domain: DiagnosticDomain, metrics: Record<string, string | number | null>, nodeEvidence: string[]): DoctorGraphNode => ({
    id,
    label,
    domain,
    status: statusFor(domain)?.status ?? "unknown",
    metrics,
    evidence: nodeEvidence,
    confidence: statusFor(domain)?.confidence ?? "Low",
    startedAt: evidence.generatedAt,
    completedAt: evidence.generatedAt,
  });
  const observations = evidence.observations;
  const nodes: DoctorGraphNode[] = [
    node("mac", "Mac", "local_host", { profile: evidence.profile }, ["Local host state observed."]),
    node("physical", observations.physicalInterface.name, observations.physicalInterface.kind === "wifi" ? "wifi_radio" : "ethernet_link", { ipv4: observations.physicalInterface.ipv4 }, [`Active physical interface is ${observations.physicalInterface.name}.`]),
    node("dhcp", "DHCP", "dhcp", { server: observations.dhcp.server ?? null, router: observations.dhcp.router ?? null }, ["DHCP lease details observed."]),
    node("gateway", observations.gateway.ip ?? "Gateway", "gateway", { avgMs: observations.gateway.avgMs ?? null, lossPct: observations.gateway.lossPct ?? null }, ["First-hop gateway timing observed."]),
    node("dns", "System DNS", "system_dns", { resolvers: observations.dns.systemDnsServers.join(", ") }, ["Resolver behavior checked with DNS queries."]),
    node("route", observations.route.defaultInterface ?? "Route", "route", { defaultInterface: observations.route.defaultInterface ?? null }, ["Default route and physical route compared."]),
  ];
  for (const overlay of observations.overlays) {
    nodes.push(node(`overlay-${overlay.interface}`, overlay.ownerName, overlay.ownerType === "tailscale" ? "tailscale" : "overlay_proxy", { interface: overlay.interface, confidence: overlay.confidence }, overlay.evidence));
  }
  nodes.push(node("tcp", "TCP", "transport_tcp", { checks: observations.transport.length }, ["TCP connection states summarized."]));
  nodes.push(node("tls", "TLS", "tls", { checks: observations.tls.length }, ["TLS handshake states summarized."]));
  nodes.push(node("application", "Application Endpoint", "application_endpoint", { checks: observations.applications.length }, ["Application HTTPS checks summarized."]));
  const edges: DoctorGraphEdge[] = [
    { from: "mac", to: "physical", relation: "uses" },
    { from: "physical", to: "dhcp", relation: "depends_on" },
    { from: "physical", to: "gateway", relation: "connects_to" },
    { from: "mac", to: "dns", relation: "resolves_via" },
    { from: "gateway", to: "route", relation: "routes_through" },
  ];
  let previous = "route";
  for (const overlay of observations.overlays.filter((item) => item.controlsDefaultRoute || item.controlsDns)) {
    const id = `overlay-${overlay.interface}`;
    edges.push({ from: previous, to: id, relation: "tunnels_through" });
    previous = id;
  }
  edges.push({ from: previous, to: "tcp", relation: "connects_to" });
  edges.push({ from: "tcp", to: "tls", relation: "depends_on" });
  edges.push({ from: "tls", to: "application", relation: "connects_to" });
  return { nodes, edges };
}

function currentNetworkPath(evidence: CompleteNetworkDoctorEvidence): string {
  const observations = evidence.observations;
  const base = [`Mac`, observations.physicalInterface.name, observations.gateway.ip ?? "Gateway"];
  const controlling = observations.overlays.filter((item) => item.controlsDefaultRoute);
  if (controlling.length) base.push(...controlling.map((item) => `${item.ownerName} ${item.interface}`));
  const exit = observations.pathTimings.find((item) => item.pathType !== "direct" && item.provider)?.provider ?? "Internet";
  base.push(exit);
  return base.join(" -> ");
}

function actualDurationSeconds(evidence: CompleteNetworkDoctorEvidence, modeProfile: DoctorModeProfile): number | null {
  const samples = evidence.observations.gateway.sampleCount;
  if (samples <= 0) return null;
  const [minSamples, maxSamples] = modeProfile.gatewaySampleTarget;
  const [minSeconds, maxSeconds] = modeProfile.targetDurationSeconds;
  const ratio = Math.min(1, Math.max(0, (samples - minSamples) / Math.max(1, maxSamples - minSamples)));
  return Math.round(minSeconds + (maxSeconds - minSeconds) * ratio);
}

function gatewayStatus(gateway: DoctorGatewayObservation): ReliabilityStatus {
  const sampleAwareConfidence = gateway.sampleCount >= 3;
  if ((gateway.lossPct ?? 0) >= 5) return "critical";
  if (sampleAwareConfidence && (gateway.avgMs ?? 0) > 50) return "critical";
  if ((gateway.lossPct ?? 0) > 0 || (gateway.avgMs ?? 0) > 30 || (gateway.jitterMs ?? 0) > 25 || gateway.arpChanged) return "warning";
  return "healthy";
}

function gatewayScore(gateway: DoctorGatewayObservation): number {
  if ((gateway.lossPct ?? 0) >= 5) return 25;
  if (gateway.sampleCount >= 3 && (gateway.avgMs ?? 0) > 50) return 35;
  if ((gateway.lossPct ?? 0) > 0 || (gateway.jitterMs ?? 0) > 25) return 62;
  return 92;
}

function wifiStatus(wifi: DoctorWifiObservation, gatewayJitter: number): ReliabilityStatus {
  if (!wifi.active) return "unknown";
  if ((wifi.rssiDbm ?? 0) < -78 || (wifi.snrDb ?? 99) < 18 || gatewayJitter > 35) return "warning";
  if (wifi.dfsChannel || (wifi.channelWidthMhz ?? 0) >= 160 || (wifi.associationChanges ?? 0) > 2) return "warning";
  return "healthy";
}

function wifiScore(wifi: DoctorWifiObservation, gatewayJitter: number): number {
  if (!wifi.active) return 82;
  if ((wifi.rssiDbm ?? 0) < -78 || (wifi.snrDb ?? 99) < 18 || gatewayJitter > 35) return 60;
  if (wifi.dfsChannel || (wifi.channelWidthMhz ?? 0) >= 160) return 74;
  return 90;
}

function wifiEvidence(wifi: DoctorWifiObservation, gatewayJitter: number): string[] {
  if (!wifi.active) return ["Wi-Fi is not the active physical path."];
  return [
    `RSSI ${wifi.rssiDbm ?? "unavailable"}, SNR ${wifi.snrDb ?? "unavailable"}, channel width ${wifi.channelWidthMhz ?? "unavailable"} MHz.`,
    `Gateway jitter while on Wi-Fi is ${formatMetric(gatewayJitter)} ms.`,
  ];
}

function dnsDomainStatus(queryFailures: DoctorDnsResolverCheck[], slowDns: DoctorDnsResolverCheck[], systemOnly: boolean): ReliabilityStatus {
  const relevantFailures = queryFailures.filter((check) => systemOnly ? check.viaOverlay : !check.viaOverlay);
  const relevantSlow = slowDns.filter((check) => systemOnly ? check.viaOverlay : !check.viaOverlay);
  if (relevantFailures.length) return "critical";
  if (relevantSlow.length) return "warning";
  return "healthy";
}

function dnsScore(queryFailures: DoctorDnsResolverCheck[], slowDns: DoctorDnsResolverCheck[], systemOnly: boolean): number {
  const relevantFailures = queryFailures.filter((check) => systemOnly ? check.viaOverlay : !check.viaOverlay);
  const relevantSlow = slowDns.filter((check) => systemOnly ? check.viaOverlay : !check.viaOverlay);
  if (relevantFailures.length) return 30;
  if (relevantSlow.length) return 68;
  return 90;
}

function dnsEvidence(checks: DoctorDnsResolverCheck[], systemOnly: boolean): string[] {
  const relevant = checks.filter((check) => systemOnly ? check.viaOverlay : !check.viaOverlay);
  if (!relevant.length) return [systemOnly ? "No overlay-scoped resolver was observed." : "No direct resolver check was available."];
  return relevant.slice(0, 3).map((check) => `${check.name} ${check.address}: query ${check.queryStatus}, response ${formatNullableMetric(check.responseMs)} ms, ICMP ${check.icmpReachable === false ? "not responding" : "not decisive"}.`);
}

function overlayEvidence(overlays: DoctorOverlayAttribution[]): string[] {
  if (!overlays.length) return ["No overlay owner attribution was required for the current route."];
  return overlays.flatMap((item) => [`${item.interface} attributed to ${item.ownerName} with ${(item.confidence * 100).toFixed(0)}% confidence.`, ...item.evidence]).slice(0, 4);
}

function applicationProblemStatus(applications: DoctorApplicationCheck[]): ReliabilityStatus {
  if (!applications.length) return "unknown";
  if (applications.every((item) => item.state !== "reachable")) return "critical";
  if (applications.some((item) => item.state !== "reachable" || (item.totalMs ?? 0) > 3000 || (item.ttfbMs ?? 0) > 2000)) return "warning";
  return "healthy";
}

function applicationScore(applications: DoctorApplicationCheck[]): number {
  if (!applications.length) return 70;
  if (applications.every((item) => item.state !== "reachable")) return 24;
  if (applications.some((item) => item.state !== "reachable" || (item.totalMs ?? 0) > 3000 || (item.ttfbMs ?? 0) > 2000)) return 64;
  return 90;
}

function applicationEvidence(applications: DoctorApplicationCheck[]): string[] {
  if (!applications.length) return ["No application endpoint checks were configured."];
  return applications.slice(0, 3).map((item) => `${item.group} ${item.url}: ${item.state}, TTFB ${formatNullableMetric(item.ttfbMs)} ms, total ${formatNullableMetric(item.totalMs)} ms.`);
}

function routerStatus(router: DoctorRouterHealthObservation): ReliabilityStatus {
  if (!router.enabled) return "unknown";
  if ((router.conntrackUsedPct ?? 0) >= 90 || (router.memoryUsedPct ?? 0) >= 92 || router.wanState === "down") return "critical";
  if ((router.conntrackUsedPct ?? 0) >= 75 || (router.memoryUsedPct ?? 0) >= 82 || (router.storageUsedPct ?? 0) >= 90) return "warning";
  return "healthy";
}

function routerScore(router: DoctorRouterHealthObservation): number {
  if (!router.enabled) return 82;
  if ((router.conntrackUsedPct ?? 0) >= 90 || (router.memoryUsedPct ?? 0) >= 92 || router.wanState === "down") return 32;
  if ((router.conntrackUsedPct ?? 0) >= 75 || (router.memoryUsedPct ?? 0) >= 82 || (router.storageUsedPct ?? 0) >= 90) return 62;
  return 88;
}

function routerEvidence(router: DoctorRouterHealthObservation): string[] {
  if (!router.enabled) return ["Router read-only health check was not enabled for this run."];
  return [
    `Router profile ${router.profile ?? "unknown_readonly"}, memory ${formatNullableMetric(router.memoryUsedPct)}%, conntrack ${formatNullableMetric(router.conntrackUsedPct)}%.`,
    ...(router.evidence ?? []),
  ];
}

function evidenceAgainst(domain: DiagnosticDomain, evidence: CompleteNetworkDoctorEvidence, physicalHealthy: boolean): string[] {
  const gateway = evidence.observations.gateway;
  const against = [];
  if (domain !== "gateway" && physicalHealthy) against.push(`Gateway loss is ${formatNullableMetric(gateway.lossPct)}% with average ${formatNullableMetric(gateway.avgMs)} ms.`);
  if (domain !== "dhcp" && evidence.observations.dhcp.ok) against.push("DHCP supplied the expected local configuration.");
  if (domain !== "router_health" && !evidence.observations.routerHealth.enabled) against.push("Router read-only connector was not part of this run, so router internals are not asserted.");
  if (!against.length) against.push("No strong counter-evidence was collected for this candidate.");
  return against;
}

function adviceForDomain(domain: DiagnosticDomain): DoctorAdvice[] {
  const genericRisk = "The network path may change while you test outside LANPilot.";
  const verifyQuick = "Run Quick Check again and compare route, DNS, gateway timing, and application timing.";
  const pairs: Record<DiagnosticDomain, [string, string, string, string, string][]> = {
    local_host: [["Close unrelated local network-heavy apps outside LANPilot.", "Local host activity can distort timing evidence.", genericRisk, "Timing noise is reduced.", verifyQuick]],
    physical_interface: [["Reconnect the active adapter or rejoin Wi-Fi outside LANPilot.", "The interface lacks a usable local address.", "Active sessions may reconnect.", "A valid local address and route return.", "Run Quick Check and confirm interface, DHCP, and gateway."], ["Try one physical path at a time.", "Multiple active paths can make routing ambiguous.", genericRisk, "The selected path is easier to interpret.", verifyQuick]],
    wifi_radio: [["Move closer to the access point or change Wi-Fi band outside LANPilot.", "Wi-Fi evidence shows weak signal, low SNR, or unstable jitter.", "The active Wi-Fi session may reconnect.", "Gateway jitter and packet loss improve.", "Run Quick Check and compare RSSI, SNR, gateway jitter, and application timing."], ["Test once on Ethernet if available.", "A wired comparison separates radio conditions from upstream issues.", genericRisk, "Physical LAN score becomes easier to interpret.", "Compare Wi-Fi and Ethernet reports." ]],
    ethernet_link: [["Check cable, adapter, and switch port outside LANPilot.", "First-hop timing suggests link instability.", genericRisk, "Gateway latency and loss return to baseline.", "Run Quick Check and compare gateway loss and jitter."], ["Test a different adapter or port.", "USB Ethernet and switch ports can produce intermittent first-hop symptoms.", genericRisk, "First-hop metrics stabilize.", verifyQuick]],
    dhcp: [["Renew the lease outside LANPilot.", "DHCP did not provide a complete address, router, and resolver set.", "The interface may briefly disconnect.", "The Mac receives a valid address and gateway.", "Run Quick Check and confirm DHCP, gateway, and DNS."], ["Check the router DHCP service.", "Self-assigned addressing points to local assignment failure.", "Other devices may be affected if the router is changed.", "A normal lease is issued.", "Retest on the same interface." ]],
    gateway: [["Inspect the local router, cable, switch port, or adapter outside LANPilot.", "First-hop latency, jitter, or loss is abnormal.", genericRisk, "Gateway timing stabilizes.", "Run Quick Check and compare gateway samples."], ["Hold proxy and VPN state constant while retesting.", "Local gateway evidence should be isolated from overlay changes.", "External route remains unchanged during the local retest.", "First-hop evidence becomes clearer.", "Run Quick Check before changing proxy or VPN state." ]],
    local_dns: [["Review gateway DNS forwarding outside LANPilot.", "DNS query evidence is slow or failing while the gateway is reachable.", genericRisk, "Resolver timing improves.", "Retest gateway DNS and system DNS separately."], ["Compare with a known resolver allowed by your policy.", "DNS health should be based on query results, not ICMP alone.", genericRisk, "The working resolver path is identified.", "Run Deep Diagnosis and compare resolver checks." ]],
    system_dns: [["Review overlay DNS policy outside LANPilot.", "System DNS appears slower or different from the local gateway resolver path.", genericRisk, "System resolver behavior matches the intended route.", "Retest DNS with overlay state unchanged and then changed."], ["Disable only the overlay DNS feature outside LANPilot if policy allows.", "Separating route control from DNS control narrows the fault domain.", genericRisk, "DNS timing becomes comparable to the gateway path.", verifyQuick]],
    route: [["Confirm whether the default route should use the overlay.", "The route differs from the physical LAN path.", genericRisk, "The path matches the intended network mode.", "Retest current path and public IP."], ["Save a baseline for each network mode.", "Route changes are normal across home, office, VPN, and proxy states.", "Baselines must be labeled accurately.", "Future comparisons become explainable.", "Compare before and after snapshots." ]],
    overlay_proxy: [["Check proxy node, rule policy, and DNS policy outside LANPilot.", "Physical LAN evidence is stronger than the overlay path evidence.", genericRisk, "External timing improves while LAN remains stable.", "Retest direct, system, and explicit proxy paths."], ["Use one overlay controller at a time while testing.", "Multiple controllers can split route and DNS ownership.", genericRisk, "The owner of route and DNS becomes clear.", "Run Quick Check and inspect TUN attribution." ]],
    tailscale: [["Check Exit Node and DNS settings outside LANPilot.", "Tailscale may be controlling route or DNS for external access.", genericRisk, "Remote access and general internet paths are separated.", "Retest route, DNS, public IP, and HTTPS timing."], ["Use Tailscale for remote access only during comparison.", "A remote exit path can add latency or fail independently of the LAN.", genericRisk, "The local ISP path can be compared cleanly.", "Run before and after snapshots." ]],
    transport_tcp: [["Check the target service status and firewall policy outside LANPilot.", "TCP state differs from a successful connection.", genericRisk, "Connection state becomes reachable or intentionally refused.", "Retest TCP and HTTPS timing for the same endpoint."], ["Do not treat refused and timeout as the same symptom.", "Refused means a host responded differently than a silent timeout.", "No local setting is changed by LANPilot.", "The next action matches the actual TCP state.", "Run Deep Diagnosis against the same allowed endpoint." ]],
    transport_udp: [["Treat UDP and QUIC results as inconclusive unless a known endpoint is configured.", "A silent UDP response is not enough evidence.", "No system setting should be changed from this result alone.", "The report avoids over-claiming.", "Retest with a known endpoint if available." ]],
    tls: [["Inspect certificate and TLS policy for the endpoint.", "TLS failed after transport evidence was collected.", genericRisk, "Handshake and certificate checks pass.", "Retest TLS and HTTPS for the same hostname."], ["Compare direct and overlay TLS results.", "TLS can fail through one path while TCP remains reachable.", genericRisk, "Path-specific TLS behavior is identified.", "Run Deep Diagnosis with the same endpoint group." ]],
    external_path: [["Compare direct, system, and overlay paths outside LANPilot.", "The LAN appears healthier than the external path.", genericRisk, "The slower path is isolated.", "Run Quick Check after each network mode change."], ["Check ISP, CDN region, or remote service status.", "External timing can degrade without a local gateway fault.", "No local router change should be made from this alone.", "The likely external dependency is identified.", "Run Deep Diagnosis and compare endpoint groups." ]],
    application_endpoint: [["Check the application endpoint group outside LANPilot.", "Application timing or HTTP state is abnormal.", genericRisk, "The endpoint becomes reachable within the expected timing window.", "Retest DNS, TCP, TLS, TTFB, and total timing."], ["Compare another fixed endpoint group.", "A single application status does not prove the entire application path.", genericRisk, "Endpoint-specific and path-wide symptoms are separated.", "Run Deep Diagnosis across endpoint groups." ]],
    router_health: [["Review router resource pressure through the optional read-only connector.", "Router evidence indicates memory, connection table, or WAN state pressure.", "Router UI changes should be made deliberately outside LANPilot.", "Forwarding health returns to expected levels.", "Run Router Read-only Check and then Quick Check."], ["Correlate router evidence with gateway timing.", "Load alone should not be treated as a fault without timing or state evidence.", genericRisk, "Router conclusions stay evidence-based.", "Retest after a steady observation interval." ]],
    unknown: [["doctorAdvice.deepSample.action", "doctorAdvice.deepSample.reason", "doctorAdvice.deepSample.risk", "doctorAdvice.deepSample.expected", "doctorAdvice.deepSample.verify"], ["doctorAdvice.saveBaseline.action", "doctorAdvice.saveBaseline.reason", "doctorAdvice.saveBaseline.risk", "doctorAdvice.saveBaseline.expected", "doctorAdvice.saveBaseline.verify" ]],
  };
  const rows = pairs[domain] ?? pairs.unknown;
  return rows.map(([action, reason, risk, expectedResult, verification]) => ({ action, reason, risk, expectedResult, verification }));
}

function retestForDomain(domain: DiagnosticDomain): string[] {
  return adviceForDomain(domain).map((item) => item.verification).slice(0, 3);
}

function confidenceForPrimary(statuses: DomainStatus[], domain: DiagnosticDomain): DoctorConfidence {
  return statuses.find((item) => item.domain === domain)?.confidence ?? "Low";
}

function primaryImpact(domain: DiagnosticDomain): "High" | "Medium" | "Low" {
  if (["dhcp", "physical_interface", "gateway", "transport_tcp", "tls"].includes(domain)) return "High";
  if (["wifi_radio", "local_dns", "system_dns", "overlay_proxy", "tailscale", "external_path", "application_endpoint", "router_health"].includes(domain)) return "Medium";
  return "Low";
}

function statusesHealthy(evidence: CompleteNetworkDoctorEvidence, domains: DiagnosticDomain[]): boolean {
  const statuses = evaluateDomains(evidence);
  return domains.every((domain) => statuses.find((item) => item.domain === domain)?.status === "healthy");
}

function scoreWeight(name: DoctorScorecard["name"]): number {
  if (name === "Physical LAN" || name === "Gateway" || name === "DNS") return 1.4;
  if (name === "Application Access") return 1.2;
  return 1;
}

export function scoreState(score: number): DoctorScoreState {
  if (score >= 90) return "Excellent";
  if (score >= 75) return "Healthy";
  if (score >= 60) return "Acceptable";
  if (score >= 40) return "Warning";
  return "Critical";
}

function reliabilityStatusFromScore(score: number): ReliabilityStatus {
  if (score >= 75) return "healthy";
  if (score >= 40) return "warning";
  return "critical";
}

function firstNumber(values: (number | null | undefined)[]): number | null {
  return values.find((value): value is number => typeof value === "number") ?? null;
}

function hostFromUrl(value: string): string {
  try {
    return new URL(value).hostname;
  } catch {
    return value;
  }
}

function formatMetric(value: number): string {
  return Number.isInteger(value) ? String(value) : value.toFixed(1);
}

function formatNullableMetric(value: number | null | undefined): string {
  return typeof value === "number" ? formatMetric(value) : "unknown";
}
