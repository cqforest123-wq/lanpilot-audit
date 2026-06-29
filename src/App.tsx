import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { supportedLocales, useI18n } from "./i18n";
import type { Locale } from "./i18n/types";
import { deduplicateFindings, localizeAssetLabel, localizeFinding, localizeGatewayStatus, reportCopy, type LocalizedFinding } from "./report-localization";
import { buildRemediationPack, type RemediationPack, type RemediationStatus } from "./remediation-assistant";
import { reliabilityThresholds, type NetworkReliabilityDiagnosis, type NetworkReliabilityEvidence, type ReliabilityStatus } from "./network-reliability";
import { demoNetworkReliabilityRun } from "./demo-network-reliability";
import { diagnoseNetworkDoctor, type DiagnosticDomain, type DoctorMode, type DoctorScoreState, type DoctorScorecard, type RootCauseCandidate } from "./network-doctor";
import packageJson from "../package.json";
import "./App.css";

type Page = "overview" | "authorization" | "engine" | "interface" | "run" | "assets" | "exposure" | "networkCheck" | "report" | "compare" | "remediation" | "export" | "settings";
type StepStatus = "pending" | "running" | "success" | "failed" | "skipped";
type AuditStepId =
  | "init_lab"
  | "baseline"
  | "passive_assets"
  | "client_isolation"
  | "common_services"
  | "smb_posture"
  | "gateway_posture"
  | "build_report"
  | "local_network_config"
  | "mdns_observation"
  | "web_tls_baseline"
  | "build_enhanced_governance_report"
  | "build_formats";

interface AuditInterface {
  name: string;
  ipv4: string;
}

interface EngineStatus {
  enginePath: string;
  engineFound: boolean;
  scriptsReady: boolean;
  missingScripts: string[];
  nmapAvailable: boolean;
  latestLabExists: boolean;
  warnings: string[];
  engineVersion: string | null;
  bundledEngineVersion: string;
  updateAvailable: boolean;
  developmentFallback: boolean;
}

interface AuditStepResult {
  stepId: AuditStepId;
  scriptName: string;
  success: boolean;
  exitCode: number | null;
  stdout: string;
  stderr: string;
  durationMs: number;
  skipped: boolean;
}

interface FullAuditResult {
  success: boolean;
  steps: AuditStepResult[];
  failedStepId: AuditStepId | null;
}

interface AuditStepEvent {
  stepId: AuditStepId;
  status: StepStatus;
  result: AuditStepResult | null;
  error: string | null;
}

interface RiskFinding {
  severity: string;
  asset: string;
  category: string;
  finding: string;
  recommended_action: string;
  status: string;
}

interface ReportSummary {
  highCount: number | null;
  mediumCount: number | null;
  lowCount: number | null;
  reachableClients: number | null;
  unreachableClients: number | null;
  openServiceHosts: number | null;
  gatewayPostureStatus: string | null;
}

interface LatestReport {
  generatedAt: number | null;
  labDirectory: string;
  executiveSummary: string | null;
  technicalReport: string | null;
  riskRegister: string | null;
  remediationRoadmap: string | null;
  evidenceIndex: string | null;
  assetInventory: string | null;
  assetInventorySummary: string | null;
  serviceExposureMatrix: string | null;
  serviceExposureSummary: string | null;
  localNetworkConfig: string | null;
  mdnsServices: string | null;
  webBaseline: string | null;
  tlsCertificates: string | null;
  snapshotDiff: string | null;
  remediationTracking: string | null;
  governanceSummary: string | null;
  missingFiles: string[];
  findings: RiskFinding[];
  summary: ReportSummary;
}

interface ExportResult {
  zipPath: string;
}

interface NetworkReliabilityRun {
  summary: NetworkReliabilityDiagnosis;
  evidence: NetworkReliabilityEvidence;
  reportMarkdown: string;
  supportBundlePath: string;
  outputDirectory: string;
  doctorMode?: DoctorMode;
}

type NetworkDoctorResultMode = "empty" | "demo" | "real" | "failed";

interface AuditStep {
  id: AuditStepId;
  labelKey: string;
  descriptionKey: string;
  status: StepStatus;
  result?: AuditStepResult;
}

interface AuthorizationDetails {
  projectName: string;
  site: string;
  notes: string;
}

const STEP_DEFINITIONS: Omit<AuditStep, "status" | "result">[] = [
  { id: "init_lab", labelKey: "step.initLab", descriptionKey: "step.initLabDescription" },
  { id: "baseline", labelKey: "step.baseline", descriptionKey: "step.baselineDescription" },
  { id: "passive_assets", labelKey: "step.passiveAssets", descriptionKey: "step.passiveAssetsDescription" },
  { id: "client_isolation", labelKey: "step.clientIsolation", descriptionKey: "step.clientIsolationDescription" },
  { id: "common_services", labelKey: "step.commonServices", descriptionKey: "step.commonServicesDescription" },
  { id: "smb_posture", labelKey: "step.smbPosture", descriptionKey: "step.smbPostureDescription" },
  { id: "gateway_posture", labelKey: "step.gatewayPosture", descriptionKey: "step.gatewayPostureDescription" },
  { id: "build_report", labelKey: "step.buildReport", descriptionKey: "step.buildReportDescription" },
  { id: "local_network_config", labelKey: "step.localNetworkConfig", descriptionKey: "step.localNetworkConfigDescription" },
  { id: "mdns_observation", labelKey: "step.mdnsObservation", descriptionKey: "step.mdnsObservationDescription" },
  { id: "web_tls_baseline", labelKey: "step.webTlsBaseline", descriptionKey: "step.webTlsBaselineDescription" },
  { id: "build_enhanced_governance_report", labelKey: "step.enhancedReport", descriptionKey: "step.enhancedReportDescription" },
  { id: "build_formats", labelKey: "step.buildFormats", descriptionKey: "step.buildFormatsDescription" },
];

const freshSteps = (): AuditStep[] => STEP_DEFINITIONS.map((step) => ({ ...step, status: "pending" }));
const errorMessage = (error: unknown): string =>
  typeof error === "string" ? error : error instanceof Error ? error.message : String(error);
const formatDuration = (durationMs: number | undefined, pending: string): string =>
  durationMs === undefined ? pending : durationMs < 1000 ? `${durationMs} ms` : `${(durationMs / 1000).toFixed(1)} s`;

function App() {
  const { t } = useI18n();
  const [page, setPage] = useState<Page>("overview");
  const [auditRunning, setAuditRunning] = useState(false);
  const [authorized, setAuthorized] = useState(false);
  const [details, setDetails] = useState<AuthorizationDetails | null>(null);
  const [auditInterface, setAuditInterface] = useState("");
  const [latestReport, setLatestReport] = useState<LatestReport | null>(null);
  const [networkResult, setNetworkResult] = useState<NetworkReliabilityRun | null>(null);

  const startAuthorization = () => {
    if (auditRunning) return;
    setAuthorized(false);
    setDetails(null);
    setPage("authorization");
  };

  const navigate = (next: Page) => {
    if (!auditRunning) setPage(next);
  };

  return (
    <main className="app-shell">
      <aside className="sidebar">
        <button className="brand" type="button" disabled={auditRunning} onClick={() => navigate("overview")}>
          <span className="brand-mark">LP</span>
          <span><strong>LANPilot Audit</strong><small>v{packageJson.version}</small></span>
        </button>
        <nav className="sidebar-nav" aria-label={t("navigation.primary")}>
          <NavButton active={page === "overview"} disabled={auditRunning} onClick={() => navigate("overview")} label={t("navOverview")} />
          <NavButton active={page === "networkCheck"} disabled={auditRunning} onClick={() => navigate("networkCheck")} label={t("navNetworkCheck")} />
          <NavButton active={["authorization", "engine", "interface", "run"].includes(page)} disabled={auditRunning} onClick={startAuthorization} label={t("navGovernanceAudit")} />
          <NavButton active={page === "report"} disabled={auditRunning} onClick={() => navigate("report")} label={t("navReport")} />
          <NavButton active={page === "remediation"} disabled={auditRunning} onClick={() => navigate("remediation")} label={t("navRemediation")} />
          <NavButton active={page === "export"} disabled={auditRunning} onClick={() => navigate("export")} label={t("navExport")} />
          <NavButton active={page === "settings"} disabled={auditRunning} onClick={() => navigate("settings")} label={t("navSettings")} />
        </nav>
        <div className="sidebar-footer">
          <LanguageSelector />
          <span className="local-first-chip">{t("settings.noCloudUpload")}</span>
        </div>
      </aside>

      <section className="workspace">
        <header className="product-header">
          <div>
            <div className="eyebrow">{t("appName")} v{packageJson.version}</div>
            <h1>{t("product.tagline")}</h1>
          </div>
          <StatusBadge status="healthy" label={t("product.localFirst")} />
        </header>

        <section className="page" aria-label={t("appName")}>
        {page === "overview" && (
          <OverviewPage
            result={networkResult}
            onNetworkCheck={() => navigate("networkCheck")}
            onGovernanceAudit={startAuthorization}
          />
        )}
        {page === "authorization" && (
          <AuthorizationPage
            onCancel={() => navigate("overview")}
            onConfirm={async (authorizationDetails) => {
              await invoke("authorize_audit", { projectName: authorizationDetails.projectName });
              setDetails(authorizationDetails);
              setAuthorized(true);
              setPage("engine");
            }}
          />
        )}
        {page === "engine" && authorized && (
          <EngineSetupPage onBack={startAuthorization} onContinue={() => setPage("interface")} />
        )}
        {page === "interface" && authorized && details && (
          <InterfacePage details={details} selected={auditInterface} onSelect={setAuditInterface} onBack={startAuthorization} onContinue={() => setPage("run")} />
        )}
        {page === "run" && authorized && (
          <RunPage
            onRunningChange={setAuditRunning}
            auditInterface={auditInterface}
            onAuthorizeNewRun={startAuthorization}
            onComplete={(report) => {
              setLatestReport(report);
            }}
            onReport={() => setPage("report")}
          />
        )}
        {page === "report" && <ReportPage initialReport={latestReport} />}
        {page === "assets" && <GovernanceDataPage titleKey="toolbox.assets" descriptionKey="toolbox.assetsDescription" fields={["assetInventorySummary", "assetInventory", "localNetworkConfig"]} />}
        {page === "exposure" && <GovernanceDataPage titleKey="toolbox.exposure" descriptionKey="toolbox.exposureDescription" fields={["serviceExposureSummary", "serviceExposureMatrix", "mdnsServices", "webBaseline", "tlsCertificates"]} />}
        {page === "networkCheck" && <NetworkReliabilityPage onRunningChange={setAuditRunning} onComplete={setNetworkResult} />}
        {page === "compare" && <GovernanceDataPage titleKey="toolbox.compare" descriptionKey="toolbox.compareDescription" fields={["snapshotDiff", "governanceSummary"]} />}
        {page === "remediation" && <RemediationPage onRetest={startAuthorization} />}
        {page === "export" && <ExportPage />}
        {page === "settings" && <SettingsPage />}
        </section>
      </section>
    </main>
  );
}

function NavButton({ active, disabled, onClick, label }: { active: boolean; disabled: boolean; onClick: () => void; label: string }) {
  return <button className={active ? "active" : ""} type="button" disabled={disabled} onClick={onClick}>{label}</button>;
}

function OverviewPage({
  result,
  onNetworkCheck,
  onGovernanceAudit,
}: {
  result: NetworkReliabilityRun | null;
  onNetworkCheck: () => void;
  onGovernanceAudit: () => void;
}) {
  const { locale, t } = useI18n();
  const display = result ?? demoNetworkReliabilityRun;
  const demo = !result;
  const evidence = display.evidence;
  const summary = display.summary;
  const physical = evidence.physicalLan;
  const overlay = evidence.overlay;

  return (
    <section className="content-stack dashboard">
      {demo && <p className="message demo-message">{t("overview.demoNotice")}</p>}
      <div className="dashboard-grid">
        <section className="card compact hero-panel">
          <div className="panel-heading">
            <span className="eyebrow">{t("overview.currentPath")}</span>
            <StatusBadge status={summary.overallStatus} label={t(`reliability.status.${summary.overallStatus}`)} />
          </div>
          <NetworkPathMap summary={summary} evidence={evidence} resultMode={demo ? "demo" : "real"} />
          <div className="actions">
            <button className="primary" type="button" onClick={onNetworkCheck}>{t("button.startNetworkCheck")}</button>
            <button className="secondary" type="button" onClick={onGovernanceAudit}>{t("button.runGovernanceAudit")}</button>
          </div>
        </section>
        <section className="card compact diagnosis-panel">
          <div className="panel-heading">
            <span className="eyebrow">{t("overview.faultPoint")}</span>
            <StatusBadge status={summary.faultDomain === "none" ? "healthy" : summary.overallStatus} label={t(`reliability.status.${summary.overallStatus}`)} />
          </div>
          <h2>{localizeReliabilityText(summary.faultPoint, locale)}</h2>
          <p>{localizeReliabilityText(summary.impact, locale)}</p>
          <Checklist title={t("overview.advice")} items={summary.remediationAdvice.slice(0, 5)} />
        </section>
      </div>
      <div className="overview-cards">
        <MetricCard title={t("overview.physicalStatus")} status={summary.physicalLanStatus} rows={[
          [t("reliability.interface"), physical.activeInterface || t("status.unknown")],
          [t("overview.localIp"), physical.ipv4 ?? t("status.unknown")],
          [t("reliability.gateway"), physical.gatewayIp ?? t("status.unknown")],
          [t("reliability.gatewayLatency"), formatNullableMs(physical.gatewayPingAvgMs, t("status.unknown"))],
          [t("reliability.gatewayLoss"), formatNullablePercent(physical.gatewayPingLossPct, t("status.unknown"))],
        ]} />
        <MetricCard title={t("overview.dnsStatus")} status={summary.dnsStatus} rows={[
          [t("overview.dhcpDns"), (physical.dhcpDns ?? []).join(", ") || t("status.unknown")],
          [t("reliability.systemDns"), evidence.localControlPlane.systemDnsServers.join(", ") || t("status.unknown")],
          [t("overview.gatewayDns"), formatNullableMs(physical.gatewayDnsMs, t("status.unknown"))],
          [t("overview.dnsJudgement"), overlay.dnsViaOverlay ? t("overview.dnsTakenByOverlay") : t("overview.dnsDirect")],
        ]} />
        <MetricCard title={t("overview.overlayStatus")} status={summary.overlayStatus} rows={[
          ["Stash", overlay.stashDetected ? t("status.active") : t("status.stopped")],
          ["Tailscale", overlay.tailscaleRunning ? t("status.active") : t("status.stopped")],
          [t("reliability.defaultRoute"), overlay.defaultRouteInterface ?? t("status.unknown")],
          ["198.18.0.0/16", overlay.hasProxyRange19818 ? t("status.detected") : t("status.notDetected")],
        ]} />
      </div>
      <LatencyVisualization evidence={evidence} />
      <RealCollectorDetails evidence={evidence} />
    </section>
  );
}

function StatusBadge({ status, label }: { status: ReliabilityStatus; label: string }) {
  return <span className={`status-badge ${status}`}>{label}</span>;
}

function MetricCard({ title, status, rows }: { title: string; status: ReliabilityStatus; rows: [string, string][] }) {
  const { t } = useI18n();
  return (
    <section className="card compact metric-card">
      <div className="panel-heading">
        <h2>{title}</h2>
        <StatusBadge status={status} label={t(`reliability.status.${status}`)} />
      </div>
      <dl className="metric-list">
        {rows.map(([label, value]) => <div key={label}><dt>{label}</dt><dd>{value}</dd></div>)}
      </dl>
    </section>
  );
}

function Checklist({ title, items }: { title: string; items: string[] }) {
  const { locale, t } = useI18n();
  return (
    <div className="checklist">
      <h3>{title}</h3>
      {items.length === 0 ? <p className="muted">{t("status.unknown")}</p> : <ul>{items.map((item) => <li key={item}>{localizeReliabilityText(item, locale)}</li>)}</ul>}
    </div>
  );
}

type PathNode = { label: string; detail?: string; status: ReliabilityStatus; source: string };

function NetworkPathMap({ summary, evidence, resultMode }: { summary: NetworkReliabilityDiagnosis; evidence: NetworkReliabilityEvidence; resultMode: NetworkDoctorResultMode }) {
  const { t } = useI18n();
  const source = resultMode === "demo" ? t("reliability.evidenceSource.synthetic") : t("reliability.evidenceSource.localCollector");
  const nodes = buildPathNodes(summary, evidence, t("status.unknown"), {
    physicalInterface: t("path.physicalInterface"),
    localGateway: t("path.localGateway"),
    gatewayNotIdentified: t("path.gatewayNotIdentified"),
    gateway: t("reliability.gateway"),
    proxyRules: t("path.proxyRules"),
    proxyExit: t("path.proxyExit"),
    internet: t("path.internet"),
    remotePath: t("path.remotePath"),
    overlayUtun: t("path.overlayUtun"),
    exitNode: t("path.exitNode"),
    isp: t("path.isp"),
  }, source);
  return (
    <div className="network-path-map" aria-label={t("reliability.networkPathView")}>
      {nodes.map((node, index) => (
        <div className="path-node-wrap" key={`${node.label}-${index}`}>
          {index > 0 && <div className="path-connector" aria-hidden="true" />}
          <div className={`path-node ${node.status}`}>
            <div className="path-node-title">
              <strong>{node.label}</strong>
              <StatusBadge status={node.status} label={t(`reliability.status.${node.status}`)} />
            </div>
            {node.detail && <small>{node.detail}</small>}
            <small className="path-source">{node.source} · {resultMode === "demo" ? t("reliability.resultMode.demo") : t("reliability.resultMode.real")}</small>
          </div>
        </div>
      ))}
    </div>
  );
}

function buildPathNodes(
  summary: NetworkReliabilityDiagnosis,
  evidence: NetworkReliabilityEvidence,
  unknown: string,
  labels: {
    physicalInterface: string;
    localGateway: string;
    gatewayNotIdentified: string;
    gateway: string;
    proxyRules: string;
    proxyExit: string;
    internet: string;
    remotePath: string;
    overlayUtun: string;
    exitNode: string;
    isp: string;
  },
  source: string,
): PathNode[] {
  const physical = evidence.physicalLan;
  const overlay = evidence.overlay;
  const physicalDetail = `${physical.activeInterface || unknown} / ${physical.ipv4 ?? unknown}`;
  const gatewayDetail = physical.gatewayIp ?? labels.gatewayNotIdentified;
  const gatewayStatus = physical.gatewayIp ? summary.physicalLanStatus : "unknown";
  if (overlay.tailscaleRunning && overlay.tailscaleExitNode) {
    return [
      { label: "Mac", status: "healthy", source },
      { label: labels.physicalInterface, detail: physicalDetail, status: summary.physicalLanStatus, source },
      { label: labels.localGateway, detail: gatewayDetail, status: gatewayStatus, source },
      { label: "Tailscale utun", detail: overlay.defaultRouteInterface ?? unknown, status: summary.overlayStatus, source },
      { label: labels.exitNode, detail: evidence.external.publicIpOrg ?? unknown, status: summary.externalPathStatus, source },
      { label: labels.internet, status: summary.externalPathStatus, source },
    ];
  }
  if (overlay.stashDetected && overlay.stashTunDetected) {
    return [
      { label: "Mac", status: "healthy", source },
      { label: labels.physicalInterface, detail: physicalDetail, status: summary.physicalLanStatus, source },
      { label: labels.localGateway, detail: gatewayDetail, status: gatewayStatus, source },
      { label: "Stash TUN", detail: `${overlay.defaultRouteInterface ?? unknown}${overlay.defaultRouteGateway ? ` / ${overlay.defaultRouteGateway}` : ""}`, status: summary.overlayStatus, source },
      { label: labels.proxyRules, status: summary.overlayStatus, source },
      { label: labels.proxyExit, detail: evidence.external.publicIpOrg ?? unknown, status: summary.externalPathStatus, source },
      { label: labels.internet, status: summary.externalPathStatus, source },
    ];
  }
  if ((overlay.defaultRouteInterface ?? "").startsWith("utun")) {
    return [
      { label: "Mac", status: "healthy", source },
      { label: labels.physicalInterface, detail: physicalDetail, status: summary.physicalLanStatus, source },
      { label: labels.localGateway, detail: gatewayDetail, status: gatewayStatus, source },
      { label: labels.overlayUtun, detail: overlay.defaultRouteInterface ?? unknown, status: summary.overlayStatus, source },
      { label: labels.remotePath, status: summary.externalPathStatus, source },
      { label: labels.internet, status: summary.externalPathStatus, source },
    ];
  }
  return [
    { label: "Mac", status: "healthy", source },
    { label: labels.physicalInterface, detail: physicalDetail, status: summary.physicalLanStatus, source },
    { label: labels.gateway, detail: gatewayDetail, status: gatewayStatus, source },
    { label: labels.isp, status: summary.externalPathStatus, source },
    { label: labels.internet, status: summary.externalPathStatus, source },
  ];
}

function LatencyVisualization({ evidence }: { evidence: NetworkReliabilityEvidence }) {
  const { t } = useI18n();
  const physical = evidence.physicalLan;
  const firstTarget = evidence.external.targets[0];
  const gatewayAverage = physical.gatewayPingAvgMs;
  const jitter = physical.gatewayPingJitterMs;
  const gatewayMin = typeof gatewayAverage === "number" && typeof jitter === "number" ? Math.max(0, gatewayAverage - jitter) : null;
  const gatewayMax = typeof gatewayAverage === "number" && typeof jitter === "number" ? gatewayAverage + jitter : null;
  const rows = [
    { label: `${t("reliability.gateway")} ${physical.gatewayIp ?? ""}`.trim(), value: gatewayAverage, meta: `${t("latency.avg")} ${formatNullableMs(gatewayAverage, t("status.unknown"))} · ${t("latency.min")} ${formatNullableMs(gatewayMin, t("status.unknown"))} · ${t("latency.max")} ${formatNullableMs(gatewayMax, t("status.unknown"))} · ${formatNullablePercent(physical.gatewayPingLossPct, t("status.unknown"))} ${t("latency.loss")}`, status: physical.gatewayPingLossPct ? "warning" as ReliabilityStatus : "healthy" as ReliabilityStatus, warning: 30, max: 100 },
    { label: t("latency.gatewayDns"), value: physical.gatewayDnsMs, meta: formatNullableMs(physical.gatewayDnsMs, t("status.unknown")), status: latencyStatus(physical.gatewayDnsMs, reliabilityThresholds.gatewayDnsWarningMs, 500), warning: reliabilityThresholds.gatewayDnsWarningMs, max: 500 },
    { label: t("latency.systemDns"), value: firstTarget?.dnsMs, meta: `${formatNullableMs(firstTarget?.dnsMs, t("status.unknown"))} · ${evidence.overlay.defaultRouteInterface ?? t("status.unknown")}`, status: latencyStatus(firstTarget?.dnsMs, reliabilityThresholds.systemDnsWarningMs, 1000), warning: reliabilityThresholds.systemDnsWarningMs, max: 1000 },
    { label: t("latency.tcpConnect"), value: firstTarget?.tcpConnectMs, meta: formatNullableMs(firstTarget?.tcpConnectMs, t("status.unknown")), status: latencyStatus(firstTarget?.tcpConnectMs, reliabilityThresholds.tcpConnectWarningMs, 3000), warning: reliabilityThresholds.tcpConnectWarningMs, max: 3000 },
    { label: t("latency.tls"), value: firstTarget?.tlsMs, meta: formatNullableMs(firstTarget?.tlsMs, t("status.unknown")), status: latencyStatus(firstTarget?.tlsMs, reliabilityThresholds.tlsWarningMs, 4000), warning: reliabilityThresholds.tlsWarningMs, max: 4000 },
    { label: t("latency.ttfb"), value: firstTarget?.ttfbMs, meta: formatNullableMs(firstTarget?.ttfbMs, t("status.unknown")), status: latencyStatus(firstTarget?.ttfbMs, reliabilityThresholds.ttfbWarningMs, 5000), warning: reliabilityThresholds.ttfbWarningMs, max: 5000 },
    { label: firstTarget?.url ?? t("latency.httpsTotal"), value: firstTarget?.totalMs, meta: formatNullableMs(firstTarget?.totalMs, t("status.unknown")), status: latencyStatus(firstTarget?.totalMs, reliabilityThresholds.httpsTotalWarningMs, reliabilityThresholds.httpsTotalCriticalMs), warning: reliabilityThresholds.httpsTotalWarningMs, max: reliabilityThresholds.httpsTotalCriticalMs },
  ];
  return (
    <section className="card compact latency-panel">
      <div className="panel-heading">
        <div>
          <h2>{t("latency.title")}</h2>
          <p className="muted">{t("latency.description")}</p>
        </div>
      </div>
      <div className="latency-list">
        {rows.map((row) => <LatencyRow key={row.label} {...row} />)}
      </div>
    </section>
  );
}

function LatencyRow({ label, value, meta, status, warning, max }: { label: string; value?: number | null; meta: string; status: ReliabilityStatus; warning: number; max: number }) {
  const { t } = useI18n();
  const width = typeof value === "number" ? Math.max(2, Math.min(100, (value / max) * 100)) : 4;
  return (
    <div className="latency-row">
      <div><strong>{label}</strong><span>{meta}</span></div>
      <div className="latency-track"><span className={status} style={{ width: `${width}%` }} /></div>
      <StatusBadge status={status} label={latencyStatusLabel(status, value, warning, t)} />
    </div>
  );
}

function latencyStatus(value: number | null | undefined, warning: number, critical: number): ReliabilityStatus {
  if (typeof value !== "number") return "unknown";
  if (value >= critical) return "critical";
  if (value >= warning) return "warning";
  return "healthy";
}

function latencyStatusLabel(status: ReliabilityStatus, value: number | null | undefined, warning: number, t: (key: string) => string): string {
  if (status === "healthy" && typeof value === "number" && value >= warning * 0.65) return t("reliability.status.acceptable");
  return t(`reliability.status.${status}`);
}

function AuthorizationPage({
  onCancel,
  onConfirm,
}: {
  onCancel: () => void;
  onConfirm: (details: AuthorizationDetails) => Promise<void>;
}) {
  const { t } = useI18n();
  const [engine, setEngine] = useState<EngineStatus | null>(null);
  const [error, setError] = useState("");
  const [projectName, setProjectName] = useState("");
  const [site, setSite] = useState("");
  const [notes, setNotes] = useState("");
  const [checks, setChecks] = useState([false, false, false, false, false]);
  const allChecked = checks.every(Boolean);
  const engineReady = Boolean(engine && (engine.scriptsReady || !engine.engineFound));

  useEffect(() => {
    invoke<EngineStatus>("check_engine").then(setEngine).catch((value) => setError(errorMessage(value)));
  }, []);

  const toggleCheck = (index: number, checked: boolean) => {
    setChecks((current) => current.map((value, itemIndex) => itemIndex === index ? checked : value));
  };

  const submit = async () => {
    setError("");
    try {
      await onConfirm({ projectName: projectName.trim(), site: site.trim(), notes: notes.trim() });
    } catch (value) {
      setError(errorMessage(value));
    }
  };

  return (
    <section className="content-stack">
      <PageHeading eyebrow={t("authorization.requiredBeforeEveryRealAudit")} title={t("authorization.title")} description={t("authorization.description")} />
      <div className="form-grid">
        <label>{t("authorization.projectName")} <strong>*</strong><input value={projectName} onChange={(event) => setProjectName(event.target.value)} /></label>
        <label>{t("authorization.siteOrganization")}<input value={site} onChange={(event) => setSite(event.target.value)} /></label>
        <label className="full-width">{t("authorization.notes")}<textarea value={notes} onChange={(event) => setNotes(event.target.value)} /></label>
      </div>
      <div className="card compact">
        <h2>{t("authorization.localEngineReadiness")}</h2>
        {!engine && !error && <p className="muted">{t("authorization.checkingEngine")}</p>}
        {engine && (
          <div className="readiness-grid">
            <Readiness label={t("authorization.engineReady")} ready={engine.engineFound} />
            <Readiness label={t("authorization.approvedScriptsReady")} ready={engine.scriptsReady} />
            <Readiness label={t("authorization.nmapReady")} ready={engine.nmapAvailable} />
            <Readiness label={t("authorization.latestLabReady")} ready={engine.latestLabExists} optional />
          </div>
        )}
        {engine?.warnings.map((warning) => <RawDetail detail={warning} warning key={warning} />)}
      </div>
      <div className="confirmation-list">
        {[
          t("authorization.confirmAssessNetwork"),
          t("authorization.confirmOnlyApprovedScripts"),
          t("authorization.confirmNoOffensiveActions"),
          t("authorization.confirmPointInTimeNoConfigChange"),
          t("authorization.confirmCurrentInterface"),
        ].map((label, index) => (
          <label className="confirmation card compact" key={label}>
            <input type="checkbox" checked={checks[index]} onChange={(event) => toggleCheck(index, event.target.checked)} />
            <span><strong>{label}</strong></span>
          </label>
        ))}
      </div>
      {error && <RawDetail detail={error} />}
      <div className="actions">
        <button className="primary" type="button" disabled={!allChecked || !projectName.trim() || !engineReady} onClick={submit}>{t("authorization.confirmAuthorization")}</button>
        <button className="secondary" type="button" onClick={onCancel}>{t("authorization.cancel")}</button>
      </div>
    </section>
  );
}

function EngineSetupPage({ onBack, onContinue }: { onBack: () => void; onContinue: () => void }) {
  const { t } = useI18n();
  const [engine, setEngine] = useState<EngineStatus | null>(null);
  const [error, setError] = useState("");
  const [installing, setInstalling] = useState(false);
  const refresh = () => invoke<EngineStatus>("check_engine").then(setEngine).catch((value) => setError(errorMessage(value)));
  useEffect(() => { void refresh(); }, []);

  const install = async () => {
    setInstalling(true);
    setError("");
    try {
      setEngine(await invoke<EngineStatus>("install_bundled_engine"));
    } catch (value) {
      setError(errorMessage(value));
    } finally {
      setInstalling(false);
    }
  };
  const ready = Boolean(engine?.engineFound && engine.scriptsReady);

  return (
    <section className="content-stack">
      <PageHeading eyebrow={t("engine.localFirstEngine")} title={t("engine.title")} description={t("engine.description")} />
      <div className="card compact">
        <div className="readiness-grid">
          <Readiness label={t("engine.installed")} ready={Boolean(engine?.engineFound)} />
          <Readiness label={t("engine.scriptReadiness")} ready={Boolean(engine?.scriptsReady)} />
          <Readiness label={t("engine.nmapAvailability")} ready={Boolean(engine?.nmapAvailable)} optional />
          <Readiness label={t("engine.latestLabFolder")} ready={Boolean(engine?.latestLabExists)} optional />
        </div>
        <p className="path">{engine?.enginePath ?? t("common.checking")}</p>
        <p className="muted">{t("engine.installedVersion")}: {engine?.engineVersion ?? t("status.notInstalled")} · {t("engine.bundledVersion")}: {engine?.bundledEngineVersion ?? t("status.unknown")}</p>
        {!engine?.nmapAvailable && <p className="message">{t("nmapUnavailable")}</p>}
        {engine?.warnings.map((warning) => <RawDetail detail={warning} warning key={warning} />)}
      </div>
      {error && <RawDetail detail={error} />}
      <div className="actions">
        {(!ready || engine?.updateAvailable || engine?.developmentFallback) && <button className="primary" type="button" disabled={installing} onClick={install}>{installing ? t("engine.installing") : t("engine.installOrUpdate")}</button>}
        <button className="primary" type="button" disabled={!ready} onClick={onContinue}>{t("engine.continueToInterface")}</button>
        <button className="secondary" type="button" onClick={onBack}>{t("authorization.reviewAuthorization")}</button>
      </div>
    </section>
  );
}

function Readiness({ label, ready, optional = false }: { label: string; ready: boolean; optional?: boolean }) {
  const { t } = useI18n();
  return <div className={`readiness ${ready ? "success-text" : optional ? "muted" : "error-text"}`}><span className="status-dot" />{label}: {ready ? t("status.ready") : optional ? t("status.unavailable") : t("common.required")}</div>;
}

function InterfacePage({ details, selected, onSelect, onBack, onContinue }: { details: AuthorizationDetails; selected: string; onSelect: (value: string) => void; onBack: () => void; onContinue: () => void }) {
  const { t } = useI18n();
  const [interfaces, setInterfaces] = useState<AuditInterface[]>([]);
  const [error, setError] = useState("");
  useEffect(() => {
    invoke<AuditInterface[]>("list_audit_interfaces")
      .then((items) => {
        setInterfaces(items);
        if (!selected) {
          const preferred = pickPreferredAuditInterface(items);
          if (preferred) onSelect(preferred.name);
        }
      })
      .catch((value) => setError(errorMessage(value)));
  }, [selected, onSelect]);
  return (
    <section className="content-stack">
      <PageHeading eyebrow={t("interface.eyebrow")} title={t("interface.title")} description={t("interface.description")} />
      <div className="card compact review-grid">
        <div><span>{t("interface.project")}</span><strong>{details.projectName}</strong></div>
        <div><span>{t("interface.siteOrganization")}</span><strong>{details.site || t("common.notProvided")}</strong></div>
        <div><span>{t("interface.executionMode")}</span><strong>{t("run.stopOnFailure")}</strong></div>
        <div><span>{t("interface.selectionRule")}</span><strong>{t("interface.preferPhysical")}</strong></div>
      </div>
      <NetworkInterfaceSelector interfaces={interfaces} selected={selected} onSelect={onSelect} mode="governance" />
      {error && <RawDetail detail={error} />}
      <Guardrail />
      <div className="actions">
        <button className="primary" type="button" disabled={!selected} onClick={onContinue}>{t("interface.continueToRun")}</button>
        <button className="secondary" type="button" onClick={onBack}>{t("authorization.reviewAuthorization")}</button>
      </div>
    </section>
  );
}

function NetworkInterfaceSelector({
  interfaces,
  selected,
  onSelect,
  mode,
}: {
  interfaces: AuditInterface[];
  selected: string;
  onSelect: (value: string) => void;
  mode: "governance" | "reliability";
}) {
  const { t } = useI18n();
  const preferred = pickPreferredAuditInterface(interfaces);
  return (
    <section className="card compact interface-selector">
      <div className="panel-heading">
        <div>
          <h2>{t("interface.selectorTitle")}</h2>
          <p className="muted">{mode === "governance" ? t("interface.governanceHint") : t("interface.reliabilityHint")}</p>
        </div>
        <StatusBadge status={selected ? "healthy" : "unknown"} label={selected || t("status.unknown")} />
      </div>
      {interfaces.length === 0 ? <p className="message">{t("interface.noInterfaces")}</p> : (
        <div className="interface-list">
          {interfaces.map((item) => {
            const overlay = isOverlayInterface(item.name);
            const selfAssigned = isSelfAssignedIpv4(item.ipv4);
            const selectedItem = selected === item.name;
            const recommended = preferred?.name === item.name && !overlay;
            const status: ReliabilityStatus = overlay || selfAssigned ? "warning" : item.ipv4 ? "healthy" : "unknown";
            const label = overlay
              ? t("interface.overlayNotRecommended")
              : selfAssigned
                ? t("interface.selfAssignedAddress")
                : item.ipv4
                  ? t("interface.physicalCandidate")
                  : t("interface.notAssociated");
            return (
              <button className={selectedItem ? "interface-option active" : "interface-option"} type="button" key={item.name} onClick={() => onSelect(item.name)} disabled={mode === "governance" && overlay}>
                <span>
                  <strong>{recommended ? `${t("interface.currentAutoSelected")}: ${item.name}` : item.name}</strong>
                  <small>{t("interface.type")}: {interfaceKindLabel(item.name, t)}</small>
                  <small>{t("interface.address")}: {item.ipv4 || t("interface.noIpv4")}</small>
                  <small>{t("interface.state")}: {selfAssigned ? t("interface.notRecommendedPrimary") : label}</small>
                </span>
                <StatusBadge status={status} label={label} />
              </button>
            );
          })}
        </div>
      )}
      {interfaces.some((item) => item.ipv4?.startsWith("172.20.10.")) && <p className="message">{t("interface.mobileHotspotNotice")}</p>}
    </section>
  );
}

function pickPreferredAuditInterface(interfaces: AuditInterface[]): AuditInterface | undefined {
  return interfaces.find((item) => !isOverlayInterface(item.name) && item.ipv4 && !isSelfAssignedIpv4(item.ipv4) && isPrivateIpv4(item.ipv4))
    ?? interfaces.find((item) => !isOverlayInterface(item.name) && item.ipv4 && !isSelfAssignedIpv4(item.ipv4))
    ?? interfaces.find((item) => !isOverlayInterface(item.name))
    ?? interfaces[0];
}

function isOverlayInterface(name: string): boolean {
  return name.startsWith("utun") || name.startsWith("tun") || name.startsWith("tap");
}

function isSelfAssignedIpv4(value?: string | null): boolean {
  return Boolean(value?.startsWith("169.254."));
}

function isPrivateIpv4(value: string): boolean {
  const parts = value.split(".").map((part) => Number(part));
  if (parts.length !== 4 || parts.some((part) => Number.isNaN(part))) return false;
  return parts[0] === 10 || (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) || (parts[0] === 192 && parts[1] === 168);
}

function interfaceKindLabel(name: string, t: (key: string) => string): string {
  if (isOverlayInterface(name)) return t("interface.kindOverlay");
  if (name === "en0") return t("interface.kindWifi");
  if (/^en[1-9]\d*$/.test(name)) return t("interface.kindPhysical");
  if (name.startsWith("bridge")) return t("interface.kindBridge");
  return t("interface.kindUnknown");
}

function RunPage({
  onRunningChange,
  auditInterface,
  onAuthorizeNewRun,
  onComplete,
  onReport,
}: {
  onRunningChange: (running: boolean) => void;
  auditInterface: string;
  onAuthorizeNewRun: () => void;
  onComplete: (report: LatestReport) => void;
  onReport: () => void;
}) {
  const { t } = useI18n();
  const [steps, setSteps] = useState<AuditStep[]>(freshSteps);
  const [running, setRunning] = useState(false);
  const [complete, setComplete] = useState(false);
  const [runError, setRunError] = useState("");

  const updateStep = (id: AuditStepId, update: Partial<AuditStep>) => {
    setSteps((current) => current.map((step) => step.id === id ? { ...step, ...update } : step));
  };

  useEffect(() => {
    let active = true;
    let unlisten: (() => void) | undefined;
    listen<AuditStepEvent>("audit-step-status", (event) => {
      if (!active) return;
      updateStep(event.payload.stepId, {
        status: event.payload.status,
        result: event.payload.result ?? undefined,
      });
      if (event.payload.error) setRunError(event.payload.error);
    }).then((stopListening) => { unlisten = stopListening; }).catch((value) => setRunError(errorMessage(value)));
    return () => { active = false; unlisten?.(); };
  }, []);

  const runAudit = async () => {
    setSteps(freshSteps());
    setRunError("");
    setComplete(false);
    setRunning(true);
    onRunningChange(true);
    try {
      const result = await invoke<FullAuditResult>("run_full_audit", { auditInterface });
      result.steps.forEach((stepResult) => updateStep(stepResult.stepId, { status: stepResult.skipped ? "skipped" : stepResult.success ? "success" : "failed", result: stepResult }));
      if (!result.success) {
        setRunError(t("run.stepFailedStop"));
        return;
      }
      const report = await invoke<LatestReport>("read_latest_report");
      onComplete(report);
      setComplete(true);
    } catch (value) {
      setRunError(errorMessage(value));
    } finally {
      setRunning(false);
      onRunningChange(false);
    }
  };

  return (
    <section className="content-stack">
      <div className="page-heading">
        <PageHeading eyebrow={`${t("run.eyebrow")} · ${auditInterface}`} title={t("run.title")} description={t("run.description")} />
        <div className="actions">
          {!complete && !runError && <button className="primary" type="button" disabled={running} onClick={runAudit}>{running ? `${t("status.running")}…` : t("run.runFullAudit")}</button>}
          {!complete && runError && <button className="primary" type="button" onClick={onAuthorizeNewRun}>{t("run.authorizationRequiredAgain")}</button>}
          {complete && <button className="primary" type="button" onClick={onReport}>{t("run.viewReport")}</button>}
          <button className="secondary" type="button" disabled>{t("run.stopOnFailure")}</button>
        </div>
      </div>
      <p className="mode-banner"><strong>{t("run.stopOnFailure")}</strong><span>{t("run.stopDescription")}</span></p>
      {runError && <RawDetail detail={runError} />}
      <div className="step-list">
        {steps.map((step, index) => (
          <article className={`step card ${step.status}`} key={step.id}>
            <div className="step-number">{index + 1}</div>
            <div className="step-main">
              <div className="step-title">
                <div><h2>{t(step.labelKey)}</h2><p>{t(step.descriptionKey)}</p></div>
                <div className="step-meta"><span>{formatDuration(step.result?.durationMs, t("run.durationPending"))}</span><span className={`status-pill ${step.status}`}>{t(`status.${step.status}`)}</span></div>
              </div>
              {step.result && (step.result.stdout.trim() || step.result.stderr.trim()) && (
                <details className="step-logs" open={step.status === "failed"}>
                  <summary>{t("run.viewLogs")}</summary>
                  <div className="logs">
                    {step.result.stdout.trim() && <pre><strong>{t("run.stdout")}</strong>{"\n"}{step.result.stdout}</pre>}
                    {step.result.stderr.trim() && <pre className="stderr"><strong>{t("run.stderr")}</strong>{"\n"}{step.result.stderr}</pre>}
                  </div>
                </details>
              )}
            </div>
          </article>
        ))}
      </div>
    </section>
  );
}

function ReportPage({ initialReport }: { initialReport: LatestReport | null }) {
  const { locale, t } = useI18n();
  const [report, setReport] = useState<LatestReport | null>(initialReport);
  const [error, setError] = useState("");
  const [view, setView] = useState<"localized" | "raw">("localized");
  const copy = reportCopy(locale);

  useEffect(() => {
    if (!report) invoke<LatestReport>("read_latest_report").then(setReport).catch((value) => setError(errorMessage(value)));
  }, [report]);

  return (
    <section className="content-stack">
      <PageHeading eyebrow={copy.latestLocalAudit} title={t("report")} description={copy.description} />
      <p className="limitation">{copy.pointInTime}</p>
      {error && <RawDetail detail={error} />}
      {!report && !error && <p className="message">{t("report.loading")}</p>}
      {report && (
        <>
          {report.missingFiles.length > 0 && <p className="message error">{t("missingFiles")}: {report.missingFiles.join(", ")}</p>}
          <SummaryCards summary={normalizedSummary(report)} />
          <div className="report-tabs" role="tablist">
            <button className={view === "localized" ? "active" : ""} type="button" role="tab" aria-selected={view === "localized"} onClick={() => setView("localized")}>{copy.localizedView}</button>
            <button className={view === "raw" ? "active" : ""} type="button" role="tab" aria-selected={view === "raw"} onClick={() => setView("raw")}>{copy.rawView}</button>
          </div>
          {view === "localized" ? <LocalizedReport report={report} locale={locale} /> : <RawEvidence report={report} locale={locale} />}
        </>
      )}
    </section>
  );
}

function SummaryCards({ summary }: { summary: ReportSummary }) {
  const { locale, t } = useI18n();
  const copy = reportCopy(locale);
  const cards: [string, number | string | null, string][] = [
    [t("high"), summary.highCount, "high"], [t("medium"), summary.mediumCount, "medium"], [t("low"), summary.lowCount, "low"],
    [t("reachableClients"), summary.reachableClients, ""], [t("unreachableClients"), summary.unreachableClients, ""],
    [t("openServiceHosts"), summary.openServiceHosts, ""], [t("gatewayPosture"), localizeGatewayStatus(summary.gatewayPostureStatus, locale), ""],
  ];
  return <div className="summary-grid">{cards.map(([label, value, tone]) => <div className={`summary-card card ${tone}`} key={label}><span>{label}</span><strong>{value ?? copy.unknown}</strong></div>)}</div>;
}

function normalizedSummary(report: LatestReport): ReportSummary {
  if (report.riskRegister === null) return report.summary;
  const findings = deduplicateFindings(report.findings);
  const count = (severity: string) => findings.filter((finding) => finding.severity.toLowerCase() === severity).length;
  return { ...report.summary, highCount: count("high"), mediumCount: count("medium"), lowCount: count("low") };
}

function LocalizedReport({ report, locale }: { report: LatestReport; locale: Locale }) {
  const copy = reportCopy(locale);
  const localized = deduplicateFindings(report.findings).map((finding) => localizeFinding(finding, locale));
  const generatedAt = report.generatedAt ? new Date(report.generatedAt * 1000).toLocaleString(locale) : copy.unknown;
  return (
    <div className="content-stack localized-report">
      <article className="card report-section">
        <h2>{copy.executiveSummary}</h2>
        <p>{copy.executiveBody}</p>
        <dl className="report-metadata">
          <div><dt>{copy.generatedAt}</dt><dd>{generatedAt}</dd></div>
          <div><dt>{copy.labDirectory}</dt><dd className="path">{report.labDirectory || copy.unknown}</dd></div>
        </dl>
      </article>
      <FindingsTable findings={localized} locale={locale} />
      <RemediationRoadmap findings={localized} locale={locale} />
    </div>
  );
}

function FindingsTable({ findings, locale }: { findings: LocalizedFinding[]; locale: Locale }) {
  const { t } = useI18n();
  const copy = reportCopy(locale);
  return (
    <section className="card report-section">
      <h2>{copy.riskRegister}</h2>
      {findings.length === 0 ? <p className="muted">{copy.noFindings}</p> : (
        <div className="table-wrap"><table><thead><tr><th>{copy.severity}</th><th>{copy.asset}</th><th>{copy.category}</th><th>{copy.finding}</th><th>{copy.recommendedAction}</th><th>{copy.status}</th></tr></thead>
          <tbody>{findings.map((finding, index) => <tr key={`${finding.asset}-${finding.finding}-${index}`}><td><span className={`severity ${finding.severity.toLowerCase()}`}>{t(finding.severity.toLowerCase())}</span></td><td>{localizeAssetLabel(finding.asset, locale)}</td><td>{finding.localizedCategory}{!finding.matched && <span className="raw-badge">{copy.raw}</span>}</td><td>{finding.localizedFinding}</td><td>{finding.localizedRecommendedAction}</td><td>{finding.localizedStatus}</td></tr>)}</tbody>
        </table></div>
      )}
    </section>
  );
}

function RemediationRoadmap({ findings, locale }: { findings: LocalizedFinding[]; locale: Locale }) {
  const copy = reportCopy(locale);
  const groups: [string, string][] = [["High", copy.daysHigh], ["Medium", copy.daysMedium], ["Low", copy.daysLow]];
  return (
    <section className="card report-section">
      <h2>{copy.remediationRoadmap}</h2>
      {groups.map(([severity, label]) => {
        const items = findings.filter((finding) => finding.severity.toLowerCase() === severity.toLowerCase());
        return items.length > 0 && <div className="roadmap-group" key={severity}><h3>{label}</h3><ul>{items.map((finding) => <li key={`${finding.asset}-${finding.finding}`}><strong>{localizeAssetLabel(finding.asset, locale)}</strong>: {finding.localizedFinding} {copy.recommendationPrefix}: {finding.localizedRecommendedAction}</li>)}</ul></div>;
      })}
      {findings.length === 0 && <p className="muted">{copy.noFindings}</p>}
    </section>
  );
}

function RawEvidence({ report, locale }: { report: LatestReport; locale: Locale }) {
  const copy = reportCopy(locale);
  return (
    <div className="content-stack raw-evidence">
      <p className="message">{copy.rawPreserved}</p>
      <ReportSection title="executive-summary.md" content={report.executiveSummary} />
      <ReportSection title="technical-report.md" content={report.technicalReport} collapsible />
      <ReportSection title="network-issues-register.csv" content={report.riskRegister} collapsible />
      <ReportSection title="remediation-roadmap.md" content={report.remediationRoadmap} collapsible />
      {report.evidenceIndex && <ReportSection title="evidence-index.md" content={report.evidenceIndex} collapsible />}
    </div>
  );
}

function ReportSection({ title, content, collapsible = false }: { title: string; content: string | null; collapsible?: boolean }) {
  const { t } = useI18n();
  if (collapsible) return <details className="card report-section"><summary>{title}</summary><pre>{content ?? t("status.unknown")}</pre></details>;
  return <article className="card report-section"><h2>{title}</h2><pre>{content ?? t("status.unknown")}</pre></article>;
}

function GovernanceDataPage({ titleKey, descriptionKey, fields }: { titleKey: string; descriptionKey: string; fields: (keyof LatestReport)[] }) {
  const { t } = useI18n();
  const [report, setReport] = useState<LatestReport | null>(null);
  const [error, setError] = useState("");
  useEffect(() => { invoke<LatestReport>("read_latest_report").then(setReport).catch((value) => setError(errorMessage(value))); }, []);
  return <section className="content-stack">
    <PageHeading eyebrow={t("toolbox.eyebrow")} title={t(titleKey)} description={t(descriptionKey)} />
    <p className="limitation">{t("toolbox.observationLimit")}</p>
    {error && <RawDetail detail={error} />}
    {!report && !error && <p className="message">{t("common.loading")}</p>}
    {report && fields.map((field) => <ReportSection key={field} title={t(`toolbox.file.${field}`)} content={(report[field] as string | null) ?? null} collapsible />)}
  </section>;
}

function RemediationPage({ onRetest }: { onRetest: () => void }) {
  const { t, locale } = useI18n();
  const [report, setReport] = useState<LatestReport | null>(null);
  const [pack, setPack] = useState<RemediationPack | null>(null);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  useEffect(() => {
    Promise.all([invoke<LatestReport>("read_latest_report"), invoke<RemediationPack | null>("read_remediation_pack")])
      .then(([latest, existing]) => { setReport(latest); setPack(existing); })
      .catch((value) => setError(errorMessage(value)));
  }, []);
  const update = (index: number, patch: Partial<RemediationPack["tickets"][number]>) =>
    setPack((current) => current ? {...current, tickets:current.tickets.map((ticket, item) => item === index ? {...ticket, ...patch} : ticket)} : current);
  const save = async (next = pack) => {
    if (!next) return;
    setError(""); setMessage("");
    try { await invoke("save_remediation_pack", { pack: next }); setPack(next); setMessage(t("remediation.saved")); }
    catch (value) { setError(errorMessage(value)); }
  };
  const generate = async () => {
    if (!report) return;
    const next = buildRemediationPack(report.findings, locale, report.labDirectory);
    await save(next);
  };
  const statuses: RemediationStatus[] = ["open","assigned","in_progress","remediated","accepted_risk","retest_required","verified"];
  return <section className="content-stack">
    <PageHeading eyebrow={t("toolbox.eyebrow")} title={t("remediation.title")} description={t("remediation.description")} />
    <p className="limitation">{t("remediation.safety")}</p>
    <div className="actions">
      <button className="primary" type="button" disabled={!report} onClick={generate}>{t("remediation.generate")}</button>
      <button className="secondary" type="button" disabled={!pack} onClick={() => save()}>{t("toolbox.saveRemediation")}</button>
      <button className="secondary" type="button" disabled={!pack} onClick={() => invoke("export_latest_lab_zip").then(() => setMessage(t("remediation.saved"))).catch((value) => setError(errorMessage(value)))}>{t("remediation.export")}</button>
      <button className="secondary" type="button" onClick={onRetest}>{t("remediation.retest")}</button>
    </div>
    {pack?.tickets.map((ticket, index) => <article className="card compact remediation-editor" key={ticket.id}>
      <h2>{ticket.id} · {ticket.asset}</h2>
      <p>{ticket.localizedFinding}</p>
      <p><strong>{ticket.localizedRecommendedAction}</strong></p>
      <div className="form-grid">
        <label>{t("toolbox.owner")}<input value={ticket.owner} onChange={(event) => update(index, { owner: event.target.value })} /></label>
        <label>{t("toolbox.dueDate")}<input type="date" value={ticket.dueDate} onChange={(event) => update(index, { dueDate: event.target.value })} /></label>
        <label>{t("toolbox.status")}<select value={ticket.status} onChange={(event) => update(index, { status:event.target.value as RemediationStatus })}>{statuses.map((status) => <option key={status} value={status}>{t(`remediation.status.${status}`)}</option>)}</select></label>
        <label>{t("toolbox.priority")}<select value={ticket.priority} onChange={(event) => update(index, { priority:event.target.value })}><option value="High">{t("high")}</option><option value="Medium">{t("medium")}</option><option value="Low">{t("low")}</option><option value="Routine">{t("toolbox.priorityRoutine")}</option></select></label>
        <label className="full-width">{t("toolbox.businessJustification")}<textarea value={ticket.businessJustification} onChange={(event) => update(index, { businessJustification:event.target.value })} /></label>
        <label className="full-width">{t("toolbox.notes")}<textarea value={ticket.notes} onChange={(event) => update(index, { notes:event.target.value })} /></label>
      </div>
      <details><summary>{t("remediation.manualSteps")}</summary><ol>{ticket.manualSteps.map((step) => <li key={step}>{step}</li>)}</ol></details>
      <details><summary>{t("remediation.validationSteps")}</summary><ol>{ticket.validationSteps.map((step) => <li key={step}>{step}</li>)}</ol></details>
      <details><summary>{t("remediation.rollback")}</summary><ol>{ticket.rollbackConsiderations.map((step) => <li key={step}>{step}</li>)}</ol></details>
    </article>)}
    {!pack && !error && <p className="message">{t("remediation.noPack")}</p>}
    {message && <p className="message success-message">{message}</p>}{error && <RawDetail detail={error} />}
  </section>;
}

function NetworkReliabilityPage({ onRunningChange, onComplete }: { onRunningChange: (running: boolean) => void; onComplete: (result: NetworkReliabilityRun) => void }) {
  const { t } = useI18n();
  const [confirmed, setConfirmed] = useState(false);
  const [mode, setMode] = useState<DoctorMode>("quick");
  const [interfaces, setInterfaces] = useState<AuditInterface[]>([]);
  const [selectedInterface, setSelectedInterface] = useState("");
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState<NetworkReliabilityRun | null>(null);
  const [resultMode, setResultMode] = useState<NetworkDoctorResultMode>("empty");
  const [lastRunAt, setLastRunAt] = useState("");
  const [lastRunMode, setLastRunMode] = useState<DoctorMode | null>(null);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const canRun = confirmed && !running;

  useEffect(() => {
    invoke<AuditInterface[]>("list_audit_interfaces")
      .then((items) => {
        setInterfaces(items);
        if (!selectedInterface) {
          const preferred = pickPreferredAuditInterface(items);
          if (preferred) setSelectedInterface(preferred.name);
        }
      })
      .catch(() => setInterfaces([]));
  }, [selectedInterface]);

  const runCheck = async () => {
    setRunning(true);
    onRunningChange(true);
    setError("");
    setMessage("");
    setResult(null);
    try {
      await invoke("authorize_audit", { projectName: mode === "quick" ? "Network Doctor Quick Check" : "Network Doctor Deep Diagnosis" });
      const next = await invoke<NetworkReliabilityRun>("run_network_reliability_check", { mode });
      const completed = { ...next, doctorMode: mode };
      setResult(completed);
      setResultMode("real");
      setLastRunAt(completed.evidence.generatedAt ?? new Date().toISOString());
      setLastRunMode(mode);
      onComplete(completed);
      setMessage(`${t("reliability.savedTo")}: ${completed.outputDirectory}`);
      setConfirmed(false);
    } catch (value) {
      setError(errorMessage(value));
      setResultMode("failed");
      setLastRunMode(mode);
    } finally {
      setRunning(false);
      onRunningChange(false);
    }
  };

  const showDemo = () => {
    setError("");
    setMessage("");
    setResult({ ...demoNetworkReliabilityRun, doctorMode: "quick" });
    setResultMode("demo");
    setLastRunAt(demoNetworkReliabilityRun.evidence.generatedAt ?? "");
    setLastRunMode("quick");
  };

  const openArtifact = async (kind: string) => {
    setError("");
    setMessage("");
    try {
      await invoke("open_network_reliability_artifact", { kind });
    } catch (value) {
      setError(errorMessage(value));
    }
  };

  return (
    <section className="content-stack reliability-page">
      <PageHeading eyebrow={t("reliability.eyebrow")} title={t("reliability.title")} description={t("reliability.description")} />
      <section className="card compact lightweight-confirmation">
        <div>
          <h2>{t("reliability.lightConfirmTitle")}</h2>
          <p>{t("reliability.lightConfirmDescription")}</p>
        </div>
        <div className="doctor-mode-selector" aria-label={t("reliability.mode")}>
          <button className={mode === "quick" ? "mode-option active" : "mode-option"} type="button" disabled={running} onClick={() => setMode("quick")}>
            <strong>{t("reliability.quickCheck")}</strong>
            <span>{t("reliability.quickCheckHint")}</span>
          </button>
          <button className={mode === "deep" ? "mode-option active" : "mode-option"} type="button" disabled={running} onClick={() => setMode("deep")}>
            <strong>{t("reliability.deepDiagnosis")}</strong>
            <span>{t("reliability.deepDiagnosisHint")}</span>
          </button>
        </div>
        <label className="confirmation">
          <input type="checkbox" checked={confirmed} onChange={(event) => setConfirmed(event.target.checked)} />
          <span><strong>{t("reliability.lightConfirmCheck")}</strong></span>
        </label>
        <div className="actions">
          <button className="primary" type="button" disabled={!canRun} onClick={runCheck}>{running ? t("reliability.running") : mode === "quick" ? t("button.startNetworkCheck") : t("reliability.deepDiagnosis")}</button>
        </div>
      </section>
      <NetworkInterfaceSelector interfaces={interfaces} selected={selectedInterface} onSelect={setSelectedInterface} mode="reliability" />
      <p className="limitation">{t("reliability.pointInTime")}</p>
      {message && <p className="message success-message">{message}</p>}
      {error && <RawDetail detail={error} />}
      {resultMode === "empty" && !result && !error && <NetworkDoctorEmptyState interfaces={interfaces} selectedInterface={selectedInterface} mode={mode} onDemo={showDemo} />}
      {resultMode === "failed" && <NetworkDoctorFailedState error={error} mode={mode} />}
      {result && <NetworkReliabilityResult result={result} resultMode={resultMode} lastRunAt={lastRunAt} lastRunMode={lastRunMode} onOpenArtifact={openArtifact} />}
    </section>
  );
}

function NetworkDoctorEmptyState({ interfaces, selectedInterface, mode, onDemo }: { interfaces: AuditInterface[]; selectedInterface: string; mode: DoctorMode; onDemo: () => void }) {
  const { t } = useI18n();
  const selected = interfaces.find((item) => item.name === selectedInterface) ?? pickPreferredAuditInterface(interfaces);
  return (
    <section className="card compact doctor-empty-state">
      <div>
        <span className="eyebrow">{t("reliability.resultMode.empty")}</span>
        <h2>{t("reliability.emptyTitle")}</h2>
        <p>{t("reliability.emptyDescription")}</p>
      </div>
      <dl className="report-metadata single-column">
        <div><dt>{t("reliability.lastRun")}</dt><dd>{t("reliability.noRealRunYet")}</dd></div>
        <div><dt>{t("reliability.pendingMode")}</dt><dd>{mode === "quick" ? t("reliability.quickCheck") : t("reliability.deepDiagnosis")}</dd></div>
        <div><dt>{t("reliability.localInterfaceSummary")}</dt><dd>{selected ? `${selected.name} / ${selected.ipv4 || t("interface.noIpv4")}` : t("interface.noInterfaces")}</dd></div>
      </dl>
      <div className="actions">
        <button className="secondary" type="button" onClick={onDemo}>{t("reliability.viewDemoResult")}</button>
      </div>
    </section>
  );
}

function NetworkDoctorFailedState({ error, mode }: { error: string; mode: DoctorMode }) {
  const { t } = useI18n();
  return (
    <section className="card compact doctor-empty-state failed">
      <span className="eyebrow">{t("reliability.resultMode.failed")}</span>
      <h2>{t("reliability.failedTitle")}</h2>
      <p>{t("reliability.failedDescription")}</p>
      <dl className="report-metadata single-column">
        <div><dt>{t("reliability.lastRunMode")}</dt><dd>{mode === "quick" ? t("reliability.quickCheck") : t("reliability.deepDiagnosis")}</dd></div>
        <div><dt>{t("common.error")}</dt><dd>{error || t("status.unknown")}</dd></div>
      </dl>
    </section>
  );
}

function NetworkReliabilityResult({ result, resultMode, lastRunAt, lastRunMode, onOpenArtifact }: { result: NetworkReliabilityRun; resultMode: NetworkDoctorResultMode; lastRunAt: string; lastRunMode: DoctorMode | null; onOpenArtifact: (kind: string) => Promise<void> }) {
  const { locale, t } = useI18n();
  const summary = result.summary;
  const evidence = result.evidence;
  const doctor = diagnoseNetworkDoctor(evidence, result.doctorMode ?? "quick");
  const demo = resultMode === "demo";
  const evidenceSource = demo ? "synthetic" : "local-collector";
  const overlayComponents = [
    evidence.overlay.stashDetected ? "Stash" : "",
    evidence.overlay.tailscaleRunning ? "Tailscale" : "",
    evidence.overlay.wireGuardDetected ? "WireGuard" : "",
    evidence.overlay.openVpnDetected ? "OpenVPN" : "",
    evidence.overlay.clashDetected ? "Clash" : "",
    evidence.overlay.surgeDetected ? "Surge" : "",
  ].filter(Boolean).join(", ") || t("status.unknown");

  return (
    <div className="content-stack">
      {demo && <p className="message demo-message">{t("reliability.demoModeNotice")}</p>}
      <section className="card compact doctor-hero">
        <div>
          <div className="panel-heading">
            <span className="eyebrow">{t("reliability.eyebrow")}</span>
            <StatusBadge status={doctor.overallStatus} label={formatScoreState(doctor.overallState, locale)} />
          </div>
          <h2>{t("reliability.currentPath")}</h2>
          <p>{doctor.currentNetworkPath}</p>
          <p className="muted">{formatRunMetadata(resultMode, evidenceSource, lastRunAt, lastRunMode, t)}</p>
        </div>
        <div className="doctor-score">
          <span>{t("reliability.score")}</span>
          <strong>{doctor.overallScore}</strong>
          <small>{formatScoreState(doctor.overallState, locale)}</small>
        </div>
      </section>
      <div className="doctor-overview-grid">
        <section className="card compact">
          <h2>{t("reliability.primaryFaultDomain")}</h2>
          <p className="doctor-domain">{formatPrimaryFaultSummary(doctor.primaryFaultDomain, doctor.overallStatus, locale, t)}</p>
          <p className="muted">{formatOsiLayerSummary(doctor.osiLayerMapping, t)}</p>
        </section>
        <section className="card compact">
          <h2>{t("reliability.contributingDomains")}</h2>
          <p className="doctor-domain">{doctor.contributingDomains.map((domain) => formatDomainLabel(domain, locale)).join(" · ") || t("status.unknown")}</p>
          <p className="muted">{t("reliability.osiMapping")}</p>
        </section>
      </div>
      <DoctorScorecards scorecards={doctor.scorecards} />
      <RootCauseCandidates candidates={doctor.rootCauseCandidates.slice(0, 3)} overallStatus={doctor.overallStatus} primaryFaultDomain={doctor.primaryFaultDomain} />
      <DoctorActionPanel candidate={doctor.rootCauseCandidates[0]} overallStatus={doctor.overallStatus} primaryFaultDomain={doctor.primaryFaultDomain} />
      <div className="summary-grid reliability-summary">
        <ReliabilitySummaryCard label={t("reliability.overallStatus")} status={summary.overallStatus} />
        <ReliabilitySummaryCard label={t("reliability.physicalLan")} status={summary.physicalLanStatus} />
        <ReliabilitySummaryCard label={t("reliability.dns")} status={summary.dnsStatus} />
        <ReliabilitySummaryCard label={t("reliability.overlay")} status={summary.overlayStatus} />
        <ReliabilitySummaryCard label={t("reliability.externalInternet")} status={summary.externalPathStatus} />
      </div>
      <section className="card compact reliability-path">
        <h2>{t("reliability.networkPathView")}</h2>
        <NetworkPathMap summary={summary} evidence={evidence} resultMode={resultMode} />
      </section>
      <LatencyVisualization evidence={evidence} />
      <div className="reliability-grid">
        <section className="card compact diagnosis-panel">
          <h2>{t("reliability.faultPoint")}</h2>
          <p>{localizeReliabilityText(summary.faultPoint, locale)}</p>
          <p className="muted">{localizeReliabilityText(summary.impact, locale)}</p>
        </section>
        <section className="card compact">
          <h2>{t("reliability.evidencePanel")}</h2>
          <dl className="report-metadata single-column">
            <div><dt>{t("reliability.profile")}</dt><dd>{evidence.profile || t("status.unknown")}</dd></div>
            <div><dt>{t("reliability.interface")}</dt><dd>{evidence.physicalLan.activeInterface}</dd></div>
            <div><dt>{t("reliability.gateway")}</dt><dd>{evidence.physicalLan.gatewayIp ?? t("status.unknown")}</dd></div>
            <div><dt>{t("reliability.gatewayLoss")}</dt><dd>{formatNullablePercent(evidence.physicalLan.gatewayPingLossPct, t("status.unknown"))}</dd></div>
            <div><dt>{t("reliability.gatewayLatency")}</dt><dd>{formatNullableMs(evidence.physicalLan.gatewayPingAvgMs, t("status.unknown"))}</dd></div>
            <div><dt>{t("reliability.systemDns")}</dt><dd>{evidence.localControlPlane.systemDnsServers.join(", ") || t("status.unknown")}</dd></div>
            <div><dt>{t("reliability.defaultRoute")}</dt><dd>{evidence.overlay.defaultRouteInterface ?? t("status.unknown")}</dd></div>
            <div><dt>{t("reliability.overlayComponents")}</dt><dd>{overlayComponents}</dd></div>
          </dl>
        </section>
      </div>
      <div className="network-check-sections">
        <DiagnosticSection title={t("networkCheck.physicalLan")} status={summary.physicalLanStatus} metrics={[
          [t("reliability.interface"), evidence.physicalLan.activeInterface],
          [t("overview.localIp"), evidence.physicalLan.ipv4 ?? t("status.unknown")],
          [t("reliability.gateway"), evidence.physicalLan.gatewayIp ?? t("status.unknown")],
          [t("reliability.gatewayLatency"), formatNullableMs(evidence.physicalLan.gatewayPingAvgMs, t("status.unknown"))],
          [t("reliability.gatewayP95"), formatNullableMs(evidence.physicalLan.gatewayPingP95Ms, t("status.unknown"))],
          [t("reliability.gatewayP99"), formatNullableMs(evidence.physicalLan.gatewayPingP99Ms, t("status.unknown"))],
          [t("reliability.gatewaySamples"), formatNullableCount(evidence.physicalLan.gatewayPingSampleCount, t("status.unknown"))],
        ]} judgement={summary.physicalLanStatus === "healthy" ? t("networkCheck.physicalHealthy") : localizeReliabilityText(summary.faultPoint, locale)} evidence={summary.evidence} advice={summary.remediationAdvice} />
        <DiagnosticSection title={t("networkCheck.dns")} status={summary.dnsStatus} metrics={[
          [t("overview.dhcpDns"), (evidence.physicalLan.dhcpDns ?? []).join(", ") || t("status.unknown")],
          [t("reliability.systemDns"), evidence.localControlPlane.systemDnsServers.join(", ") || t("status.unknown")],
          [t("overview.gatewayDns"), formatNullableMs(evidence.physicalLan.gatewayDnsMs, t("status.unknown"))],
          [t("reliability.resolverChecks"), formatResolverChecks(evidence.localControlPlane.resolverChecks, t("status.unknown"), t)],
        ]} judgement={evidence.overlay.dnsViaOverlay ? t("overview.dnsTakenByOverlay") : t("overview.dnsDirect")} evidence={summary.evidence} advice={summary.remediationAdvice} />
        <DiagnosticSection title={t("networkCheck.overlay")} status={summary.overlayStatus} metrics={[
          [t("reliability.defaultRoute"), evidence.overlay.defaultRouteInterface ?? t("status.unknown")],
          ["Stash", evidence.overlay.stashDetected ? t("status.active") : t("status.stopped")],
          ["Tailscale", evidence.overlay.tailscaleRunning ? t("status.active") : t("status.stopped")],
          ["utun", evidence.overlay.utunInterfaces.join(", ") || t("status.notDetected")],
        ]} judgement={overlayComponents} evidence={summary.evidence} advice={summary.remediationAdvice} />
        <DiagnosticSection title={t("networkCheck.external")} status={summary.externalPathStatus} metrics={evidence.external.targets.map((target) => [target.url, formatNullableMs(target.totalMs, t("status.unknown"))])} judgement={summary.externalPathStatus === "healthy" ? t("networkCheck.externalHealthy") : localizeReliabilityText(summary.faultPoint, locale)} evidence={summary.evidence} advice={summary.remediationAdvice} />
      </div>
      <div className="reliability-grid">
        <NetworkListCard title={t("reliability.advicePanel")} items={summary.remediationAdvice} />
        <NetworkListCard title={t("reliability.retest")} items={summary.retestPlan} ordered />
      </div>
      <section className="card compact export-card">
        <div>
          <h2>{t("reliability.supportBundle")}</h2>
          <p className="path">{result.supportBundlePath}</p>
        </div>
        <div className="actions">
          <button className="secondary" type="button" disabled={demo} onClick={() => onOpenArtifact("report")}>{t("reliability.exportMarkdown")}</button>
          <button className="secondary" type="button" disabled={demo} onClick={() => onOpenArtifact("summary")}>{t("reliability.exportJson")}</button>
          <button className="secondary" type="button" disabled={demo} onClick={() => onOpenArtifact("bundle")}>{t("button.exportSupportBundle")}</button>
          <button className="secondary" type="button" disabled={demo} onClick={() => onOpenArtifact("folder")}>{t("reliability.openOutput")}</button>
        </div>
      </section>
      <details className="card compact report-section">
        <summary>{t("reliability.rawEvidence")}</summary>
        <p className="muted">{t("reliability.rawEvidenceDescription")}</p>
        <pre>{JSON.stringify({ summary: result.summary, evidence: result.evidence }, null, 2)}</pre>
      </details>
    </div>
  );
}

function RealCollectorDetails({ evidence }: { evidence: NetworkReliabilityEvidence }) {
  const { t } = useI18n();
  const unknown = t("status.unknown");
  const pathNotice = evidence.physicalLan.iphoneHotspotLikely
    ? t("reliability.hotspotPathNotice")
    : evidence.physicalLan.selfAssignedAddress
      ? t("reliability.selfAssignedPathNotice")
      : evidence.physicalLan.networkPathNotice;
  const resolverChecks = evidence.localControlPlane.resolverChecks ?? [];

  return (
    <div className="reliability-grid">
      <section className="card compact">
        <h2>{t("reliability.gatewayDistribution")}</h2>
        {pathNotice && <p className="message">{pathNotice}</p>}
        <dl className="report-metadata single-column">
          <div><dt>{t("reliability.gatewayAvg")}</dt><dd>{formatNullableMs(evidence.physicalLan.gatewayPingAvgMs, unknown)}</dd></div>
          <div><dt>{t("reliability.gatewayP95")}</dt><dd>{formatNullableMs(evidence.physicalLan.gatewayPingP95Ms, unknown)}</dd></div>
          <div><dt>{t("reliability.gatewayP99")}</dt><dd>{formatNullableMs(evidence.physicalLan.gatewayPingP99Ms, unknown)}</dd></div>
          <div><dt>{t("reliability.gatewayMax")}</dt><dd>{formatNullableMs(evidence.physicalLan.gatewayPingMaxMs, unknown)}</dd></div>
          <div><dt>{t("reliability.gatewaySamples")}</dt><dd>{formatNullableCount(evidence.physicalLan.gatewayPingSampleCount, unknown)}</dd></div>
        </dl>
      </section>
      <section className="card compact">
        <h2>{t("reliability.dnsResolverChecks")}</h2>
        {resolverChecks.length === 0 ? (
          <p className="muted">{unknown}</p>
        ) : (
          <dl className="report-metadata single-column">
            {resolverChecks.map((check, index) => (
              <div key={`${check.address}-${index}`}>
                <dt>{check.name || check.address}</dt>
                <dd>{formatResolverCheck(check, unknown, t)}</dd>
              </div>
            ))}
          </dl>
        )}
      </section>
    </div>
  );
}

function DoctorScorecards({ scorecards }: { scorecards: DoctorScorecard[] }) {
  const { locale, t } = useI18n();
  return (
    <section className="card compact doctor-scorecards">
      <div className="panel-heading">
        <h2>{t("reliability.score")}</h2>
      </div>
      <div className="doctor-scorecard-grid">
        {scorecards.map((card) => (
          <div className={`doctor-scorecard ${card.status}`} key={card.name}>
            <span>{formatScorecardName(card.name, locale)}</span>
            <strong>{card.score}</strong>
            <small>{formatScoreState(card.state, locale)}</small>
          </div>
        ))}
      </div>
    </section>
  );
}

function RootCauseCandidates({ candidates, overallStatus, primaryFaultDomain }: { candidates: RootCauseCandidate[]; overallStatus: ReliabilityStatus; primaryFaultDomain: DiagnosticDomain }) {
  const { locale, t } = useI18n();
  if (primaryFaultDomain === "unknown" && overallStatus === "healthy") {
    return (
      <section className="card compact root-cause-panel">
        <h2>{t("reliability.rootCauseTop3")}</h2>
        <p className="message">{t("reliability.noClearFaultDetected")}</p>
      </section>
    );
  }
  return (
    <section className="card compact root-cause-panel">
      <h2>{t("reliability.rootCauseTop3")}</h2>
      <div className="root-cause-list">
        {candidates.map((candidate) => (
          <article className="root-cause-item" key={`${candidate.rank}-${candidate.faultDomain}`}>
            <div>
              <strong>{candidate.rank}. {localizeDoctorTitle(candidate.title, locale)}</strong>
              <span>{formatDomainLabel(candidate.faultDomain, locale)}</span>
            </div>
            <dl>
              <div><dt>{t("reliability.probability")}</dt><dd>{candidate.probability}%</dd></div>
              <div><dt>{t("reliability.confidence")}</dt><dd>{formatConfidence(candidate.confidence, locale)}</dd></div>
            </dl>
            <EvidenceDetails title={t("reliability.evidenceFor")} items={candidate.evidenceFor} locale={locale} />
            <EvidenceDetails title={t("reliability.evidenceAgainst")} items={candidate.evidenceAgainst} locale={locale} />
          </article>
        ))}
      </div>
    </section>
  );
}

function EvidenceDetails({ title, items, locale }: { title: string; items: string[]; locale: Locale }) {
  const { t } = useI18n();
  if (items.length === 0) return <p className="muted">{t("reliability.insufficientEvidence")}</p>;
  return (
    <details>
      <summary>{title}</summary>
      <ul>{items.map((item) => <li key={item}>{localizeReliabilityText(item, locale)}</li>)}</ul>
    </details>
  );
}

function DoctorActionPanel({ candidate, overallStatus, primaryFaultDomain }: { candidate: RootCauseCandidate | undefined; overallStatus: ReliabilityStatus; primaryFaultDomain: DiagnosticDomain }) {
  const { locale, t } = useI18n();
  if (!candidate) return null;
  if (primaryFaultDomain === "unknown" && overallStatus === "healthy") return null;
  return (
    <section className="card compact doctor-action-panel">
      <div className="panel-heading">
        <h2>{t("reliability.recommendedActions")}</h2>
        <StatusBadge status={candidate.confidence === "High" ? "warning" : "unknown"} label={formatConfidence(candidate.confidence, locale)} />
      </div>
      <div className="doctor-action-grid">
        {candidate.remediationAdvice.slice(0, 2).map((advice) => (
          <article className="doctor-action" key={advice.action}>
            <h3>{localizeReliabilityText(advice.action, locale)}</h3>
            <dl>
              <div><dt>{t("reliability.reason")}</dt><dd>{localizeReliabilityText(advice.reason, locale)}</dd></div>
              <div><dt>{t("reliability.risk")}</dt><dd>{localizeReliabilityText(advice.risk, locale)}</dd></div>
              <div><dt>{t("reliability.expectedResult")}</dt><dd>{localizeReliabilityText(advice.expectedResult, locale)}</dd></div>
              <div><dt>{t("reliability.verification")}</dt><dd>{localizeReliabilityText(advice.verification, locale)}</dd></div>
            </dl>
          </article>
        ))}
      </div>
    </section>
  );
}

function DiagnosticSection({
  title,
  status,
  metrics,
  judgement,
  evidence,
  advice,
}: {
  title: string;
  status: ReliabilityStatus;
  metrics: [string, string][];
  judgement: string;
  evidence: string[];
  advice: string[];
}) {
  const { locale, t } = useI18n();
  return (
    <section className="card compact diagnostic-section">
      <div className="panel-heading">
        <h2>{title}</h2>
        <StatusBadge status={status} label={t(`reliability.status.${status}`)} />
      </div>
      <dl className="metric-list">
        {metrics.map(([label, value]) => <div key={`${title}-${label}`}><dt>{label}</dt><dd>{value}</dd></div>)}
      </dl>
      <div className="judgement"><strong>{t("networkCheck.judgement")}</strong><span>{judgement}</span></div>
      <details>
        <summary>{t("networkCheck.evidence")}</summary>
        <ul>{evidence.slice(0, 3).map((item) => <li key={item}>{localizeReliabilityText(item, locale)}</li>)}</ul>
      </details>
      <details>
        <summary>{t("networkCheck.advice")}</summary>
        <ul>{advice.slice(0, 4).map((item) => <li key={item}>{localizeReliabilityText(item, locale)}</li>)}</ul>
      </details>
    </section>
  );
}

function ReliabilitySummaryCard({ label, status }: { label: string; status: ReliabilityStatus }) {
  const { t } = useI18n();
  return <div className={`summary-card card reliability-status ${status}`}><span>{label}</span><strong>{t(`reliability.status.${status}`)}</strong></div>;
}

function NetworkListCard({ title, items, ordered = false }: { title: string; items: string[]; ordered?: boolean }) {
  const { locale, t } = useI18n();
  const Tag = ordered ? "ol" : "ul";
  return <section className="card compact reliability-list"><h2>{title}</h2>{items.length === 0 ? <p className="muted">{t("status.unknown")}</p> : <Tag>{items.map((item) => <li key={item}>{localizeReliabilityText(item, locale)}</li>)}</Tag>}</section>;
}

function formatNullableMs(value: number | null | undefined, unknown: string): string {
  return typeof value === "number" ? `${formatNumber(value)} ms` : unknown;
}

function formatNullablePercent(value: number | null | undefined, unknown: string): string {
  return typeof value === "number" ? `${formatNumber(value)}%` : unknown;
}

function formatNullableCount(value: number | null | undefined, unknown: string): string {
  return typeof value === "number" ? String(value) : unknown;
}

function formatResolverChecks(checks: NetworkReliabilityEvidence["localControlPlane"]["resolverChecks"], unknown: string, t: (key: string) => string): string {
  if (!checks || checks.length === 0) return unknown;
  return checks
    .slice(0, 3)
    .map((check) => formatResolverCheck(check, unknown, t))
    .join(" · ");
}

function formatResolverCheck(check: NonNullable<NetworkReliabilityEvidence["localControlPlane"]["resolverChecks"]>[number], unknown: string, t: (key: string) => string): string {
  const status = check.queryStatus ?? "not_tested";
  const parts = [
    check.address || unknown,
    formatNullableMs(check.responseMs, unknown),
    t(`reliability.resolverStatus.${status}`),
  ];
  if (check.viaOverlay) parts.push(t("reliability.viaOverlay"));
  return parts.join(" · ");
}

function formatNumber(value: number): string {
  return Number.isInteger(value) ? String(value) : value.toFixed(1);
}

function localizeReliabilityText(value: string, locale: Locale): string {
  const adviceKeys: Record<Locale, Record<string, string>> = {
    en: {
      "doctorAdvice.deepSample.action": "Collect a Deep Diagnosis sample.",
      "doctorAdvice.deepSample.reason": "Current evidence does not support one high-confidence root cause.",
      "doctorAdvice.deepSample.risk": "The check takes longer than Quick Check.",
      "doctorAdvice.deepSample.expected": "Additional samples improve confidence.",
      "doctorAdvice.deepSample.verify": "Run Deep Diagnosis and compare candidate probabilities.",
      "doctorAdvice.saveBaseline.action": "Save the current result as a baseline.",
      "doctorAdvice.saveBaseline.reason": "A healthy or ambiguous run can still help future comparisons.",
      "doctorAdvice.saveBaseline.risk": "Baseline labels must describe the network state.",
      "doctorAdvice.saveBaseline.expected": "Future route, DNS, and latency changes are easier to explain.",
      "doctorAdvice.saveBaseline.verify": "Compare the next run against this snapshot.",
    },
    "zh-CN": {
      "doctorAdvice.deepSample.action": "采集一次深度诊断样本",
      "doctorAdvice.deepSample.reason": "当前证据不足以支持单一高置信度根因。",
      "doctorAdvice.deepSample.risk": "该检查比快速诊断耗时更长。",
      "doctorAdvice.deepSample.expected": "更多样本可以提高判断置信度。",
      "doctorAdvice.deepSample.verify": "运行深度诊断并比较候选根因概率。",
      "doctorAdvice.saveBaseline.action": "将当前结果保存为基线",
      "doctorAdvice.saveBaseline.reason": "健康或不明确的运行结果仍可用于后续对比。",
      "doctorAdvice.saveBaseline.risk": "基线标签必须准确描述当时网络状态。",
      "doctorAdvice.saveBaseline.expected": "后续路由、DNS 和延迟变化会更容易解释。",
      "doctorAdvice.saveBaseline.verify": "将下一次运行结果与此快照对比。",
    },
    "zh-TW": {
      "doctorAdvice.deepSample.action": "採集一次深度診斷樣本",
      "doctorAdvice.deepSample.reason": "目前證據不足以支持單一高信賴度根因。",
      "doctorAdvice.deepSample.risk": "此檢查比快速診斷耗時更長。",
      "doctorAdvice.deepSample.expected": "更多樣本可以提高判斷信賴度。",
      "doctorAdvice.deepSample.verify": "執行深度診斷並比較候選根因機率。",
      "doctorAdvice.saveBaseline.action": "將目前結果儲存為基線",
      "doctorAdvice.saveBaseline.reason": "健康或不明確的執行結果仍可用於後續比較。",
      "doctorAdvice.saveBaseline.risk": "基線標籤必須準確描述當時網路狀態。",
      "doctorAdvice.saveBaseline.expected": "後續路由、DNS 與延遲變化會更容易解釋。",
      "doctorAdvice.saveBaseline.verify": "將下一次執行結果與此快照比較。",
    },
    ja: {
      "doctorAdvice.deepSample.action": "詳細診断サンプルを収集",
      "doctorAdvice.deepSample.reason": "現在の証拠では高信頼の単一根因を支持できません。",
      "doctorAdvice.deepSample.risk": "Quick Check より時間がかかります。",
      "doctorAdvice.deepSample.expected": "サンプルが増えるほど信頼度が上がります。",
      "doctorAdvice.deepSample.verify": "詳細診断を実行し、候補確率を比較します。",
      "doctorAdvice.saveBaseline.action": "現在の結果をベースラインとして保存",
      "doctorAdvice.saveBaseline.reason": "正常または曖昧な結果も将来比較に役立ちます。",
      "doctorAdvice.saveBaseline.risk": "ベースライン名はネットワーク状態を正確に示す必要があります。",
      "doctorAdvice.saveBaseline.expected": "今後のルート、DNS、遅延変化を説明しやすくなります。",
      "doctorAdvice.saveBaseline.verify": "次回実行をこのスナップショットと比較します。",
    },
    ko: {
      "doctorAdvice.deepSample.action": "심층 진단 샘플 수집",
      "doctorAdvice.deepSample.reason": "현재 근거만으로는 단일 고신뢰 원인을 지지하기 어렵습니다.",
      "doctorAdvice.deepSample.risk": "Quick Check보다 시간이 더 걸립니다.",
      "doctorAdvice.deepSample.expected": "샘플이 늘어나면 신뢰도가 높아집니다.",
      "doctorAdvice.deepSample.verify": "심층 진단을 실행하고 후보 확률을 비교합니다.",
      "doctorAdvice.saveBaseline.action": "현재 결과를 기준선으로 저장",
      "doctorAdvice.saveBaseline.reason": "정상 또는 모호한 결과도 향후 비교에 도움이 됩니다.",
      "doctorAdvice.saveBaseline.risk": "기준선 라벨은 네트워크 상태를 정확히 설명해야 합니다.",
      "doctorAdvice.saveBaseline.expected": "향후 경로, DNS, 지연 변화 해석이 쉬워집니다.",
      "doctorAdvice.saveBaseline.verify": "다음 실행 결과를 이 스냅샷과 비교합니다.",
    },
    de: {
      "doctorAdvice.deepSample.action": "Eine Deep-Diagnosis-Probe erfassen.",
      "doctorAdvice.deepSample.reason": "Die aktuellen Nachweise stützen keine einzelne Ursache mit hoher Konfidenz.",
      "doctorAdvice.deepSample.risk": "Die Prüfung dauert länger als Quick Check.",
      "doctorAdvice.deepSample.expected": "Mehr Proben erhöhen die Konfidenz.",
      "doctorAdvice.deepSample.verify": "Deep Diagnosis ausführen und Kandidatenwahrscheinlichkeiten vergleichen.",
      "doctorAdvice.saveBaseline.action": "Aktuelles Ergebnis als Baseline speichern.",
      "doctorAdvice.saveBaseline.reason": "Auch ein gesunder oder uneindeutiger Lauf hilft späteren Vergleichen.",
      "doctorAdvice.saveBaseline.risk": "Baseline-Beschriftungen müssen den Netzwerkzustand beschreiben.",
      "doctorAdvice.saveBaseline.expected": "Spätere Änderungen an Route, DNS und Latenz sind leichter erklärbar.",
      "doctorAdvice.saveBaseline.verify": "Den nächsten Lauf mit diesem Snapshot vergleichen.",
    },
    fr: {
      "doctorAdvice.deepSample.action": "Collecter un échantillon de diagnostic approfondi.",
      "doctorAdvice.deepSample.reason": "Les preuves actuelles ne soutiennent pas une cause unique avec forte confiance.",
      "doctorAdvice.deepSample.risk": "La vérification dure plus longtemps que Quick Check.",
      "doctorAdvice.deepSample.expected": "Des échantillons supplémentaires améliorent la confiance.",
      "doctorAdvice.deepSample.verify": "Exécuter le diagnostic approfondi et comparer les probabilités candidates.",
      "doctorAdvice.saveBaseline.action": "Enregistrer le résultat actuel comme baseline.",
      "doctorAdvice.saveBaseline.reason": "Un résultat sain ou ambigu reste utile pour les comparaisons futures.",
      "doctorAdvice.saveBaseline.risk": "Les libellés de baseline doivent décrire l’état réseau.",
      "doctorAdvice.saveBaseline.expected": "Les futurs changements de route, DNS et latence seront plus faciles à expliquer.",
      "doctorAdvice.saveBaseline.verify": "Comparer la prochaine exécution avec cet instantané.",
    },
    es: {
      "doctorAdvice.deepSample.action": "Recopilar una muestra de diagnóstico profundo.",
      "doctorAdvice.deepSample.reason": "La evidencia actual no respalda una única causa con alta confianza.",
      "doctorAdvice.deepSample.risk": "La comprobación tarda más que Quick Check.",
      "doctorAdvice.deepSample.expected": "Más muestras mejoran la confianza.",
      "doctorAdvice.deepSample.verify": "Ejecutar diagnóstico profundo y comparar probabilidades candidatas.",
      "doctorAdvice.saveBaseline.action": "Guardar el resultado actual como línea base.",
      "doctorAdvice.saveBaseline.reason": "Una ejecución sana o ambigua también ayuda en comparaciones futuras.",
      "doctorAdvice.saveBaseline.risk": "Las etiquetas de línea base deben describir el estado de red.",
      "doctorAdvice.saveBaseline.expected": "Los futuros cambios de ruta, DNS y latencia serán más fáciles de explicar.",
      "doctorAdvice.saveBaseline.verify": "Comparar la próxima ejecución con esta instantánea.",
    },
    "pt-BR": {
      "doctorAdvice.deepSample.action": "Coletar uma amostra de diagnóstico profundo.",
      "doctorAdvice.deepSample.reason": "As evidências atuais não sustentam uma causa única com alta confiança.",
      "doctorAdvice.deepSample.risk": "A verificação leva mais tempo que o Quick Check.",
      "doctorAdvice.deepSample.expected": "Mais amostras aumentam a confiança.",
      "doctorAdvice.deepSample.verify": "Executar diagnóstico profundo e comparar probabilidades candidatas.",
      "doctorAdvice.saveBaseline.action": "Salvar o resultado atual como baseline.",
      "doctorAdvice.saveBaseline.reason": "Uma execução saudável ou ambígua ainda ajuda comparações futuras.",
      "doctorAdvice.saveBaseline.risk": "Os rótulos de baseline devem descrever o estado da rede.",
      "doctorAdvice.saveBaseline.expected": "Mudanças futuras de rota, DNS e latência ficam mais fáceis de explicar.",
      "doctorAdvice.saveBaseline.verify": "Comparar a próxima execução com este snapshot.",
    },
    it: {
      "doctorAdvice.deepSample.action": "Raccogliere un campione di diagnosi approfondita.",
      "doctorAdvice.deepSample.reason": "Le evidenze attuali non supportano una singola causa ad alta confidenza.",
      "doctorAdvice.deepSample.risk": "La verifica richiede più tempo di Quick Check.",
      "doctorAdvice.deepSample.expected": "Più campioni migliorano la confidenza.",
      "doctorAdvice.deepSample.verify": "Eseguire la diagnosi approfondita e confrontare le probabilità candidate.",
      "doctorAdvice.saveBaseline.action": "Salvare il risultato attuale come baseline.",
      "doctorAdvice.saveBaseline.reason": "Un risultato sano o ambiguo aiuta comunque i confronti futuri.",
      "doctorAdvice.saveBaseline.risk": "Le etichette baseline devono descrivere lo stato della rete.",
      "doctorAdvice.saveBaseline.expected": "Le future variazioni di route, DNS e latenza saranno più facili da spiegare.",
      "doctorAdvice.saveBaseline.verify": "Confrontare la prossima esecuzione con questo snapshot.",
    },
    nl: {
      "doctorAdvice.deepSample.action": "Een Deep Diagnosis-sample verzamelen.",
      "doctorAdvice.deepSample.reason": "Het huidige bewijs ondersteunt geen enkele oorzaak met hoge zekerheid.",
      "doctorAdvice.deepSample.risk": "De controle duurt langer dan Quick Check.",
      "doctorAdvice.deepSample.expected": "Meer samples verhogen de zekerheid.",
      "doctorAdvice.deepSample.verify": "Deep Diagnosis uitvoeren en kandidaatkansen vergelijken.",
      "doctorAdvice.saveBaseline.action": "Het huidige resultaat als baseline opslaan.",
      "doctorAdvice.saveBaseline.reason": "Een gezonde of dubbelzinnige run helpt nog steeds bij latere vergelijkingen.",
      "doctorAdvice.saveBaseline.risk": "Baseline-labels moeten de netwerkstatus beschrijven.",
      "doctorAdvice.saveBaseline.expected": "Latere route-, DNS- en latentieverschillen zijn makkelijker te verklaren.",
      "doctorAdvice.saveBaseline.verify": "Vergelijk de volgende run met deze snapshot.",
    },
  };
  const englishAdvice = adviceKeys.en[value];
  if (englishAdvice) return adviceKeys[locale][value] ?? englishAdvice;
  const zhCN: Record<string, string> = {
    "Physical LAN is healthy; internet path is currently handled by Stash TUN.": "物理网络正常，当前上网路径由 Stash TUN 接管。",
    "No physical LAN fault is indicated; traffic is intentionally using an overlay path.": "当前没有物理网络故障迹象，流量正在按预期使用 Overlay 路径。",
    "Physical LAN has DHCP, router, and stable gateway reachability.": "物理网络具备 DHCP、路由器和稳定网关可达性。",
    "Default route uses an overlay interface and Stash indicators are present.": "默认路由使用 Overlay 接口，并检测到 Stash 相关迹象。",
    "If external access is slow, check Stash node, rule routing, DNS policy, and proxy exit.": "如果外网访问慢，优先检查 Stash 节点、规则分流、DNS 策略和代理出口。",
    "Compare direct gateway DNS with system DNS before blaming the router.": "在判断路由器故障前，先对比网关直连 DNS 与系统 DNS。",
    "Retest once with the overlay disabled outside LANPilot, then retest with Stash enabled.": "先在 LANPilot 外关闭 Overlay 复测，再启用 Stash 后复测。",
    "Tailscale Exit Node may be affecting external connectivity.": "Tailscale Exit Node 可能正在影响外部连通性。",
    "External traffic may be routed through a remote exit path instead of the local ISP path.": "外部流量可能通过远端出口路径，而不是本地运营商路径。",
    "Default route uses an overlay interface while Tailscale is running as an exit path.": "默认路由使用 Overlay 接口，同时 Tailscale 正作为出口路径运行。",
    "DNS uses Tailscale DNS and HTTPS timing is slow or failed.": "DNS 使用 Tailscale DNS，且 HTTPS 时序较慢或失败。",
    "Disable Exit Node outside LANPilot and retest.": "在 LANPilot 外关闭 Exit Node 后复测。",
    "Disable Tailscale DNS if it is not needed for this workflow.": "如果当前流程不需要 Tailscale DNS，请关闭后复测。",
    "Compare external HTTPS timing before and after the Exit Node change.": "对比调整 Exit Node 前后的外部 HTTPS 时序。",
    "Local gateway or physical link instability detected.": "检测到本地网关或物理链路不稳定。",
    "Local network instability can affect DNS, browsing, and app connectivity before traffic reaches the internet.": "在流量到达互联网前，本地网络不稳定就可能影响 DNS、浏览器和应用连接。",
    "Check Ethernet cable, switch port, router load, and USB Ethernet adapter.": "检查网线、交换机端口、路由器负载和 USB 网卡。",
    "Retest with the current physical path isolated from overlay and proxy changes.": "在保持 Overlay 和代理状态不变的前提下，单独复测当前物理路径。",
    "Run gateway ping and gateway DNS timing again after the physical path is checked.": "检查物理路径后，再次复测网关 ping 和网关 DNS 时序。",
  };
  const zhTW: Record<string, string> = Object.fromEntries(Object.entries(zhCN).map(([key, text]) => [
    key,
    [
      ["网络", "網路"], ["当前", "目前"], ["路径", "路徑"], ["网关", "閘道"],
      ["检测", "檢測"], ["默认", "預設"], ["关闭", "關閉"], ["后", "後"],
      ["复测", "複測"], ["运营商", "營運商"],
    ].reduce((current, [from, to]) => current.split(from).join(to), text),
  ]));
  if (locale === "zh-CN") return zhCN[value] ?? value;
  if (locale === "zh-TW") return zhTW[value] ?? value;
  return value;
}

function formatRunMetadata(resultMode: NetworkDoctorResultMode, evidenceSource: string, lastRunAt: string, lastRunMode: DoctorMode | null, t: (key: string) => string): string {
  const modeLabel = resultMode === "demo" ? t("reliability.resultMode.demo") : resultMode === "real" ? t("reliability.resultMode.real") : t(`reliability.resultMode.${resultMode}`);
  const runMode = lastRunMode ? (lastRunMode === "quick" ? t("reliability.quickCheck") : t("reliability.deepDiagnosis")) : t("status.unknown");
  return `${t("reliability.resultMode")}: ${modeLabel} · ${t("reliability.evidenceSource")}: ${evidenceSource} · ${t("reliability.lastRun")}: ${lastRunAt || t("status.unknown")} · ${runMode}`;
}

function formatPrimaryFaultSummary(domain: DiagnosticDomain, status: ReliabilityStatus, locale: Locale, t: (key: string) => string): string {
  if (domain === "unknown" && status === "healthy") return t("reliability.noClearFaultDetected");
  if (domain === "unknown" && status === "warning") return t("reliability.needsDeepDiagnosis");
  if (domain === "unknown") return t("reliability.undetermined");
  return formatDomainLabel(domain, locale);
}

function formatOsiLayerSummary(mapping: { layers: string[] }[], t: (key: string) => string): string {
  const layers = mapping.flatMap((item) => item.layers).filter(Boolean);
  return layers.length ? Array.from(new Set(layers)).join(" / ") : t("reliability.undetermined");
}

function formatDomainLabel(domain: DiagnosticDomain, locale: Locale): string {
  const labels: Record<Locale, Partial<Record<DiagnosticDomain, string>>> = {
    en: {
      local_host: "Local host", physical_interface: "Physical interface", wifi_radio: "Wi-Fi radio", ethernet_link: "Ethernet link", dhcp: "DHCP", gateway: "Gateway", local_dns: "Local DNS", system_dns: "System DNS", route: "Route", overlay_proxy: "Overlay / Proxy", tailscale: "Tailscale", transport_tcp: "TCP", transport_udp: "UDP / QUIC", tls: "TLS", external_path: "External path", application_endpoint: "Application endpoint", router_health: "Router health", unknown: "Undetermined",
    },
    "zh-CN": {
      local_host: "本机", physical_interface: "物理接口", wifi_radio: "Wi-Fi 射频", ethernet_link: "以太网链路", dhcp: "DHCP", gateway: "网关", local_dns: "本地 DNS", system_dns: "系统 DNS", route: "路由", overlay_proxy: "Overlay / 代理", tailscale: "Tailscale", transport_tcp: "TCP", transport_udp: "UDP / QUIC", tls: "TLS", external_path: "外部路径", application_endpoint: "应用端点", router_health: "路由器健康", unknown: "未确定",
    },
    "zh-TW": {
      local_host: "本機", physical_interface: "實體介面", wifi_radio: "Wi-Fi 射頻", ethernet_link: "乙太網路鏈路", dhcp: "DHCP", gateway: "閘道", local_dns: "本機 DNS", system_dns: "系統 DNS", route: "路由", overlay_proxy: "Overlay / 代理", tailscale: "Tailscale", transport_tcp: "TCP", transport_udp: "UDP / QUIC", tls: "TLS", external_path: "外部路徑", application_endpoint: "應用端點", router_health: "路由器健康", unknown: "未確定",
    },
    ja: {
      local_host: "ローカルホスト", physical_interface: "物理インターフェース", wifi_radio: "Wi-Fi 無線", ethernet_link: "Ethernet リンク", dhcp: "DHCP", gateway: "ゲートウェイ", local_dns: "ローカル DNS", system_dns: "システム DNS", route: "ルート", overlay_proxy: "Overlay / プロキシ", tailscale: "Tailscale", transport_tcp: "TCP", transport_udp: "UDP / QUIC", tls: "TLS", external_path: "外部経路", application_endpoint: "アプリ端点", router_health: "ルーター状態", unknown: "未確定",
    },
    ko: {
      local_host: "로컬 호스트", physical_interface: "물리 인터페이스", wifi_radio: "Wi-Fi 무선", ethernet_link: "이더넷 링크", dhcp: "DHCP", gateway: "게이트웨이", local_dns: "로컬 DNS", system_dns: "시스템 DNS", route: "경로", overlay_proxy: "Overlay / 프록시", tailscale: "Tailscale", transport_tcp: "TCP", transport_udp: "UDP / QUIC", tls: "TLS", external_path: "외부 경로", application_endpoint: "애플리케이션 엔드포인트", router_health: "라우터 상태", unknown: "미확정",
    },
    de: {
      local_host: "Lokaler Host", physical_interface: "Physische Schnittstelle", wifi_radio: "WLAN-Funk", ethernet_link: "Ethernet-Link", dhcp: "DHCP", gateway: "Gateway", local_dns: "Lokales DNS", system_dns: "System-DNS", route: "Route", overlay_proxy: "Overlay / Proxy", tailscale: "Tailscale", transport_tcp: "TCP", transport_udp: "UDP / QUIC", tls: "TLS", external_path: "Externer Pfad", application_endpoint: "App-Endpunkt", router_health: "Routerzustand", unknown: "Nicht bestimmt",
    },
    fr: {
      local_host: "Hôte local", physical_interface: "Interface physique", wifi_radio: "Radio Wi-Fi", ethernet_link: "Lien Ethernet", dhcp: "DHCP", gateway: "Passerelle", local_dns: "DNS local", system_dns: "DNS système", route: "Route", overlay_proxy: "Overlay / proxy", tailscale: "Tailscale", transport_tcp: "TCP", transport_udp: "UDP / QUIC", tls: "TLS", external_path: "Chemin externe", application_endpoint: "Point applicatif", router_health: "Santé routeur", unknown: "Indéterminé",
    },
    es: {
      local_host: "Host local", physical_interface: "Interfaz física", wifi_radio: "Radio Wi-Fi", ethernet_link: "Enlace Ethernet", dhcp: "DHCP", gateway: "Puerta de enlace", local_dns: "DNS local", system_dns: "DNS del sistema", route: "Ruta", overlay_proxy: "Overlay / proxy", tailscale: "Tailscale", transport_tcp: "TCP", transport_udp: "UDP / QUIC", tls: "TLS", external_path: "Ruta externa", application_endpoint: "Endpoint de aplicación", router_health: "Salud del router", unknown: "Sin determinar",
    },
    "pt-BR": {
      local_host: "Host local", physical_interface: "Interface física", wifi_radio: "Rádio Wi-Fi", ethernet_link: "Link Ethernet", dhcp: "DHCP", gateway: "Gateway", local_dns: "DNS local", system_dns: "DNS do sistema", route: "Rota", overlay_proxy: "Overlay / proxy", tailscale: "Tailscale", transport_tcp: "TCP", transport_udp: "UDP / QUIC", tls: "TLS", external_path: "Caminho externo", application_endpoint: "Endpoint da aplicação", router_health: "Saúde do roteador", unknown: "Indeterminado",
    },
    it: {
      local_host: "Host locale", physical_interface: "Interfaccia fisica", wifi_radio: "Radio Wi-Fi", ethernet_link: "Link Ethernet", dhcp: "DHCP", gateway: "Gateway", local_dns: "DNS locale", system_dns: "DNS di sistema", route: "Route", overlay_proxy: "Overlay / proxy", tailscale: "Tailscale", transport_tcp: "TCP", transport_udp: "UDP / QUIC", tls: "TLS", external_path: "Percorso esterno", application_endpoint: "Endpoint applicativo", router_health: "Salute router", unknown: "Non determinato",
    },
    nl: {
      local_host: "Lokale host", physical_interface: "Fysieke interface", wifi_radio: "Wi-Fi-radio", ethernet_link: "Ethernetlink", dhcp: "DHCP", gateway: "Gateway", local_dns: "Lokaal DNS", system_dns: "Systeem-DNS", route: "Route", overlay_proxy: "Overlay / proxy", tailscale: "Tailscale", transport_tcp: "TCP", transport_udp: "UDP / QUIC", tls: "TLS", external_path: "Extern pad", application_endpoint: "Applicatie-eindpunt", router_health: "Routergezondheid", unknown: "Onbepaald",
    },
  };
  return labels[locale][domain] ?? labels.en[domain] ?? domain;
}

function formatScoreState(state: DoctorScoreState, locale: Locale): string {
  const values: Record<Locale, Record<DoctorScoreState, string>> = {
    en: { Excellent: "Excellent", Healthy: "Healthy", Acceptable: "Acceptable", Warning: "Warning", Critical: "Critical" },
    "zh-CN": { Excellent: "优秀", Healthy: "正常", Acceptable: "可接受", Warning: "警告", Critical: "严重" },
    "zh-TW": { Excellent: "優秀", Healthy: "正常", Acceptable: "可接受", Warning: "警告", Critical: "嚴重" },
    ja: { Excellent: "優秀", Healthy: "正常", Acceptable: "許容範囲", Warning: "警告", Critical: "重大" },
    ko: { Excellent: "매우 좋음", Healthy: "정상", Acceptable: "허용 가능", Warning: "경고", Critical: "심각" },
    de: { Excellent: "Exzellent", Healthy: "Gesund", Acceptable: "Akzeptabel", Warning: "Warnung", Critical: "Kritisch" },
    fr: { Excellent: "Excellent", Healthy: "Sain", Acceptable: "Acceptable", Warning: "Avertissement", Critical: "Critique" },
    es: { Excellent: "Excelente", Healthy: "Saludable", Acceptable: "Aceptable", Warning: "Advertencia", Critical: "Crítico" },
    "pt-BR": { Excellent: "Excelente", Healthy: "Saudável", Acceptable: "Aceitável", Warning: "Aviso", Critical: "Crítico" },
    it: { Excellent: "Eccellente", Healthy: "Sano", Acceptable: "Accettabile", Warning: "Avviso", Critical: "Critico" },
    nl: { Excellent: "Uitstekend", Healthy: "Gezond", Acceptable: "Acceptabel", Warning: "Waarschuwing", Critical: "Kritiek" },
  };
  return values[locale][state];
}

function formatConfidence(value: RootCauseCandidate["confidence"], locale: Locale): string {
  const values: Record<Locale, Record<RootCauseCandidate["confidence"], string>> = {
    en: { High: "High", Medium: "Medium", Low: "Low" },
    "zh-CN": { High: "高", Medium: "中", Low: "低" },
    "zh-TW": { High: "高", Medium: "中", Low: "低" },
    ja: { High: "高", Medium: "中", Low: "低" },
    ko: { High: "높음", Medium: "중간", Low: "낮음" },
    de: { High: "Hoch", Medium: "Mittel", Low: "Niedrig" },
    fr: { High: "Élevée", Medium: "Moyenne", Low: "Faible" },
    es: { High: "Alta", Medium: "Media", Low: "Baja" },
    "pt-BR": { High: "Alta", Medium: "Média", Low: "Baixa" },
    it: { High: "Alta", Medium: "Media", Low: "Bassa" },
    nl: { High: "Hoog", Medium: "Middel", Low: "Laag" },
  };
  return values[locale][value];
}

function formatScorecardName(name: DoctorScorecard["name"], locale: Locale): string {
  const zhCN: Record<DoctorScorecard["name"], string> = {
    "Physical LAN": "物理网络",
    "Wi-Fi": "Wi-Fi",
    "Gateway": "网关",
    "DNS": "DNS",
    "Overlay / Proxy": "Overlay / 代理",
    "External Path": "外部路径",
    "Application Access": "应用访问",
  };
  const zhTW: Record<DoctorScorecard["name"], string> = { ...zhCN, "Physical LAN": "實體網路", "Gateway": "閘道", "External Path": "外部路徑", "Application Access": "應用存取" };
  const ja: Record<DoctorScorecard["name"], string> = { "Physical LAN": "物理 LAN", "Wi-Fi": "Wi-Fi", Gateway: "ゲートウェイ", DNS: "DNS", "Overlay / Proxy": "Overlay / プロキシ", "External Path": "外部経路", "Application Access": "アプリ接続" };
  const ko: Record<DoctorScorecard["name"], string> = { "Physical LAN": "물리 LAN", "Wi-Fi": "Wi-Fi", Gateway: "게이트웨이", DNS: "DNS", "Overlay / Proxy": "Overlay / 프록시", "External Path": "외부 경로", "Application Access": "앱 접근" };
  if (locale === "zh-CN") return zhCN[name];
  if (locale === "zh-TW") return zhTW[name];
  if (locale === "ja") return ja[name];
  if (locale === "ko") return ko[name];
  return name;
}

function localizeDoctorTitle(value: string, locale: Locale): string {
  const zhCN: Record<string, string> = {
    "No clear fault detected": "未发现明确故障",
    "Overlay or proxy path is the likely inspection point": "Overlay 或代理路径是优先检查点",
    "Tailscale exit path or DNS policy may be affecting access": "Tailscale 出口路径或 DNS 策略可能影响访问",
    "Local gateway or first-hop path instability": "本地网关或第一跳路径不稳定",
    "DHCP or local address assignment is incomplete": "DHCP 或本地地址分配不完整",
    "Wi-Fi radio quality or channel conditions may be degrading the path": "Wi-Fi 射频质量或信道条件可能导致路径降级",
    "TCP connection state explains the application failure": "TCP 连接状态可解释应用失败",
    "TLS handshake or certificate validation is failing": "TLS 握手或证书验证失败",
    "Application endpoint is slow or returning errors": "应用端点较慢或返回错误",
    "Router resource pressure may affect forwarding": "路由器资源压力可能影响转发",
  };
  if (locale === "zh-CN") return zhCN[value] ?? value;
  if (locale === "zh-TW") return [
    ["路径", "路徑"], ["网关", "閘道"], ["证据", "證據"], ["应用", "應用"],
  ].reduce((current, [from, to]) => current.split(from).join(to), zhCN[value] ?? value);
  return value;
}

function ExportPage() {
  const { t } = useI18n();
  const [zipPath, setZipPath] = useState("");
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const [exporting, setExporting] = useState(false);

  const runAction = async (action: () => Promise<void>, successMessage: string) => {
    setError("");
    setMessage("");
    try {
      await action();
      setMessage(successMessage);
    } catch (value) {
      setError(errorMessage(value));
    }
  };

  const exportZip = async () => {
    setError("");
    setMessage("");
    setExporting(true);
    try {
      const result = await invoke<ExportResult>("export_latest_lab_zip");
      setZipPath(result.zipPath);
      setMessage(t("export.created"));
    } catch (value) {
      setError(errorMessage(value));
    } finally {
      setExporting(false);
    }
  };

  return (
    <section className="content-stack">
      <PageHeading eyebrow={t("export.eyebrow")} title={t("export")} description={t("export.description")} />
      <div className="card compact export-card">
        <div><h2>{t("export.latestWorkspace")}</h2><p className="path">~/lanpilot-audit-latest</p></div>
        <div className="actions">
          <button className="secondary" type="button" onClick={() => runAction(() => invoke("open_latest_lab_folder"), t("export.openedLab"))}>{t("export.openLabFolder")}</button>
          <button className="secondary" type="button" onClick={() => runAction(() => invoke("open_html_report"), t("export.openedHtml"))}>{t("export.openHtml")}</button>
          <button className="secondary" type="button" onClick={() => runAction(() => invoke("open_excel_report"), t("export.openedExcel"))}>{t("export.openExcel")}</button>
        </div>
      </div>
      <div className="card compact export-card">
        <div><h2>{t("export.zipTitle")}</h2><p className="path">{zipPath || "~/Desktop/LANPilot-Audit-Exports/LANPilot-Audit-YYYYMMDD-HHMMSS.zip"}</p></div>
        <div className="actions">
          <button className="primary" type="button" disabled={exporting} onClick={exportZip}>{exporting ? t("export.exporting") : t("exportZip")}</button>
          <button className="secondary" type="button" onClick={() => runAction(() => invoke("open_export_folder"), t("export.openedFolder"))}>{t("openExportFolder")}</button>
        </div>
      </div>
      {message && <p className="message success-message">{message}</p>}
      {error && <RawDetail detail={error} />}
    </section>
  );
}

function SettingsPage() {
  const { t } = useI18n();
  const [status, setStatus] = useState<EngineStatus | null>(null);
  useEffect(() => {
    invoke<EngineStatus>("get_engine_status").then(setStatus).catch(() => setStatus(null));
  }, []);
  return (
    <section className="content-stack">
      <PageHeading eyebrow={t("settings.eyebrow")} title={t("settings.title")} description={t("settings.description")} />
      <div className="card compact review-grid">
        <div><span>{t("settings.version")}</span><strong>{packageJson.version}</strong></div>
        <div><span>{t("settings.engineVersion")}</span><strong>{status?.engineVersion ?? status?.bundledEngineVersion ?? "—"}</strong></div>
        <div><span>{t("settings.dataStorageLocation")}</span><strong>~/lanpilot-audit-latest</strong></div>
        <div><span>{t("settings.exportFolder")}</span><strong>~/Desktop/LANPilot-Audit-Exports</strong></div>
        <div><span>{t("settings.privacyLocalFirst")}</span><strong>{t("settings.noCloudUpload")}</strong></div>
        <div><span>{t("settings.supportedLanguages")}</span><strong>11</strong></div>
      </div>
      <Guardrail />
      <div className="card compact"><h2>{t("language")}</h2><LanguageSelector /></div>
      <div className="actions">
        <button className="secondary" type="button" onClick={() => invoke("open_engine_folder")}>{t("settings.openEngineFolder")}</button>
        <button className="secondary" type="button" onClick={() => invoke("open_export_folder")}>{t("settings.openExportFolder")}</button>
      </div>
    </section>
  );
}

function LanguageSelector() {
  const { locale, setLocale, t } = useI18n();
  const visibleLocales = ["en", "zh-CN"] as const;
  const names: Record<(typeof visibleLocales)[number], string> = {
    en: "English",
    "zh-CN": "简体中文",
  };
  const selectedLocale = visibleLocales.includes(locale as (typeof visibleLocales)[number])
    ? locale
    : "en";

  return (
    <label className="language-selector">
      <span>{t("language")}</span>
      <select
        aria-label={t("language")}
        value={selectedLocale}
        onChange={(event) => setLocale(event.target.value as Locale)}
      >
        {visibleLocales.map((item) => (
          <option value={item} key={item}>{names[item]}</option>
        ))}
        {supportedLocales
          .filter((item) => !visibleLocales.includes(item as (typeof visibleLocales)[number]))
          .map((item) => (
            <option value={item} key={item} hidden>{item}</option>
          ))}
      </select>
    </label>
  );
}

function PageHeading({ eyebrow, title, description }: { eyebrow: string; title: string; description: string }) {
  return <div><div className="eyebrow">{eyebrow}</div><h1>{title}</h1><p className="lead">{description}</p></div>;
}

function RawDetail({ detail, warning = false }: { detail: string; warning?: boolean }) {
  const { t } = useI18n();
  return <details className={`message ${warning ? "" : "error"}`}><summary>{t(warning ? "status.warning" : "common.error")}</summary><pre>{t("common.rawDetail")}: {"\n"}{detail}</pre></details>;
}

function Guardrail() {
  const { t } = useI18n();
  return <div className="guardrail"><strong>{t("safetyBoundary")}</strong><span>{t("guardrail.description")}</span></div>;
}

export default App;
