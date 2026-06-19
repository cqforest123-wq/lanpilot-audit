import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { supportedLocales, useI18n } from "./i18n";
import type { Locale } from "./i18n/types";
import { deduplicateFindings, localizeAssetLabel, localizeFinding, localizeGatewayStatus, reportCopy, type LocalizedFinding } from "./report-localization";
import { buildRemediationPack, type RemediationPack, type RemediationStatus } from "./remediation-assistant";
import type { NetworkReliabilityDiagnosis, NetworkReliabilityEvidence, ReliabilityStatus } from "./network-reliability";
import packageJson from "../package.json";
import "./App.css";

type Page = "landing" | "authorization" | "engine" | "interface" | "run" | "assets" | "exposure" | "networkReliability" | "report" | "compare" | "remediation" | "export" | "settings";
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
}

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
  const [page, setPage] = useState<Page>("landing");
  const [auditRunning, setAuditRunning] = useState(false);
  const [authorized, setAuthorized] = useState(false);
  const [details, setDetails] = useState<AuthorizationDetails | null>(null);
  const [auditInterface, setAuditInterface] = useState("");
  const [latestReport, setLatestReport] = useState<LatestReport | null>(null);

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
      <header className="topbar">
        <button className="brand" type="button" disabled={auditRunning} onClick={() => navigate("landing")}>
          <span className="brand-mark">LP</span><span>LANPilot Audit</span>
        </button>
        <nav>
          <button type="button" disabled={auditRunning} onClick={startAuthorization}>{t("navRun")}</button>
          <button type="button" disabled={auditRunning} onClick={() => navigate("assets")}>{t("navAssets")}</button>
          <button type="button" disabled={auditRunning} onClick={() => navigate("exposure")}>{t("navExposure")}</button>
          <button type="button" disabled={auditRunning} onClick={() => navigate("networkReliability")}>{t("navNetworkReliability")}</button>
          <button type="button" disabled={auditRunning} onClick={() => navigate("report")}>{t("navReport")}</button>
          <button type="button" disabled={auditRunning} onClick={() => navigate("compare")}>{t("navCompare")}</button>
          <button type="button" disabled={auditRunning} onClick={() => navigate("remediation")}>{t("navRemediation")}</button>
          <button type="button" disabled={auditRunning} onClick={() => navigate("export")}>{t("navExport")}</button>
          <button type="button" disabled={auditRunning} onClick={() => navigate("settings")}>{t("navSettings")}</button>
          <LanguageSelector />
        </nav>
      </header>

      <section className="page" aria-label={t("appName")}>
        {page === "landing" && <LandingPage onStart={startAuthorization} onReport={() => navigate("report")} />}
        {page === "authorization" && (
          <AuthorizationPage
            onCancel={() => navigate("landing")}
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
        {page === "networkReliability" && <NetworkReliabilityPage onRunningChange={setAuditRunning} />}
        {page === "compare" && <GovernanceDataPage titleKey="toolbox.compare" descriptionKey="toolbox.compareDescription" fields={["snapshotDiff", "governanceSummary"]} />}
        {page === "remediation" && <RemediationPage onRetest={startAuthorization} />}
        {page === "export" && <ExportPage />}
        {page === "settings" && <SettingsPage />}
      </section>
    </main>
  );
}

function LandingPage({ onStart, onReport }: { onStart: () => void; onReport: () => void }) {
  const { t } = useI18n();
  return (
    <section className="hero card">
      <div className="eyebrow">{t("landingEyebrow")}</div>
      <h1>{t("landingTitle")}</h1>
      <p className="lead">{t("landingDescription")}</p>
      <div className="actions">
        <button className="primary" type="button" onClick={onStart}>{t("startAudit")}</button>
        <button className="secondary" type="button" onClick={onReport}>{t("latestReport")}</button>
      </div>
      <Guardrail />
    </section>
  );
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
  const [checks, setChecks] = useState([false, false, false, false]);
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
          t("authorization.confirmFixedInterface"),
          t("authorization.confirmPointInTimeNoConfigChange"),
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
        if (!selected && items[0]) onSelect(items[0].name);
      })
      .catch((value) => setError(errorMessage(value)));
  }, [selected, onSelect]);
  return (
    <section className="content-stack">
      <PageHeading eyebrow={t("interface.eyebrow")} title={t("interface.title")} description={t("interface.description")} />
      <div className="card compact review-grid">
        <div><span>{t("interface.project")}</span><strong>{details.projectName}</strong></div>
        <div><span>{t("interface.siteOrganization")}</span><strong>{details.site || t("common.notProvided")}</strong></div>
        <label><span>{t("interface.selectedInterface")}</span><select value={selected} onChange={(event) => onSelect(event.target.value)}>{interfaces.map((item) => <option value={item.name} key={item.name}>{item.name} · {item.ipv4}</option>)}</select></label>
        <div><span>{t("interface.executionMode")}</span><strong>{t("run.stopOnFailure")}</strong></div>
      </div>
      {error && <RawDetail detail={error} />}
      <Guardrail />
      <div className="actions">
        <button className="primary" type="button" disabled={!selected} onClick={onContinue}>{t("interface.continueToRun")}</button>
        <button className="secondary" type="button" onClick={onBack}>{t("authorization.reviewAuthorization")}</button>
      </div>
    </section>
  );
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

function NetworkReliabilityPage({ onRunningChange }: { onRunningChange: (running: boolean) => void }) {
  const { t } = useI18n();
  const [projectName, setProjectName] = useState("");
  const [checks, setChecks] = useState([false, false, false, false]);
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState<NetworkReliabilityRun | null>(null);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const allChecked = checks.every(Boolean);
  const canRun = allChecked && projectName.trim().length > 0 && !running;

  const toggleCheck = (index: number, checked: boolean) => {
    setChecks((current) => current.map((value, itemIndex) => itemIndex === index ? checked : value));
  };

  const runCheck = async () => {
    setRunning(true);
    onRunningChange(true);
    setError("");
    setMessage("");
    try {
      await invoke("authorize_audit", { projectName: projectName.trim() });
      const next = await invoke<NetworkReliabilityRun>("run_network_reliability_check");
      setResult(next);
      setMessage(`${t("reliability.savedTo")}: ${next.outputDirectory}`);
      setChecks([false, false, false, false]);
    } catch (value) {
      setError(errorMessage(value));
    } finally {
      setRunning(false);
      onRunningChange(false);
    }
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
      <p className="limitation">{t("pointInTime")}</p>
      <div className="form-grid">
        <label>{t("reliability.projectName")} <strong>*</strong><input value={projectName} onChange={(event) => setProjectName(event.target.value)} /></label>
      </div>
      <div className="confirmation-list">
        {[
          t("reliability.confirmScope"),
          t("reliability.confirmReadOnly"),
          t("reliability.confirmNoChanges"),
          t("reliability.confirmLocalFiles"),
        ].map((label, index) => (
          <label className="confirmation card compact" key={label}>
            <input type="checkbox" checked={checks[index]} onChange={(event) => toggleCheck(index, event.target.checked)} />
            <span><strong>{label}</strong></span>
          </label>
        ))}
      </div>
      <div className="actions">
        <button className="primary" type="button" disabled={!canRun} onClick={runCheck}>{running ? t("reliability.running") : t("reliability.run")}</button>
      </div>
      {message && <p className="message success-message">{message}</p>}
      {error && <RawDetail detail={error} />}
      {!result && !error && <p className="message">{t("reliability.noResult")}</p>}
      {result && <NetworkReliabilityResult result={result} onOpenArtifact={openArtifact} />}
    </section>
  );
}

function NetworkReliabilityResult({ result, onOpenArtifact }: { result: NetworkReliabilityRun; onOpenArtifact: (kind: string) => Promise<void> }) {
  const { t } = useI18n();
  const summary = result.summary;
  const evidence = result.evidence;
  const pathSegments = summary.currentPath.split(/\s+->\s+/).filter(Boolean);
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
      <div className="summary-grid reliability-summary">
        <ReliabilitySummaryCard label={t("reliability.overallStatus")} status={summary.overallStatus} />
        <ReliabilitySummaryCard label={t("reliability.physicalLan")} status={summary.physicalLanStatus} />
        <ReliabilitySummaryCard label={t("reliability.dns")} status={summary.dnsStatus} />
        <ReliabilitySummaryCard label={t("reliability.externalInternet")} status={summary.externalPathStatus} />
      </div>
      <section className="card compact reliability-path">
        <h2>{t("reliability.networkPathView")}</h2>
        <div className="path-segments">
          {pathSegments.map((segment, index) => (
            <span className="path-segment" key={`${segment}-${index}`}>{segment}</span>
          ))}
        </div>
      </section>
      <div className="reliability-grid">
        <section className="card compact">
          <h2>{t("reliability.summary")}</h2>
          <dl className="report-metadata single-column">
            <div><dt>{t("reliability.profile")}</dt><dd>{evidence.profile || t("status.unknown")}</dd></div>
            <div><dt>{t("reliability.faultPoint")}</dt><dd>{summary.faultPoint}</dd></div>
            <div><dt>{t("reliability.impact")}</dt><dd>{summary.impact}</dd></div>
            <div><dt>{t("reliability.currentPath")}</dt><dd>{summary.currentPath}</dd></div>
          </dl>
        </section>
        <section className="card compact">
          <h2>{t("reliability.evidencePanel")}</h2>
          <dl className="report-metadata single-column">
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
      <div className="reliability-grid">
        <NetworkListCard title={t("reliability.keyEvidence")} items={summary.evidence} />
        <NetworkListCard title={t("reliability.advicePanel")} items={summary.remediationAdvice} />
      </div>
      <div className="reliability-grid">
        <NetworkListCard title={t("reliability.retest")} items={summary.retestPlan} ordered />
        <NetworkListCard title={t("reliability.externalTargets")} items={evidence.external.targets.map((target) => `${target.url}: ${formatNullableMs(target.totalMs, t("status.unknown"))}`)} />
      </div>
      <section className="card compact export-card">
        <div>
          <h2>{t("reliability.supportBundle")}</h2>
          <p className="path">{result.supportBundlePath}</p>
        </div>
        <div className="actions">
          <button className="secondary" type="button" onClick={() => onOpenArtifact("report")}>{t("reliability.exportMarkdown")}</button>
          <button className="secondary" type="button" onClick={() => onOpenArtifact("summary")}>{t("reliability.exportJson")}</button>
          <button className="secondary" type="button" onClick={() => onOpenArtifact("bundle")}>{t("reliability.exportZip")}</button>
          <button className="secondary" type="button" onClick={() => onOpenArtifact("folder")}>{t("reliability.openOutput")}</button>
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

function ReliabilitySummaryCard({ label, status }: { label: string; status: ReliabilityStatus }) {
  const { t } = useI18n();
  return <div className={`summary-card card reliability-status ${status}`}><span>{label}</span><strong>{t(`reliability.status.${status}`)}</strong></div>;
}

function NetworkListCard({ title, items, ordered = false }: { title: string; items: string[]; ordered?: boolean }) {
  const { t } = useI18n();
  const Tag = ordered ? "ol" : "ul";
  return <section className="card compact reliability-list"><h2>{title}</h2>{items.length === 0 ? <p className="muted">{t("status.unknown")}</p> : <Tag>{items.map((item) => <li key={item}>{item}</li>)}</Tag>}</section>;
}

function formatNullableMs(value: number | null | undefined, unknown: string): string {
  return typeof value === "number" ? `${value} ms` : unknown;
}

function formatNullablePercent(value: number | null | undefined, unknown: string): string {
  return typeof value === "number" ? `${value}%` : unknown;
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
  const names: Record<Locale, string> = { en:"English","zh-CN":"简体中文","zh-TW":"繁體中文",ja:"日本語",ko:"한국어",de:"Deutsch",fr:"Français",es:"Español","pt-BR":"Português (Brasil)",it:"Italiano",nl:"Nederlands" };
  return <label className="language-selector"><span>{t("language")}</span><select aria-label={t("language")} value={locale} onChange={(event) => setLocale(event.target.value as Locale)}>{supportedLocales.map((item) => <option value={item} key={item}>{names[item]}</option>)}</select></label>;
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
