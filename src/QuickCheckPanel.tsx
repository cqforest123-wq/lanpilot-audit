import { useCallback, useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { useI18n } from "./i18n";

/* Types mirroring the Rust payloads -------------------------------------- */

type Health = "good" | "fair" | "poor" | "unreachable" | "untrustworthy";
type PathVerdict = "direct" | "locallyIntercepted" | "noExternalPath" | "unknown";
type InterfaceKind = "physical" | "tunnel" | "bridge" | "loopback" | "other";
type PortState = "open" | "refused" | "filtered";
type DnsVerdict = "consistent" | "syntheticAnswer" | "divergent" | "inconclusive";
type Tool = "ping" | "port" | "route" | "dns" | "watch" | "deep";
type SignalQuality = "excellent" | "good" | "fair" | "weak" | "unusable";
type EgressVerdict = "confirmed" | "split" | "intercepted" | "unknown";

interface ProbeStats {
  sent: number; received: number; lossPct: number;
  minMs: number | null; avgMs: number | null; maxMs: number | null; jitterMs: number | null;
}
interface Interference { verdict: PathVerdict; reasons: string[]; gatewayRttMs: number | null }
interface QuickCheckReport {
  target: string; resolvedAddress: string | null; dnsMs: number | null;
  stats: ProbeStats; samples: number[];
  gateway: string | null; gatewayStats: ProbeStats | null;
  interference: Interference; health: Health; findings: string[];
}
interface NetInterface {
  name: string; kind: InterfaceKind; ipv4: string; netmask: string;
  prefix: number; isUp: boolean; carriesFakeIp: boolean;
}
interface WifiStatus {
  interface: string | null; rssiDbm: number | null; noiseDbm: number | null;
  snrDb: number | null; transmitRateMbps: number | null; quality: SignalQuality | null;
}
interface Egress {
  primary: string | null; secondary: string | null; verdict: EgressVerdict; reasons: string[];
}
interface LocalNetwork {
  interfaces: NetInterface[]; dnsServers: string[]; gateway: string | null; tunnels: string[];
  sandboxed: boolean; wifi: WifiStatus | null;
}
interface PortResult { port: number; state: PortState; elapsedMs: number; service: string | null }
interface DnsAnswer { server: string; addresses: string[]; elapsedMs: number | null; error: string | null }
interface DnsDiagnosis { name: string; system: DnsAnswer[]; public: DnsAnswer; verdict: DnsVerdict; reasons: string[] }
interface Hop {
  ttl: number; address: string | null; hostname: string | null;
  rttMs: number | null; reachedTarget: boolean;
}
interface Trace {
  target: string; hops: Hop[];
  outcome: "completed" | "hopLimitReached" | "abandoned";
  implausiblyShort: boolean;
}
interface Outage { startedAtMs: number; endedAtMs: number | null; durationMs: number | null; missedProbes: number }
interface WatchSummary {
  totalProbes: number; replies: number; lossPct: number;
  outages: Outage[]; longestOutageMs: number | null; worstRttMs: number | null;
}

/* Shared pieces ------------------------------------------------------------ */

/** Round-trip chart. Losses stay visible as gaps, never smoothed over. */
function Chart({ samples, height = 160 }: { samples: (number | null)[]; height?: number }) {
  const replies = samples.filter((value): value is number => value !== null);
  if (replies.length === 0) return null;

  const width = 800;
  const pad = 10;
  const peak = Math.max(...replies, 1);
  const step = samples.length > 1 ? (width - pad * 2) / (samples.length - 1) : 0;
  const y = (value: number) => height - pad - (value / peak) * (height - pad * 2);

  const segments: string[] = [];
  let run: string[] = [];
  samples.forEach((value, index) => {
    if (value === null) { if (run.length) segments.push(run.join(" ")); run = []; return; }
    run.push(`${pad + index * step},${y(value)}`);
  });
  if (run.length) segments.push(run.join(" "));

  const average = replies.reduce((total, value) => total + value, 0) / replies.length;

  return (
    <div className="qc-chart" style={{ ["--qc-chart-height" as string]: `${height}px` }}>
      <svg viewBox={`0 0 ${width} ${height}`} preserveAspectRatio="none" className="qc-chart-svg">
        <line x1={pad} y1={y(average)} x2={width - pad} y2={y(average)} className="qc-chart-avg" />
        {segments.map((points, index) => (
          <polyline key={index} points={points} fill="none" className="qc-chart-line" />
        ))}
        {samples.map((value, index) =>
          value === null ? (
            <line key={index} x1={pad + index * step} y1={pad} x2={pad + index * step} y2={height - pad} className="qc-chart-loss" />
          ) : (
            <circle key={index} cx={pad + index * step} cy={y(value)} r={2.5} className="qc-chart-dot" />
          ),
        )}
      </svg>
      <span className="qc-chart-peak">{peak.toFixed(1)} ms</span>
      <span className="qc-chart-base">0</span>
    </div>
  );
}

function Metric({ label, value, hint, tone }: { label: string; value: string; hint?: string; tone?: string }) {
  // An address broken across two lines is unreadable; step the size down
  // instead of letting it wrap mid-number.
  const long = value.length > 11;
  return (
    <div className={`qc-metric${tone ? ` qc-metric-${tone}` : ""}`}>
      <span className="qc-metric-label">{label}</span>
      <strong className={`qc-metric-value${long ? " qc-metric-value-long" : ""}`}>{value}</strong>
      {hint ? <span className="qc-metric-hint">{hint}</span> : null}
    </div>
  );
}

function TargetForm({
  value, onChange, onSubmit, running, placeholder, label, action, busyAction, children,
}: {
  value: string; onChange: (next: string) => void; onSubmit: () => void; running: boolean;
  placeholder: string; label: string; action: string; busyAction: string; children?: React.ReactNode;
}) {
  return (
    <form className="qc-form" onSubmit={(event) => { event.preventDefault(); onSubmit(); }}>
      <label className="qc-field">
        <span>{label}</span>
        <input
          type="text" value={value} placeholder={placeholder} disabled={running}
          onChange={(event) => onChange(event.target.value)}
          spellCheck={false} autoCapitalize="none" autoCorrect="off"
        />
      </label>
      {children}
      <button type="submit" className="primary" disabled={running || value.trim().length === 0}>
        {running ? busyAction : action}
      </button>
    </form>
  );
}

/** Backend errors arrive as stable `kind:code` keys, never raw text. */
function useErrorText() {
  const { t } = useI18n();
  return useCallback((raw: unknown) => {
    const cleaned = String(raw).replace(/^Error:\s*/, "");
    const [kind, code] = cleaned.split(":");
    if (kind === "target" && code) return t(`quickCheck.error.${code}`);
    if (kind === "dns" && code) return t(`quickCheck.error.${code}`);
    if (kind === "watch" && code) return t(`quickCheck.error.${code}`);
    if (cleaned === "resolveFailed" || cleaned === "resolveEmpty") return t(`quickCheck.error.${cleaned}`);
    return t("quickCheck.error.generic");
  }, [t]);
}

/* Overview ---------------------------------------------------------------- */

/** Four bars, because a dBm number means nothing to most people. */
function SignalBars({ quality }: { quality: SignalQuality | null }) {
  const filled: Record<SignalQuality, number> = {
    excellent: 4, good: 3, fair: 2, weak: 1, unusable: 0,
  };
  const count = quality ? filled[quality] : 0;
  return (
    <span className={`qc-bars qc-bars-${quality ?? "unknown"}`} aria-hidden="true">
      {[0, 1, 2, 3].map((index) => (
        <i key={index} className={index < count ? "on" : ""} style={{ height: `${(index + 1) * 25}%` }} />
      ))}
    </span>
  );
}

function Overview({ data, egress, egressLoading }: {
  data: LocalNetwork | null;
  egress: Egress | null;
  egressLoading: boolean;
}) {
  const { t } = useI18n();
  if (!data) return <p className="qc-loading">{t("quickCheck.loadingOverview")}</p>;

  // Tolerate a malformed payload rather than taking the whole panel down with
  // it: the overview is a convenience, and the tools below must stay usable.
  const interfaces = Array.isArray(data.interfaces) ? data.interfaces : [];
  const dnsServers = Array.isArray(data.dnsServers) ? data.dnsServers : [];
  const tunnels = Array.isArray(data.tunnels) ? data.tunnels : [];

  const active = interfaces.filter((entry) => entry.kind === "physical" && entry.isUp);
  const fakeIp = interfaces.filter((entry) => entry.carriesFakeIp && entry.isUp);
  const primary = active[0];
  const wifi = data.wifi;

  const egressValue = egressLoading
    ? "…"
    : egress?.primary ?? (egress ? t("quickCheck.egressUnknown") : "—");

  return (
    <div className="qc-overview">
      <div className="qc-overview-grid">
        <Metric
          label={t("quickCheck.ovInterface")}
          value={primary ? primary.name : "—"}
          hint={primary ? `${primary.ipv4}/${primary.prefix}` : undefined}
        />
        <Metric label={t("quickCheck.ovGateway")} value={data.gateway ?? "—"} />
        <Metric
          label={t("quickCheck.ovDns")}
          value={dnsServers[0] ?? "—"}
          hint={dnsServers.length > 1 ? dnsServers.slice(1).join(", ") : undefined}
        />
        <Metric
          label={t("quickCheck.ovEgress")}
          value={egressValue}
          hint={egress?.secondary ? `${t("quickCheck.egressAlso")} ${egress.secondary}` : undefined}
          tone={egress?.verdict === "split" || egress?.verdict === "intercepted" ? "warn" : undefined}
        />
        <Metric
          label={t("quickCheck.ovTunnels")}
          value={tunnels.length === 0 ? t("quickCheck.ovNone") : String(tunnels.length)}
          hint={tunnels.join(", ") || undefined}
          tone={tunnels.length > 0 ? "warn" : undefined}
        />
      </div>

      {wifi && wifi.quality ? (
        <div className={`qc-wifi qc-wifi-${wifi.quality}`}>
          <SignalBars quality={wifi.quality} />
          <div className="qc-wifi-text">
            <strong>{t(`quickCheck.signal.${wifi.quality}`)}</strong>
            <span>
              {[
                wifi.rssiDbm !== null ? `${wifi.rssiDbm} dBm` : null,
                wifi.snrDb !== null ? `${t("quickCheck.snr")} ${wifi.snrDb} dB` : null,
                wifi.transmitRateMbps !== null ? `${Math.round(wifi.transmitRateMbps)} Mbps` : null,
              ].filter(Boolean).join(" · ")}
            </span>
          </div>
          {wifi.quality === "weak" || wifi.quality === "unusable" ? (
            <p className="qc-wifi-note">{t("quickCheck.signalWeakNote")}</p>
          ) : null}
        </div>
      ) : null}

      {/* When the fake-IP banner is shown it already names this cause, so the
          weaker restatement is suppressed. A split route is different news and
          is always worth showing. */}
      {egress && (egress.verdict === "split" || (egress.verdict === "intercepted" && fakeIp.length === 0)) ? (
        <div className="qc-banner qc-banner-warn">
          <strong>{t(`quickCheck.egressTitle.${egress.verdict}`)}</strong>
          <ul>{egress.reasons.map((reason) => <li key={reason}>{t(`quickCheck.egressReason.${reason}`)}</li>)}</ul>
        </div>
      ) : null}

      {fakeIp.length > 0 ? (
        <div className="qc-banner qc-banner-alert" role="alert">
          <strong>{t("quickCheck.fakeIpTitle")}</strong>
          <p>{t("quickCheck.fakeIpBody", { interfaces: fakeIp.map((entry) => `${entry.name} (${entry.ipv4})`).join(", ") })}</p>
        </div>
      ) : null}

      <details className="qc-details">
        <summary>{t("quickCheck.allInterfaces")}</summary>
        <table className="qc-table">
          <thead>
            <tr>
              <th>{t("quickCheck.colName")}</th><th>{t("quickCheck.colAddress")}</th><th>{t("quickCheck.colKind")}</th>
            </tr>
          </thead>
          <tbody>
            {interfaces.map((entry) => (
              <tr key={entry.name} className={entry.carriesFakeIp ? "qc-row-alert" : undefined}>
                <td>{entry.name}</td>
                <td className="qc-mono">{entry.ipv4}/{entry.prefix}</td>
                <td>{t(`quickCheck.kind.${entry.kind}`)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </details>
    </div>
  );
}

/* Ping -------------------------------------------------------------------- */

function PingTool() {
  const { t } = useI18n();
  const describe = useErrorText();
  const [target, setTarget] = useState("");
  const [running, setRunning] = useState(false);
  const [report, setReport] = useState<QuickCheckReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [phase, setPhase] = useState<string | null>(null);
  const [live, setLive] = useState<(number | null)[]>([]);

  useEffect(() => {
    let active = true;
    let dispose: (() => void) | null = null;
    void (async () => {
      try {
        const stop = await listen<{ phase: string; rttMs: number | null }>("quick-check-probe", (event) => {
          if (!active) return;
          setPhase(event.payload.phase);
          if (event.payload.phase === "target") setLive((prev) => [...prev, event.payload.rttMs]);
        });
        if (active) dispose = stop;
        else stop();
      } catch {
        // Losing live updates costs chart points, not the panel.
      }
    })();
    return () => { active = false; dispose?.(); };
  }, []);

  const run = async (raw: string) => {
    const candidate = raw.trim();
    if (!candidate || running) return;
    setRunning(true); setError(null); setReport(null); setLive([]); setPhase(null);
    try {
      const result = await invoke<QuickCheckReport>("run_quick_check", { target: candidate });
      setReport(result); setLive(result.samples);
    } catch (failure) {
      setError(describe(failure));
    } finally { setRunning(false); setPhase(null); }
  };

  const intercepted = report?.health === "untrustworthy";
  const healthText: Record<Health, string> = {
    good: t("quickCheck.healthGood"), fair: t("quickCheck.healthFair"), poor: t("quickCheck.healthPoor"),
    unreachable: t("quickCheck.healthUnreachable"), untrustworthy: t("quickCheck.healthUntrustworthy"),
  };
  const ms = (value: number | null | undefined) => (value === null || value === undefined ? "—" : `${value} ms`);

  return (
    <>
      <TargetForm
        value={target} onChange={setTarget} onSubmit={() => void run(target)} running={running}
        label={t("quickCheck.targetLabel")} placeholder={t("quickCheck.placeholder")}
        action={t("quickCheck.run")} busyAction={t("quickCheck.running")}
      />
      <div className="qc-presets">
        <span>{t("quickCheck.presets")}</span>
        {["1.1.1.1", "example.com"].map((preset) => (
          <button key={preset} type="button" disabled={running} onClick={() => { setTarget(preset); void run(preset); }}>
            {preset}
          </button>
        ))}
      </div>

      {running && phase ? <p className="qc-phase">{t(`quickCheck.phase.${phase}`)}</p> : null}
      {error ? <p className="error-text">{error}</p> : null}
      {live.length > 0 ? <Chart samples={live} /> : null}

      {report ? (
        <>
          {intercepted ? (
            <div className="qc-banner qc-banner-alert" role="alert">
              <strong>{t("quickCheck.interceptTitle")}</strong>
              <p>{t("quickCheck.interceptBody")}</p>
              <ul>{report.interference.reasons.map((reason) => <li key={reason}>{t(`quickCheck.reason.${reason}`)}</li>)}</ul>
            </div>
          ) : null}

          {/* When intercepted, the alert above already carries the verdict;
              repeating it in a second card says the same thing twice. */}
          {intercepted ? null : (
            <div className={`qc-verdict qc-verdict-${report.health}`}>
              <span>{report.target}{report.resolvedAddress && report.resolvedAddress !== report.target ? ` · ${report.resolvedAddress}` : ""}</span>
              <strong>{healthText[report.health]}</strong>
            </div>
          )}

          {/* Numbers declared untrustworthy must not also be the headline. */}
          {intercepted ? <p className="qc-void-label">{t("quickCheck.voidedMetrics")}</p> : null}
          <div className={`qc-metrics${intercepted ? " qc-metrics-void" : ""}`}>
            <Metric label={t("quickCheck.metricLoss")} value={`${report.stats.lossPct.toFixed(0)}%`} tone={report.stats.lossPct > 0 ? "warn" : undefined} />
            <Metric label={t("quickCheck.metricLatency")} value={ms(report.stats.avgMs)} />
            <Metric label={t("quickCheck.metricJitter")} value={ms(report.stats.jitterMs)} hint={t("quickCheck.jitterHint")} />
            {report.dnsMs !== null ? <Metric label={t("quickCheck.metricDns")} value={ms(report.dnsMs)} /> : null}
          </div>

          <div className="qc-findings">
            <h3>{t("quickCheck.whatThisMeans")}</h3>
            <ul>{report.findings.map((finding) => <li key={finding}>{t(`quickCheck.finding.${finding}`)}</li>)}</ul>
          </div>
        </>
      ) : null}
    </>
  );
}

/* Ports ------------------------------------------------------------------- */

const PORT_PRESETS = [80, 443, 22, 445, 554, 8080];

function PortTool() {
  const { t } = useI18n();
  const describe = useErrorText();
  const [target, setTarget] = useState("");
  const [port, setPort] = useState("443");
  const [running, setRunning] = useState(false);
  const [results, setResults] = useState<PortResult[]>([]);
  const [error, setError] = useState<string | null>(null);

  const run = async (which: number[]) => {
    const candidate = target.trim();
    if (!candidate || running) return;
    setRunning(true); setError(null); setResults([]);
    try {
      // Sequential, not parallel: a burst of simultaneous connects is the shape
      // of a scanner, and this tool must never look like one.
      const collected: PortResult[] = [];
      for (const value of which) {
        collected.push(await invoke<PortResult>("check_tcp_port", { target: candidate, port: value }));
        setResults([...collected]);
      }
    } catch (failure) {
      setError(describe(failure));
    } finally { setRunning(false); }
  };

  return (
    <>
      <TargetForm
        value={target} onChange={setTarget} onSubmit={() => void run([Number(port) || 0])} running={running}
        label={t("quickCheck.portTargetLabel")} placeholder={t("quickCheck.placeholder")}
        action={t("quickCheck.portRun")} busyAction={t("quickCheck.running")}
      >
        <label className="qc-field qc-field-narrow">
          <span>{t("quickCheck.portLabel")}</span>
          <input
            type="number" min={1} max={65535} value={port} disabled={running}
            onChange={(event) => setPort(event.target.value)}
          />
        </label>
      </TargetForm>

      <div className="qc-presets">
        <span>{t("quickCheck.portCommon")}</span>
        <button type="button" disabled={running || !target.trim()} onClick={() => void run(PORT_PRESETS)}>
          {t("quickCheck.portCheckCommon")}
        </button>
      </div>

      {error ? <p className="error-text">{error}</p> : null}

      {results.length > 0 ? (
        <table className="qc-table qc-table-wide">
          <thead>
            <tr>
              <th>{t("quickCheck.colPort")}</th><th>{t("quickCheck.colService")}</th>
              <th>{t("quickCheck.colState")}</th><th>{t("quickCheck.colTime")}</th>
            </tr>
          </thead>
          <tbody>
            {results.map((result) => (
              <tr key={result.port}>
                <td>{result.port}</td>
                <td>{result.service ?? "—"}</td>
                <td><span className={`qc-pill qc-pill-${result.state}`}>{t(`quickCheck.portState.${result.state}`)}</span></td>
                <td>{result.elapsedMs.toFixed(0)} ms</td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : null}

      {results.length > 0 ? <p className="qc-note">{t("quickCheck.portStateHint")}</p> : null}
    </>
  );
}

/* Route --------------------------------------------------------------------- */

function RouteTool() {
  const { t } = useI18n();
  const describe = useErrorText();
  const [target, setTarget] = useState("");
  const [running, setRunning] = useState(false);
  const [hops, setHops] = useState<Hop[]>([]);
  const [trace, setTrace] = useState<Trace | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    let dispose: (() => void) | null = null;
    void (async () => {
      try {
        const stop = await listen<Hop>("quick-check-hop", (event) => {
          if (active) setHops((prev) => [...prev, event.payload]);
        });
        if (active) dispose = stop;
        else stop();
      } catch {
        // The final result still arrives; only the live fill is lost.
      }
    })();
    return () => { active = false; dispose?.(); };
  }, []);

  const run = async () => {
    const candidate = target.trim();
    if (!candidate || running) return;
    setRunning(true); setError(null); setHops([]); setTrace(null);
    try {
      setTrace(await invoke<Trace>("run_traceroute", { target: candidate, resolveNames: true }));
    } catch (failure) {
      setError(describe(failure));
    } finally { setRunning(false); }
  };

  const shown = trace?.hops ?? hops;

  return (
    <>
      <TargetForm
        value={target} onChange={setTarget} onSubmit={() => void run()} running={running}
        label={t("quickCheck.routeTargetLabel")} placeholder={t("quickCheck.placeholder")}
        action={t("quickCheck.routeRun")} busyAction={t("quickCheck.routeRunning")}
      />
      <p className="qc-note">{t("quickCheck.routeHint")}</p>
      {error ? <p className="error-text">{error}</p> : null}

      {trace?.implausiblyShort ? (
        <div className="qc-banner qc-banner-alert" role="alert">
          <strong>{t("quickCheck.routeFakeTitle")}</strong>
          <p>{t("quickCheck.routeFakeBody")}</p>
        </div>
      ) : null}

      {shown.length > 0 ? (
        // A trace we have just called fake must not also paint the final hop as
        // a successful arrival.
        <ol className={`qc-hops${trace?.implausiblyShort ? " qc-hops-void" : ""}`}>
          {shown.map((hop) => (
            <li key={hop.ttl} className={hop.reachedTarget && !trace?.implausiblyShort ? "qc-hop-target" : hop.address ? "" : "qc-hop-silent"}>
              <span className="qc-hop-ttl">{hop.ttl}</span>
              <span className="qc-hop-name">
                {hop.address ? (
                  <>
                    <span className="qc-mono">{hop.address}</span>
                    {hop.hostname ? <em>{hop.hostname}</em> : null}
                  </>
                ) : (
                  <span className="qc-hop-nothing">{t("quickCheck.routeNoReply")}</span>
                )}
              </span>
              <span className="qc-hop-rtt">{hop.rttMs === null ? "" : `${hop.rttMs.toFixed(1)} ms`}</span>
            </li>
          ))}
        </ol>
      ) : null}

      {trace && !trace.implausiblyShort ? (
        <p className="qc-note">{t(`quickCheck.routeOutcome.${trace.outcome}`)}</p>
      ) : null}
    </>
  );
}

/* DNS --------------------------------------------------------------------- */

function DnsTool() {
  const { t } = useI18n();
  const describe = useErrorText();
  const [name, setName] = useState("");
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState<DnsDiagnosis | null>(null);
  const [error, setError] = useState<string | null>(null);

  const run = async (raw: string) => {
    const candidate = raw.trim();
    if (!candidate || running) return;
    setRunning(true); setError(null); setResult(null);
    try {
      setResult(await invoke<DnsDiagnosis>("diagnose_dns", { name: candidate }));
    } catch (failure) {
      setError(describe(failure));
    } finally { setRunning(false); }
  };

  return (
    <>
      <TargetForm
        value={name} onChange={setName} onSubmit={() => void run(name)} running={running}
        label={t("quickCheck.dnsNameLabel")} placeholder="example.com"
        action={t("quickCheck.dnsRun")} busyAction={t("quickCheck.running")}
      />
      {error ? <p className="error-text">{error}</p> : null}

      {result ? (
        <>
          <div className={`qc-verdict qc-verdict-dns-${result.verdict}`}>
            <span>{result.name}</span>
            <strong>{t(`quickCheck.dnsVerdict.${result.verdict}`)}</strong>
          </div>

          <table className="qc-table qc-table-wide">
            <thead>
              <tr>
                <th>{t("quickCheck.colResolver")}</th><th>{t("quickCheck.colAnswer")}</th><th>{t("quickCheck.colTime")}</th>
              </tr>
            </thead>
            <tbody>
              {[...result.system.map((answer) => ({ answer, role: "system" })), { answer: result.public, role: "public" }].map(({ answer, role }) => (
                <tr key={`${role}-${answer.server}`}>
                  <td>{answer.server}<span className="qc-role">{t(`quickCheck.resolverRole.${role}`)}</span></td>
                  <td>{answer.error ? <em>{t(`quickCheck.dnsError.${answer.error}`)}</em> : answer.addresses.join(", ")}</td>
                  <td>{answer.elapsedMs === null ? "—" : `${answer.elapsedMs.toFixed(0)} ms`}</td>
                </tr>
              ))}
            </tbody>
          </table>

          <div className="qc-findings">
            <ul>{result.reasons.map((reason) => <li key={reason}>{t(`quickCheck.dnsReason.${reason}`)}</li>)}</ul>
          </div>
        </>
      ) : null}
    </>
  );
}

/* Watch ------------------------------------------------------------------- */

function WatchTool() {
  const { t } = useI18n();
  const describe = useErrorText();
  const [target, setTarget] = useState("");
  const [running, setRunning] = useState(false);
  const [samples, setSamples] = useState<(number | null)[]>([]);
  const [summary, setSummary] = useState<WatchSummary | null>(null);
  const [error, setError] = useState<string | null>(null);
  const startedAt = useRef<number>(0);

  useEffect(() => {
    let active = true;
    let dispose: (() => void) | null = null;
    void (async () => {
      try {
        const stop = await listen<[number, number | null]>("quick-check-watch", (event) => {
          if (!active) return;
          setSamples((prev) => [...prev, event.payload[1]]);
        });
        if (active) dispose = stop;
        else stop();
      } catch {
        // Same: the run still completes and returns its summary.
      }
    })();
    return () => { active = false; dispose?.(); };
  }, []);

  const start = async () => {
    const candidate = target.trim();
    if (!candidate || running) return;
    setRunning(true); setError(null); setSamples([]); setSummary(null);
    startedAt.current = Date.now();
    try {
      setSummary(await invoke<WatchSummary>("start_watch", { target: candidate, intervalMs: 1000 }));
    } catch (failure) {
      setError(describe(failure));
    } finally { setRunning(false); }
  };

  const stop = () => { void invoke("stop_watch"); };

  const clock = (ms: number) => {
    const total = Math.round(ms / 1000);
    return `${String(Math.floor(total / 60)).padStart(2, "0")}:${String(total % 60).padStart(2, "0")}`;
  };

  return (
    <>
      <TargetForm
        value={target} onChange={setTarget} onSubmit={() => void start()} running={running}
        label={t("quickCheck.watchTargetLabel")} placeholder={t("quickCheck.placeholder")}
        action={t("quickCheck.watchStart")} busyAction={t("quickCheck.watchRunning")}
      />
      {running ? (
        <div className="qc-presets">
          <button type="button" className="qc-stop" onClick={stop}>{t("quickCheck.watchStop")}</button>
          <span className="qc-live-count">{t("quickCheck.watchProbes", { count: String(samples.length) })}</span>
        </div>
      ) : null}

      <p className="qc-note">{t("quickCheck.watchHint")}</p>
      {error ? <p className="error-text">{error}</p> : null}
      {samples.length > 0 ? <Chart samples={samples} height={180} /> : null}

      {summary ? (
        <>
          <div className="qc-metrics">
            <Metric label={t("quickCheck.watchTotal")} value={String(summary.totalProbes)} />
            <Metric label={t("quickCheck.metricLoss")} value={`${summary.lossPct}%`} tone={summary.lossPct > 0 ? "warn" : undefined} />
            <Metric label={t("quickCheck.watchOutages")} value={String(summary.outages.length)} tone={summary.outages.length > 0 ? "warn" : undefined} />
            <Metric label={t("quickCheck.watchLongest")} value={summary.longestOutageMs === null ? "—" : `${(summary.longestOutageMs / 1000).toFixed(1)} s`} />
          </div>

          {summary.outages.length > 0 ? (
            <table className="qc-table qc-table-wide">
              <thead>
                <tr><th>{t("quickCheck.colWhen")}</th><th>{t("quickCheck.colDuration")}</th><th>{t("quickCheck.colMissed")}</th></tr>
              </thead>
              <tbody>
                {summary.outages.map((outage) => (
                  <tr key={outage.startedAtMs}>
                    <td>{clock(outage.startedAtMs)}</td>
                    <td>{outage.durationMs === null ? t("quickCheck.watchOngoing") : `${(outage.durationMs / 1000).toFixed(1)} s`}</td>
                    <td>{outage.missedProbes}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <p className="qc-note">{t("quickCheck.watchNoOutage")}</p>
          )}
        </>
      ) : null}
    </>
  );
}

/* Shell -------------------------------------------------------------------- */

const SANDBOX_SAFE_TOOLS: Tool[] = ["ping", "port", "route", "dns", "watch"];

/**
 * The single destination for network diagnostics.
 *
 * `deepReport` is the authorization-gated whole-path analysis. It lives here as
 * a tab rather than as its own sidebar entry, because two top-level entries both
 * meaning "check my network" only made users guess which one to open.
 */
export function QuickCheckPanel({
  onRunningChange,
  deepReport,
}: {
  onRunningChange?: (running: boolean) => void;
  deepReport?: React.ReactNode;
}) {
  const { t } = useI18n();
  const [tool, setTool] = useState<Tool>("ping");
  const [network, setNetwork] = useState<LocalNetwork | null>(null);
  const [egress, setEgress] = useState<Egress | null>(null);
  const [egressLoading, setEgressLoading] = useState(true);

  // The full-path report shells out, which App Sandbox forbids. Offering a tab
  // that can only fail is worse than not offering it.
  const tools: Tool[] = deepReport && !network?.sandboxed
    ? [...SANDBOX_SAFE_TOOLS, "deep"]
    : SANDBOX_SAFE_TOOLS;

  useEffect(() => {
    // The overview loads on mount, so the screen is never empty on arrival.
    // Wrapped rather than chained with `.catch`: if the bridge is unavailable
    // `invoke` throws synchronously, and an error escaping an effect unmounts
    // the whole panel. The overview is optional; the tools below are not.
    let active = true;
    void (async () => {
      try {
        const snapshot = await invoke<LocalNetwork>("read_local_network");
        if (active) setNetwork(snapshot);
      } catch {
        if (active) setNetwork(null);
      }
    })();
    return () => { active = false; };
  }, []);

  useEffect(() => {
    // Separate from the overview fetch: this one waits on DNS round trips, and
    // the rest of the screen should not wait with it.
    let active = true;
    void (async () => {
      try {
        const seen = await invoke<Egress>("read_public_egress");
        if (active) setEgress(seen);
      } catch {
        if (active) setEgress(null);
      } finally {
        if (active) setEgressLoading(false);
      }
    })();
    return () => { active = false; };
  }, []);

  useEffect(() => { onRunningChange?.(false); }, [onRunningChange]);

  return (
    <section className="card quick-check">
      <span className="eyebrow">{t("quickCheck.eyebrow")}</span>
      <h2>{t("quickCheck.title")}</h2>
      <p className="qc-lede">{t("quickCheck.description")}</p>

      <Overview data={network} egress={egress} egressLoading={egressLoading} />

      <div className="qc-tabs" role="tablist">
        {tools.map((entry) => (
          <button
            key={entry} type="button" role="tab" aria-selected={tool === entry}
            className={tool === entry ? "active" : ""} onClick={() => setTool(entry)}
          >
            {t(`quickCheck.tool.${entry}`)}
          </button>
        ))}
      </div>

      <p className="qc-tool-lede">{t(`quickCheck.toolLede.${tool}`)}</p>

      <div className="qc-tool-body">
        {tool === "ping" ? <PingTool /> : null}
        {tool === "port" ? <PortTool /> : null}
        {tool === "route" ? <RouteTool /> : null}
        {tool === "dns" ? <DnsTool /> : null}
        {tool === "watch" ? <WatchTool /> : null}
        {tool === "deep" ? deepReport ?? null : null}
      </div>

      {tool === "deep" ? null : <p className="guardrail">{t("quickCheck.limits")}</p>}
    </section>
  );
}
