import { useCallback, useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { Camera, CircleHelp, Laptop, Monitor, Router, Search, type LucideIcon } from "lucide-react";
import { useI18n } from "./i18n";
import { filterWifiDevices, type WifiDeviceFilter } from "./wifi-inventory";

/* Types mirroring the Rust payloads -------------------------------------- */

type Health = "good" | "fair" | "poor" | "unreachable" | "untrustworthy";
type PathVerdict = "direct" | "locallyIntercepted" | "noExternalPath" | "unknown";
type InterfaceKind = "physical" | "tunnel" | "bridge" | "loopback" | "other";
type PortState = "open" | "refused" | "filtered";
type DnsVerdict = "consistent" | "syntheticAnswer" | "divergent" | "inconclusive";
type Tool = "ping" | "port" | "device" | "route" | "dns" | "watch" | "deep";
type DeviceProfile = "camera" | "switch" | "generic";
type RtspState = "serving" | "needsCredentials" | "notRtsp" | "unreachable";
type SegmentVerdict = "standard" | "tunnelled" | "restricted" | "unreachable";
type NeighbourKind = "device" | "randomised" | "multicast" | "broadcast" | "unresolved";
type LikelyKind = "camera" | "network" | "endpoint";
type SignalQuality = "excellent" | "good" | "fair" | "weak" | "unusable";
type EgressVerdict = "confirmed" | "split" | "intercepted" | "unknown";
type ClockVerdict = "accurate" | "drifting" | "wrong" | "unreachable" | "imprecise";

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
interface ClockCheck {
  server: string; offsetMs: number | null; roundTripMs: number | null;
  uncertaintyMs: number | null; verdict: ClockVerdict; reasons: string[];
}
interface LocalNetwork {
  interfaces: NetInterface[]; dnsServers: string[]; gateway: string | null; tunnels: string[];
  sandboxed: boolean; wifi: WifiStatus | null;
}
interface PortResult { port: number; state: PortState; elapsedMs: number; service: string | null }
interface DnsAnswer { server: string; addresses: string[]; elapsedMs: number | null; error: string | null }
interface DnsDiagnosis { name: string; system: DnsAnswer[]; public: DnsAnswer; verdict: DnsVerdict; reasons: string[] }
interface Neighbour {
  ip: string; mac: string | null; kind: NeighbourKind;
  vendor: string | null; likely: LikelyKind | null;
  interface: string | null; hostname: string | null;
}
interface ScopeRecord { subnet: string; authorizedAt: string; note: string | null }
interface SweepScope {
  subnet: string;
  authorized: boolean;
}
interface SweepResult {
  subnet: string; probed: number; responded: number; hosts: Neighbour[];
}
interface RtspCheck {
  port: number; state: RtspState; methods: string[]; server: string | null; elapsedMs: number;
}
interface DeviceReport {
  target: string; profile: DeviceProfile; ports: PortResult[]; rtsp: RtspCheck[]; findings: string[];
}
interface SegmentCheck {
  target: string; port: number; mss: number | null; impliedMtu: number | null;
  verdict: SegmentVerdict; reasons: string[];
}
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

/** Scope errors carry the subnet after the code, so they need their own parse. */
function describeScopeError(raw: unknown, t: (key: string, params?: Record<string, string>) => string) {
  const cleaned = String(raw).replace(/^Error:\s*/, "");
  const [kind, code, extra] = cleaned.split(":");
  if (kind === "scope" && code === "notAuthorized") {
    return t("quickCheck.error.notAuthorized", { subnet: extra ?? "" });
  }
  if (kind === "wifi" && code) {
    return t(`wifi.error.${code}`);
  }
  if ((kind === "scope" || kind === "sweep") && code) {
    return t(`quickCheck.error.${code}`);
  }
  return t("quickCheck.error.generic");
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

/**
 * Scale a clock offset to a unit a person can read.
 * "+412000 ms" is technically the offset and tells nobody they are seven
 * minutes out.
 */
function formatOffset(offsetMs: number, t: (key: string, params?: Record<string, string>) => string) {
  const sign = offsetMs > 0 ? "+" : "-";
  const magnitude = Math.abs(offsetMs);
  if (magnitude < 1000) return `${sign}${Math.round(magnitude)} ms`;
  if (magnitude < 90_000) return `${sign}${(magnitude / 1000).toFixed(1)} s`;
  const minutes = Math.floor(magnitude / 60_000);
  const seconds = Math.round((magnitude % 60_000) / 1000);
  return `${sign}${t("quickCheck.clockMinutes", { minutes: String(minutes), seconds: String(seconds) })}`;
}

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

function Overview({ data, egress, egressLoading, clock }: {
  data: LocalNetwork | null;
  egress: Egress | null;
  egressLoading: boolean;
  clock: ClockCheck | null;
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
          label={t("quickCheck.ovClock")}
          value={
            clock === null ? "…"
              : clock.verdict === "unreachable" ? "—"
              : clock.verdict === "imprecise" ? t("quickCheck.clockImprecise")
              : formatOffset(clock.offsetMs ?? 0, t)
          }
          hint={clock ? t(`quickCheck.clockVerdict.${clock.verdict}`) : undefined}
          tone={clock?.verdict === "wrong" ? "warn" : undefined}
        />
        <Metric
          label={t("quickCheck.ovTunnels")}
          value={tunnels.length === 0 ? t("quickCheck.ovNone") : String(tunnels.length)}
          hint={tunnels.join(", ") || undefined}
          tone={tunnels.length > 0 ? "warn" : undefined}
        />
      </div>

      {clock && clock.verdict === "wrong" ? (
        <div className="qc-banner qc-banner-alert" role="alert">
          <strong>{t("quickCheck.clockWrongTitle")}</strong>
          <p>{t("quickCheck.clockWrongBody", {
            amount: formatOffset(Math.abs(clock.offsetMs ?? 0), t).replace(/^[+-]/, ""),
            direction: t(`quickCheck.clock.${(clock.offsetMs ?? 0) > 0 ? "behind" : "ahead"}`),
          })}</p>
          <ul>{clock.reasons.map((reason) => <li key={reason}>{t(`quickCheck.clockReason.${reason}`)}</li>)}</ul>
        </div>
      ) : null}

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

/* Devices ------------------------------------------------------------------- */

const PROFILES: DeviceProfile[] = ["camera", "switch", "generic"];
/** Ports whose management page can be opened, mirroring the backend's rule. */
const WEB_PORTS = [443, 8443, 80, 8080, 8000];

/** What this Mac has already talked to. Passive, and explicitly partial. */
function Neighbours({ onPick, wifiOnly = false }: { onPick?: (ip: string) => void; wifiOnly?: boolean }) {
  const { t } = useI18n();
  const [items, setItems] = useState<Neighbour[] | null>(null);
  const [loading, setLoading] = useState(false);
  const [sweeping, setSweeping] = useState(false);
  const [swept, setSwept] = useState<SweepResult | null>(null);
  const [progress, setProgress] = useState<[number, number] | null>(null);
  const [pending, setPending] = useState<SweepScope | null>(null);
  const [note, setNote] = useState("");
  const [scope, setScope] = useState<ScopeRecord[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [wifiQuery, setWifiQuery] = useState("");
  const [wifiFilter, setWifiFilter] = useState<WifiDeviceFilter>("all");
  const [cacheReadAt, setCacheReadAt] = useState<Date | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      setItems(await invoke<Neighbour[]>(wifiOnly ? "list_wifi_neighbours" : "list_neighbours", { resolveNames: !wifiOnly }));
      if (wifiOnly) setCacheReadAt(new Date());
    } catch (failure) {
      setItems([]);
      if (wifiOnly) setCacheReadAt(null);
      setError(describeScopeError(failure, t));
    } finally {
      setLoading(false);
    }
  }, [t, wifiOnly]);

  useEffect(() => { void load(); }, [load]);

  useEffect(() => {
    let active = true;
    let dispose: (() => void) | null = null;
    void (async () => {
      try {
        const stop = await listen<[number, number]>("quick-check-sweep", (event) => {
          if (active) setProgress(event.payload);
        });
        if (active) dispose = stop;
        else stop();
      } catch {
        // Progress only.
      }
    })();
    return () => { active = false; dispose?.(); };
  }, []);

  const loadScope = useCallback(async () => {
    try {
      setScope(await invoke<ScopeRecord[]>("read_scope"));
    } catch {
      setScope([]);
    }
  }, []);

  useEffect(() => { if (!wifiOnly) void loadScope(); }, [loadScope, wifiOnly]);

  const runSweep = async () => {
    setSweeping(true); setProgress(null); setSwept(null); setError(null);
    try {
      setSwept(await invoke<SweepResult>("sweep_local_subnet"));
      await load();
    } catch (failure) {
      setError(describeScopeError(failure, t));
      setSwept(null);
    } finally { setSweeping(false); setProgress(null); }
  };

  /// Asks for consent the first time a network is swept, then remembers it.
  const startSweep = async () => {
    setError(null);
    try {
      const current = await invoke<SweepScope>("describe_sweep_scope");
      if (current.authorized) {
        await runSweep();
      } else {
        setPending(current);
      }
    } catch (failure) {
      setError(describeScopeError(failure, t));
    }
  };

  const confirmScope = async () => {
    try {
      setScope(await invoke<ScopeRecord[]>("authorize_current_subnet", { note: note.trim() || null }));
      setPending(null);
      setNote("");
      await runSweep();
    } catch (failure) {
      setError(describeScopeError(failure, t));
    }
  };

  const revoke = async (subnet: string) => {
    try {
      setScope(await invoke<ScopeRecord[]>("revoke_subnet", { subnet }));
    } catch (failure) {
      setError(describeScopeError(failure, t));
    }
  };

  // Once a sweep has run its list supersedes the passive one.
  const shown = swept?.hosts ?? items;
  const wifiCategories: WifiDeviceFilter[] = ["all", "network", "camera", "endpoint", "other"];
  const filteredWifiDevices = wifiOnly ? filterWifiDevices(shown ?? [], wifiFilter, wifiQuery) : [];

  const iconForWifiDevice = (entry: Neighbour): LucideIcon => {
    if (entry.likely === "network") return Router;
    if (entry.likely === "camera") return Camera;
    if (entry.likely === "endpoint") return Laptop;
    return entry.kind === "unresolved" ? CircleHelp : Monitor;
  };

  return (
    <details className="qc-details qc-neighbours" open>
      <summary>
        {wifiOnly ? t("wifi.detectedDevices") : t("quickCheck.neighboursHeading")}
        {shown ? <span className="qc-count">{shown.length}</span> : null}
      </summary>
      {wifiOnly ? (
        <div className="wifi-scan-actions">
          <span className="wifi-source-label">{t("wifi.cacheSource")}</span>
          <div className="qc-presets">
            <button type="button" disabled={loading || sweeping} onClick={() => void load()}>{t("wifi.refresh")}</button>
          </div>
        </div>
      ) : null}
      <p className="qc-note">
        {swept ? t("quickCheck.sweptSummary", { subnet: swept.subnet, probed: String(swept.probed) }) : wifiOnly ? t("wifi.passiveNote") : t("quickCheck.neighboursLimit")}
      </p>
      {wifiOnly && cacheReadAt ? <p className="qc-note">{t("wifi.cacheReadAt", { time: cacheReadAt.toLocaleTimeString() })}</p> : null}
      {wifiOnly && shown && shown.length > 0 ? (
        <div className="wifi-inventory-tools">
          <label className="wifi-device-search">
            <Search size={16} aria-hidden="true" />
            <input type="search" value={wifiQuery} onChange={(event) => setWifiQuery(event.target.value)} placeholder={t("wifi.searchDevices")} aria-label={t("wifi.searchDevices")} />
          </label>
          <div className="wifi-device-filters" role="group" aria-label={t("wifi.detectedDevices")}>
            {wifiCategories.map((filter) => {
              const count = filter === "all" ? shown.length : shown.filter((entry) => (entry.likely ?? "other") === filter).length;
              return (
                <button key={filter} type="button" aria-pressed={wifiFilter === filter} className={wifiFilter === filter ? "selected" : ""} onClick={() => setWifiFilter(filter)}>
                  {t(`wifi.filter.${filter}`)}<span>{count}</span>
                </button>
              );
            })}
          </div>
        </div>
      ) : null}
      {wifiOnly && filteredWifiDevices.length > 0 ? (
        <div className="wifi-device-grid">
          {filteredWifiDevices.map((entry) => {
            const Icon = iconForWifiDevice(entry);
            const title = entry.hostname || (entry.likely ? t(`wifi.filter.${entry.likely}`) : t(`quickCheck.neighbourKind.${entry.kind}`));
            return (
              <article className="wifi-device-card" key={`${entry.ip}-${entry.mac ?? "none"}`}>
                <div className="wifi-device-card-heading">
                  <span className="wifi-device-icon"><Icon size={19} strokeWidth={1.9} /></span>
                  <div className="wifi-device-title"><strong title={title}>{title}</strong><span>{entry.ip}</span></div>
                  {entry.likely ? <span aria-label={`${t("wifi.deviceType")}: ${t(`wifi.filter.${entry.likely}`)}`} className={`wifi-device-kind ${entry.likely}`}>{t(`wifi.filter.${entry.likely}`)}</span> : null}
                </div>
                <dl className="wifi-device-details">
                  {entry.hostname ? <div><dt>{t("wifi.hostname")}</dt><dd>{entry.hostname}</dd></div> : null}
                  <div><dt>{t("wifi.manufacturer")}</dt><dd>{entry.vendor ?? "—"}</dd></div>
                  <div><dt>{t("wifi.mac")}</dt><dd className="qc-mono">{entry.mac ?? "—"}</dd></div>
                </dl>
              </article>
            );
          })}
        </div>
      ) : wifiOnly && shown && shown.length > 0 ? (
        <p className="wifi-no-matches">{t("wifi.noMatches")}</p>
      ) : null}
      {!wifiOnly && shown && shown.length > 0 ? (
        <table className="qc-table">
          <tbody>
            {shown.map((entry) => (
              <tr key={`${entry.ip}-${entry.mac ?? "none"}`}>
                <td>
                  {onPick ? (
                    <button type="button" className="qc-link" onClick={() => onPick(entry.ip)}>
                      <span className="qc-mono">{entry.ip}</span>
                    </button>
                  ) : <span className="qc-mono">{entry.ip}</span>}
                </td>
                <td>
                  {entry.vendor ? (
                    <span className={entry.likely ? `qc-tag qc-tag-${entry.likely}` : "qc-tag"}>{entry.vendor}</span>
                  ) : (
                    <span className="qc-dim">{t(`quickCheck.neighbourKind.${entry.kind}`)}</span>
                  )}
                </td>
                <td className="qc-dim">{entry.hostname ?? entry.mac ?? ""}</td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : !wifiOnly && (
        error ? null : <p className="qc-note">{loading || sweeping ? t("quickCheck.loadingOverview") : wifiOnly ? t("wifi.empty") : t("quickCheck.neighboursEmpty")}</p>
      )}
      {wifiOnly && (!shown || shown.length === 0) && !error ? <p className="qc-note">{loading || sweeping ? t("quickCheck.loadingOverview") : t("wifi.empty")}</p> : null}
      {wifiOnly ? <p className="wifi-coverage-note">{t("wifi.coverage")}</p> : null}
      {pending ? (
        <div className="qc-consent" role="alertdialog" aria-label={t("quickCheck.scopeTitle")}>
          <strong>{t("quickCheck.scopeTitle")}</strong>
          <p>{t("quickCheck.scopeBody", { subnet: pending.subnet })}</p>
          <label className="qc-field">
            <span>{t("quickCheck.scopeNoteLabel")}</span>
            <input
              type="text" value={note} placeholder={t("quickCheck.scopeNotePlaceholder")}
              onChange={(event) => setNote(event.target.value)}
            />
          </label>
          <div className="qc-presets">
            <button type="button" className="primary" onClick={() => void confirmScope()}>
              {t("quickCheck.scopeConfirm")}
            </button>
            <button type="button" onClick={() => { setPending(null); setNote(""); }}>
              {t("quickCheck.scopeCancel")}
            </button>
          </div>
        </div>
      ) : null}

      {error ? <p className="error-text">{error}</p> : null}

      {!wifiOnly && scope.length > 0 ? (
        <div className="qc-scope-list">
          <span>{t("quickCheck.scopeAuthorized")}</span>
          {scope.map((record) => (
            <span key={record.subnet} className="qc-scope-item">
              <span className="qc-mono">{record.subnet}</span>
              {record.note ? <em>{record.note}</em> : null}
              <button type="button" onClick={() => void revoke(record.subnet)} aria-label={t("quickCheck.scopeRevoke")}>×</button>
            </span>
          ))}
        </div>
      ) : null}

      {!wifiOnly ? <div className="qc-presets">
        <button type="button" disabled={loading || sweeping} onClick={() => void load()}>
          {t("quickCheck.neighboursRefresh")}
        </button>
        <button type="button" className="primary" disabled={sweeping || pending !== null} onClick={() => void startSweep()}>
          {sweeping ? t("quickCheck.sweepRunning") : t("quickCheck.sweepStart")}
        </button>
        {sweeping && progress ? (
          <span className="qc-live-count">{progress[0]} / {progress[1]}</span>
        ) : null}
      </div> : null}
      {!wifiOnly && sweeping && progress ? (
        <progress className="wifi-scan-progress" value={progress[0]} max={Math.max(progress[1], 1)} aria-label={t("quickCheck.sweepRunning")} />
      ) : null}
    </details>
  );
}

export function WifiDevicesPage() {
  const { t } = useI18n();
  const [network, setNetwork] = useState<LocalNetwork | null>(null);
  const [networkLoading, setNetworkLoading] = useState(true);

  useEffect(() => {
    let active = true;
    void invoke<LocalNetwork>("read_local_network")
      .then((snapshot) => { if (active) setNetwork(snapshot); })
      .catch(() => { if (active) setNetwork(null); })
      .finally(() => { if (active) setNetworkLoading(false); });
    return () => { active = false; };
  }, []);

  const wifi = network?.wifi;
  const wifiInterface = network?.interfaces.find((entry) => entry.name === wifi?.interface && entry.isUp);
  return (
    <section className="content-stack wifi-workspace">
      <header className="page-heading">
        <div>
          <span className="eyebrow">{t("navWifi")}</span>
          <h2>{t("wifi.title")}</h2>
          <p>{t("wifi.description")}</p>
        </div>
        <span className="wifi-free-badge">{t("wifi.freeLabel")}</span>
      </header>
      <section className="wifi-signal-summary" aria-label={t("wifi.connection")}>
        <div className="wifi-signal-heading">
          <h3>{t("wifi.connection")}</h3>
          {networkLoading ? <span className="muted">{t("wifi.loading")}</span> : null}
        </div>
        <div className="wifi-signal-metrics">
          <div><span>{t("wifi.interface")}</span><strong>{wifi?.interface ?? "—"}</strong></div>
          <div><span>{t("wifi.localAddress")}</span><strong>{wifiInterface ? `${wifiInterface.ipv4}/${wifiInterface.prefix}` : "—"}</strong></div>
          <div><span>{t("wifi.signal")}</span><strong>{wifi?.quality ? t(`quickCheck.signal.${wifi.quality}`) : t("wifi.unavailable")}</strong></div>
          <div><span>{t("wifi.rssi")}</span><strong>{wifi?.rssiDbm != null ? `${wifi.rssiDbm} dBm` : "—"}</strong></div>
          <div><span>{t("wifi.snr")}</span><strong>{wifi?.snrDb != null ? `${wifi.snrDb} dB` : "—"}</strong></div>
          <div><span>{t("wifi.linkRate")}</span><strong>{wifi?.transmitRateMbps != null ? `${Math.round(wifi.transmitRateMbps)} Mbps` : "—"}</strong></div>
        </div>
      </section>
      <div className="wifi-devices-panel">
        <Neighbours wifiOnly />
      </div>
    </section>
  );
}

function DeviceTool() {
  const { t } = useI18n();
  const describe = useErrorText();
  const [target, setTarget] = useState("");
  const [profile, setProfile] = useState<DeviceProfile>("camera");
  const [running, setRunning] = useState(false);
  const [progress, setProgress] = useState<string | null>(null);
  const [report, setReport] = useState<DeviceReport | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    let dispose: (() => void) | null = null;
    void (async () => {
      try {
        const stop = await listen<[string, number]>("quick-check-device", (event) => {
          if (active) setProgress(t(`quickCheck.deviceProbing.${event.payload[0]}`, { port: String(event.payload[1]) }));
        });
        if (active) dispose = stop;
        else stop();
      } catch {
        // Progress text only; the report still arrives.
      }
    })();
    return () => { active = false; dispose?.(); };
  }, [t]);

  const run = async () => {
    const candidate = target.trim();
    if (!candidate || running) return;
    setRunning(true); setError(null); setReport(null); setProgress(null);
    try {
      setReport(await invoke<DeviceReport>("inspect_device", { target: candidate, profile }));
    } catch (failure) {
      setError(describe(failure));
    } finally { setRunning(false); setProgress(null); }
  };

  const openPage = async (port: number) => {
    try {
      await invoke("open_device_page", { target: target.trim(), port });
    } catch (failure) {
      setError(describe(failure));
    }
  };

  const openablePort = report?.ports.find(
    (entry) => entry.state === "open" && WEB_PORTS.includes(entry.port),
  );

  return (
    <>
      <Neighbours onPick={setTarget} />

      <div className="qc-profiles" role="radiogroup" aria-label={t("quickCheck.deviceProfileLabel")}>
        {PROFILES.map((entry) => (
          <button
            key={entry} type="button" role="radio" aria-checked={profile === entry}
            className={profile === entry ? "active" : ""} disabled={running}
            onClick={() => setProfile(entry)}
          >
            {t(`quickCheck.profile.${entry}`)}
          </button>
        ))}
      </div>
      <p className="qc-note">{t(`quickCheck.profileLede.${profile}`)}</p>

      <TargetForm
        value={target} onChange={setTarget} onSubmit={() => void run()} running={running}
        label={t("quickCheck.deviceTargetLabel")} placeholder={t("quickCheck.placeholder")}
        action={t("quickCheck.deviceRun")} busyAction={t("quickCheck.running")}
      />

      {running && progress ? <p className="qc-phase">{progress}</p> : null}
      {error ? <p className="error-text">{error}</p> : null}

      {report ? (
        <>
          <table className="qc-table qc-table-wide">
            <thead>
              <tr>
                <th>{t("quickCheck.colPort")}</th><th>{t("quickCheck.colService")}</th>
                <th>{t("quickCheck.colState")}</th><th>{t("quickCheck.colTime")}</th>
              </tr>
            </thead>
            <tbody>
              {report.ports.map((entry) => (
                <tr key={entry.port}>
                  <td>{entry.port}</td>
                  <td>{entry.service ?? "—"}</td>
                  <td><span className={`qc-pill qc-pill-${entry.state}`}>{t(`quickCheck.portState.${entry.state}`)}</span></td>
                  <td>{entry.elapsedMs.toFixed(0)} ms</td>
                </tr>
              ))}
            </tbody>
          </table>

          {report.rtsp.length > 0 ? (
            <div className="qc-rtsp">
              <h3>{t("quickCheck.rtspHeading")}</h3>
              {report.rtsp.map((entry) => (
                <div key={entry.port} className={`qc-rtsp-row qc-rtsp-${entry.state}`}>
                  <strong>{entry.port}</strong>
                  <span>{t(`quickCheck.rtspState.${entry.state}`)}</span>
                  {entry.server ? <em>{entry.server}</em> : null}
                  {entry.methods.length > 0 ? <span className="qc-rtsp-methods">{entry.methods.join(", ")}</span> : null}
                </div>
              ))}
            </div>
          ) : null}

          {openablePort ? (
            <div className="qc-presets">
              <button type="button" onClick={() => void openPage(openablePort.port)}>
                {t("quickCheck.openManagementPage", { port: String(openablePort.port) })}
              </button>
            </div>
          ) : null}

          <div className="qc-findings">
            <h3>{t("quickCheck.whatThisMeans")}</h3>
            <ul>{report.findings.map((finding) => <li key={finding}>{t(`quickCheck.deviceFinding.${finding}`)}</li>)}</ul>
          </div>
        </>
      ) : null}
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
  const [segment, setSegment] = useState<SegmentCheck | null>(null);
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
    setRunning(true); setError(null); setHops([]); setTrace(null); setSegment(null);
    try {
      setTrace(await invoke<Trace>("run_traceroute", { target: candidate, resolveNames: true }));
      // Packet size is a property of the same path, so it belongs with the hops.
      try {
        setSegment(await invoke<SegmentCheck>("check_segment_size", { target: candidate, port: 443 }));
      } catch {
        setSegment(null);
      }
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

      {segment && segment.mss !== null ? (
        <div className="qc-metrics">
          <Metric
            label={t("quickCheck.metricSegment")}
            value={`${segment.mss} B`}
            hint={t(`quickCheck.segmentVerdict.${segment.verdict}`)}
            tone={segment.verdict === "restricted" ? "warn" : undefined}
          />
        </div>
      ) : null}
      {segment && segment.verdict !== "standard" && segment.mss !== null ? (
        <div className="qc-findings">
          <ul>{segment.reasons.map((reason) => <li key={reason}>{t(`quickCheck.segmentReason.${reason}`)}</li>)}</ul>
        </div>
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

const SANDBOX_SAFE_TOOLS: Tool[] = ["ping", "port", "device", "route", "dns", "watch"];

/**
 * The destination for general network diagnostics.
 *
 * `deepReport` is the authorization-gated whole-path analysis. It lives here as
 * a tab rather than as another general-purpose network-check entry. Wi-Fi device
 * discovery has a separate workspace.
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
  const [clock, setClock] = useState<ClockCheck | null>(null);

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
    let active = true;
    void (async () => {
      try {
        const reading = await invoke<ClockCheck>("check_clock");
        if (active) setClock(reading);
      } catch {
        if (active) setClock(null);
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

      <Overview data={network} egress={egress} egressLoading={egressLoading} clock={clock} />

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
        {tool === "device" ? <DeviceTool /> : null}
        {tool === "route" ? <RouteTool /> : null}
        {tool === "dns" ? <DnsTool /> : null}
        {tool === "watch" ? <WatchTool /> : null}
        {tool === "deep" ? deepReport ?? null : null}
      </div>

      {tool === "deep" ? null : <p className="guardrail">{t("quickCheck.limits")}</p>}
    </section>
  );
}
