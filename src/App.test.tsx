import { cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import App from "./App";
import { I18nProvider, resolveLocale } from "./i18n";

const { invokeMock } = vi.hoisted(() => ({
  invokeMock: vi.fn(),
}));

vi.mock("@tauri-apps/api/core", () => ({
  invoke: invokeMock,
}));

vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn().mockResolvedValue(() => undefined),
}));

const engineStatus = {
  enginePath: "/Users/test/lanpilot-audit",
  engineFound: true,
  scriptsReady: true,
  missingScripts: [],
  nmapAvailable: true,
  latestLabExists: true,
  warnings: [],
  scripts: [],
};

const expectedSteps = [
  "init_lab",
  "baseline",
  "passive_assets",
  "client_isolation",
  "common_services",
  "smb_posture",
  "gateway_posture",
  "build_report",
  "local_network_config",
  "mdns_observation",
  "web_tls_baseline",
  "build_enhanced_governance_report",
  "build_formats",
];

afterEach(() => {
  cleanup();
  invokeMock.mockReset();
  localStorage.clear();
});

describe("audit authorization and failure flow", () => {
  it("stops after a failed step and requires fresh authorization before retry", async () => {
    const invokedSteps: string[] = [];
    invokeMock.mockImplementation((command: string) => {
      if (command === "check_engine") {
        return Promise.resolve(engineStatus);
      }
      if (command === "authorize_audit") {
        return Promise.resolve();
      }
      if (command === "list_audit_interfaces") {
        return Promise.resolve([{ name: "en0", ipv4: "192.168.50.10" }]);
      }
      if (command === "run_full_audit") {
        invokedSteps.push("init_lab", "baseline");
        return Promise.resolve({
          success: false,
          failedStepId: "baseline",
          steps: [
            { stepId: "init_lab", scriptName: "01-init-lab.sh", success: true, exitCode: 0, stdout: "", stderr: "", durationMs: 1 },
            { stepId: "baseline", scriptName: "02-baseline.sh", success: false, exitCode: 1, stdout: "", stderr: "baseline failed", durationMs: 1 },
          ],
        });
      }
      return Promise.reject(new Error(`Unexpected command: ${command}`));
    });

    const user = userEvent.setup();
    render(<App />);

    await user.click(screen.getByRole("button", { name: "Start Authorized Audit" }));
    await screen.findByText("Engine: Ready");

    const continueButton = screen.getByRole("button", { name: "Confirm Authorization" });
    expect(continueButton).toBeDisabled();

    await user.type(screen.getByLabelText(/Project name/), "Test audit");
    for (const checkbox of screen.getAllByRole("checkbox")) await user.click(checkbox);
    expect(continueButton).toBeEnabled();
    await user.click(continueButton);
    await user.click(screen.getByRole("button", { name: "Continue to Interface" }));
    await user.click(screen.getByRole("button", { name: "Continue to Run" }));
    const content = screen.getByRole("region", { name: "LANPilot Audit" });
    await user.click(within(content).getByRole("button", { name: "Run Full Audit" }));

    await screen.findByRole("button", { name: "Authorize New Run" });
    expect(invokedSteps).toEqual(["init_lab", "baseline"]);
    expect(screen.getByText("baseline failed")).toBeVisible();

    await user.click(screen.getByRole("button", { name: "Authorize New Run" }));
    await waitFor(() => expect(screen.getByRole("button", { name: "Confirm Authorization" })).toBeDisabled());
    expect(screen.getAllByRole("checkbox").every((checkbox) => !(checkbox as HTMLInputElement).checked)).toBe(true);
  });

  it("runs all fixed steps in order before enabling the report", async () => {
    const invokedSteps: string[] = [];
    invokeMock.mockImplementation((command: string) => {
      if (command === "check_engine") {
        return Promise.resolve(engineStatus);
      }
      if (command === "authorize_audit") {
        return Promise.resolve();
      }
      if (command === "list_audit_interfaces") {
        return Promise.resolve([{ name: "en0", ipv4: "192.168.50.10" }]);
      }
      if (command === "run_full_audit") {
        invokedSteps.push(...expectedSteps);
        return Promise.resolve({
          success: true,
          failedStepId: null,
          steps: expectedSteps.map((stepId) => ({
            stepId,
            scriptName: `${stepId}.sh`,
            success: true,
            exitCode: 0,
            stdout: `${stepId} complete`,
            stderr: "",
            durationMs: 1,
          })),
        });
      }
      if (command === "read_latest_report") {
        return Promise.resolve({
          executiveSummary: "Summary",
          technicalReport: "Technical",
          riskRegister: "",
          remediationRoadmap: "Roadmap",
          evidenceIndex: "Evidence",
          missingFiles: [],
          findings: [],
          summary: {
            highCount: 0,
            mediumCount: 0,
            lowCount: 0,
            reachableClients: null,
            unreachableClients: null,
            openServiceHosts: null,
            gatewayPostureStatus: null,
          },
        });
      }
      return Promise.reject(new Error(`Unexpected command: ${command}`));
    });

    const user = userEvent.setup();
    render(<App />);

    await user.click(screen.getByRole("button", { name: "Start Authorized Audit" }));
    await screen.findByText("Engine: Ready");
    await user.type(screen.getByLabelText(/Project name/), "Test audit");
    for (const checkbox of screen.getAllByRole("checkbox")) await user.click(checkbox);
    await user.click(screen.getByRole("button", { name: "Confirm Authorization" }));
    await user.click(screen.getByRole("button", { name: "Continue to Interface" }));
    await user.click(screen.getByRole("button", { name: "Continue to Run" }));

    const content = screen.getByRole("region", { name: "LANPilot Audit" });
    await user.click(within(content).getByRole("button", { name: "Run Full Audit" }));

    await screen.findByRole("button", { name: "View Report" });
    expect(invokedSteps).toEqual(expectedSteps);
    expect(screen.getAllByText("Success")).toHaveLength(13);
  });

  it("creates an export ZIP through the fixed backend command", async () => {
    invokeMock.mockImplementation((command: string) => {
      if (command === "export_latest_lab_zip") {
        return Promise.resolve({ zipPath: "/Users/test/Desktop/LANPilot-Audit-Exports/LANPilot-Audit-20260611-120000.zip" });
      }
      return Promise.resolve();
    });
    const user = userEvent.setup();
    render(<App />);

    await user.click(screen.getByRole("button", { name: "Export" }));
    const content = screen.getByRole("region", { name: "LANPilot Audit" });
    await user.click(within(content).getByRole("button", { name: "Export ZIP" }));

    expect(await screen.findByText(/LANPilot-Audit-20260611-120000.zip/)).toBeVisible();
    expect(invokeMock).toHaveBeenCalledWith("export_latest_lab_zip");
  });

  it("generates a fixed local remediation pack and requires authorization before retest", async () => {
    invokeMock.mockImplementation((command: string) => {
      if (command === "read_latest_report") return Promise.resolve(localizedReportFixture);
      if (command === "read_remediation_pack") return Promise.resolve(null);
      if (command === "save_remediation_pack") return Promise.resolve();
      return Promise.resolve();
    });
    const user = userEvent.setup();
    render(<App />);
    await user.click(screen.getByRole("button", { name: "Remediation" }));
    await user.click(await screen.findByRole("button", { name: "Generate Remediation Pack" }));
    expect(invokeMock).toHaveBeenCalledWith("save_remediation_pack", { pack: expect.objectContaining({ tickets: expect.any(Array) }) });
    await user.click(screen.getByRole("button", { name: "Enter Authorized Retest" }));
    expect(screen.getByRole("button", { name: "Confirm Authorization" })).toBeDisabled();
    expect(invokeMock.mock.calls.some(([command]) => command === "run_full_audit" || command === "run_audit_step")).toBe(false);
  });

  it("runs the fixed Network Reliability check only after local authorization", async () => {
    invokeMock.mockImplementation((command: string) => {
      if (command === "authorize_audit") return Promise.resolve();
      if (command === "run_network_reliability_check") return Promise.resolve(networkReliabilityFixture);
      if (command === "open_network_reliability_artifact") return Promise.resolve();
      return Promise.resolve(engineStatus);
    });
    const user = userEvent.setup();
    render(<App />);

    await user.click(screen.getByRole("button", { name: "Network Reliability" }));
    await user.type(screen.getByLabelText(/Project name/), "Reliability check");
    for (const checkbox of screen.getAllByRole("checkbox")) await user.click(checkbox);
    await user.click(screen.getByRole("button", { name: "Run Network Check" }));

    expect(await screen.findByText("Current network path")).toBeVisible();
    expect(screen.getAllByText("Mac -> en0 -> 192.0.2.1 -> ISP -> Internet").length).toBeGreaterThan(0);
    expect(invokeMock).toHaveBeenCalledWith("run_network_reliability_check");
    expect(invokeMock.mock.calls.some(([command]) => command === "run_full_audit" || command === "run_audit_step")).toBe(false);
  });
});

describe("localization", () => {
  it("falls back to English for an unsupported locale", () => {
    expect(resolveLocale("xx-YY")).toBe("en");
  });

  it.each([
    ["zh-CN", "一次授权流程"],
    ["zh-TW", "一次授權流程"],
    ["ja", "承認された一つの流れ"],
    ["ko", "승인된 하나의 흐름"],
  ])("switches the landing title for %s", async (locale, expected) => {
    localStorage.setItem("lanpilot.locale", locale);
    render(<I18nProvider><App /></I18nProvider>);
    expect(screen.getByRole("heading", { level: 1 }).textContent).toContain(expected);
  });

  it("keeps authorization form state when the language changes", async () => {
    invokeMock.mockResolvedValue(engineStatus);
    const user = userEvent.setup();
    render(<I18nProvider><App /></I18nProvider>);
    await user.click(screen.getByRole("button", { name: "Start Authorized Audit" }));
    await screen.findByText("Engine: Ready");
    await user.type(screen.getByLabelText(/Project name/), "Persistent project");
    await user.click(screen.getAllByRole("checkbox")[0]);
    await user.selectOptions(screen.getByRole("combobox", { name: "Language" }), "ja");
    expect(screen.getByDisplayValue("Persistent project")).toBeVisible();
    expect(screen.getAllByRole("checkbox")[0]).toBeChecked();
  });

  it("shows missing report files without crashing", async () => {
    invokeMock.mockResolvedValue({
      executiveSummary: null, technicalReport: null, riskRegister: null, remediationRoadmap: null, evidenceIndex: null,
      missingFiles: ["06-report/executive-summary.md"], findings: [],
      summary: { highCount: null, mediumCount: null, lowCount: null, reachableClients: null, unreachableClients: null, openServiceHosts: null, gatewayPostureStatus: null },
    });
    const user = userEvent.setup();
    render(<I18nProvider><App /></I18nProvider>);
    await user.click(screen.getByRole("button", { name: "Report" }));
    expect(await screen.findByText(/06-report\/executive-summary.md/)).toBeVisible();
    expect(screen.getAllByText("Unknown").length).toBeGreaterThan(0);
  });
});

const localizedReportFixture = {
  generatedAt: 1781240000,
  labDirectory: "/Users/test/lanpilot-audit-latest",
  executiveSummary: "This report summarizes authorized network governance observations.",
  technicalReport: "Raw technical report in English.",
  riskRegister: "severity,asset,category,finding,recommended_action,status\nHigh,192.168.50.248,SMB,SMB service is reachable from peer client network,Close SMB,open",
  remediationRoadmap: "Recommended action: close SMB.",
  evidenceIndex: "Raw evidence index.",
  missingFiles: [],
  findings: [
    { severity: "High", asset: "192.168.50.248", category: "SMB", finding: "SMB service is reachable from peer client network", recommended_action: "Close SMB", status: "open" },
    { severity: "High", asset: "192.168.50.248", category: "SMB", finding: "SMB service is reachable from peer client network", recommended_action: "Close SMB", status: "open" },
    { severity: "Low", asset: "192.168.50.88", category: "Web", finding: "Web service tcp/80 is reachable on a client asset", recommended_action: "Review web service", status: "open" },
    { severity: "Medium", asset: "192.168.50.90", category: "Remote", finding: "Remote administration service tcp/5900 is reachable", recommended_action: "Restrict remote administration", status: "open" },
  ],
  summary: { highCount: 2, mediumCount: 1, lowCount: 1, reachableClients: 14, unreachableClients: 2, openServiceHosts: 3, gatewayPostureStatus: "Services observed" },
};

const networkReliabilityFixture = {
  summary: {
    overallStatus: "healthy",
    physicalLanStatus: "healthy",
    dnsStatus: "healthy",
    overlayStatus: "healthy",
    externalPathStatus: "healthy",
    faultDomain: "none",
    faultPoint: "No clear fault point detected.",
    currentPath: "Mac -> en0 -> 192.0.2.1 -> ISP -> Internet",
    impact: "No immediate user-visible impact is indicated.",
    evidence: ["Gateway is reachable.", "External timing is normal."],
    remediationAdvice: ["Save this result as a baseline.", "Retest after path changes."],
    retestPlan: ["Run the same check after network changes."],
    rawEvidenceRefs: ["network-environment-evidence.json"],
  },
  evidence: {
    profile: "Home LAN",
    physicalLan: {
      activeInterface: "en0",
      interfaceKind: "wifi",
      ipv4: "192.0.2.20",
      dhcpOk: true,
      gatewayIp: "192.0.2.1",
      gatewayPingLossPct: 0,
      gatewayPingAvgMs: 3,
      gatewayDnsMs: 20,
      selfAssignedAddress: false,
    },
    localControlPlane: {
      systemDnsServers: ["192.0.2.1"],
      scopedResolvers: [],
      resolverSummary: "Gateway DNS",
      listeningServices: [],
    },
    overlay: {
      defaultRouteInterface: "en0",
      utunInterfaces: [],
      stashDetected: false,
      tailscaleRunning: false,
      multipleOverlayComponents: false,
      dnsViaOverlay: false,
    },
    external: {
      targets: [{ group: "apple", url: "https://www.apple.com", totalMs: 800, status: 200, failed: false }],
    },
    rawEvidenceRefs: ["network-environment-evidence.json"],
  },
  reportMarkdown: "# Network Reliability Report",
  supportBundlePath: "/Users/test/lanpilot-audit-latest/08-network-reliability/network-environment-redacted-support-bundle.zip",
  outputDirectory: "/Users/test/lanpilot-audit-latest/08-network-reliability",
};

describe("localized report view", () => {
  it("renders a fully localized Chinese main view, deduplicates findings, and preserves raw evidence", async () => {
    localStorage.setItem("lanpilot.locale", "zh-CN");
    invokeMock.mockResolvedValue(localizedReportFixture);
    const user = userEvent.setup();
    render(<I18nProvider><App /></I18nProvider>);

    await user.click(screen.getByRole("button", { name: "报告" }));
    expect(await screen.findByText("SMB 服务可从同一客户端网络位置访问。")).toBeVisible();
    expect(screen.getByText("客户端资产的 tcp/80 Web 服务可从当前网络位置访问。")).toBeVisible();
    expect(screen.getByText("远程管理服务 tcp/5900 可从当前网络位置访问。")).toBeVisible();
    expect(screen.getAllByText("SMB 服务可从同一客户端网络位置访问。")).toHaveLength(1);
    expect(document.querySelector(".roadmap-group")?.textContent).toContain("SMB 服务可从同一客户端网络位置访问。");
    expect(document.querySelector(".summary-card.high strong")).toHaveTextContent("1");
    expect(screen.queryByText(/This report summarizes/)).not.toBeInTheDocument();
    expect(screen.queryByText(/Recommended action: close SMB/)).not.toBeInTheDocument();
    expect(screen.queryByText("Risk Register")).not.toBeInTheDocument();

    await user.click(screen.getByRole("tab", { name: "原始证据" }));
    expect(screen.getByText(/This report summarizes authorized network governance observations/)).toBeVisible();
    expect(screen.getByText(/Recommended action: close SMB/)).toBeInTheDocument();
    expect(screen.getByText("原始证据按生成时的原文保留。")).toBeVisible();
  });

  it("updates the localized report to Japanese while raw evidence remains unchanged", async () => {
    localStorage.setItem("lanpilot.locale", "zh-CN");
    invokeMock.mockResolvedValue(localizedReportFixture);
    const user = userEvent.setup();
    render(<I18nProvider><App /></I18nProvider>);

    await user.click(screen.getByRole("button", { name: "报告" }));
    await screen.findByText("管理摘要");
    await user.selectOptions(screen.getByRole("combobox", { name: "语言" }), "ja");
    expect(screen.getByText("エグゼクティブサマリー")).toBeVisible();
    expect(screen.getByText("同一クライアントネットワーク位置から SMB サービスに到達できます。")).toBeVisible();
    expect(screen.queryByText("Risk Register")).not.toBeInTheDocument();

    await user.click(screen.getByRole("tab", { name: "原始証跡" }));
    expect(screen.getByText(/This report summarizes authorized network governance observations/)).toBeVisible();
  });
});

describe("full guided workflow localization", () => {
  it("keeps the Chinese authorization and engine pages free of English UI copy", async () => {
    localStorage.setItem("lanpilot.locale", "zh-CN");
    invokeMock.mockResolvedValue(engineStatus);
    const user = userEvent.setup();
    render(<I18nProvider><App /></I18nProvider>);

    await user.click(screen.getByRole("button", { name: "开始授权审计" }));
    await screen.findByText("本地引擎就绪状态");
    const authorizationText = screen.getByRole("region", { name: "LANPilot Audit" }).textContent ?? "";
    for (const forbidden of ["Required before every real audit", "Local engine readiness", "Engine: Ready", "Approved scripts", "I am authorized", "I understand", "Review Authorization"]) {
      expect(authorizationText).not.toContain(forbidden);
    }
    expect(authorizationText).toContain("nmap");
    expect(authorizationText).toContain("所选本地 IPv4 审计接口");

    await user.type(screen.getByLabelText(/项目名称/), "本地化测试");
    for (const checkbox of screen.getAllByRole("checkbox")) await user.click(checkbox);
    await user.click(screen.getByRole("button", { name: "确认授权" }));
    await screen.findByText("本地优先引擎");
    const engineText = screen.getByRole("region", { name: "LANPilot Audit" }).textContent ?? "";
    for (const forbidden of ["Local-first engine", "Install or update", "Engine installed", "Script readiness", "nmap availability", "Installed version", "Bundled version", "Review Authorization"]) {
      expect(engineText).not.toContain(forbidden);
    }
    expect(engineText).toContain("Application Support");
  });

  it.each([
    ["ja", "実際の監査前に毎回必要", "ローカル優先エンジン"],
    ["ko", "모든 실제 감사 전에 필요", "로컬 우선 엔진"],
  ])("does not fall back to English on %s authorization and engine pages", async (locale, authorizationHeading, engineHeading) => {
    localStorage.setItem("lanpilot.locale", locale);
    invokeMock.mockResolvedValue(engineStatus);
    const user = userEvent.setup();
    render(<I18nProvider><App /></I18nProvider>);
    await user.click(screen.getByRole("button", { name: locale === "ja" ? "承認済み監査を開始" : "승인 감사 시작" }));
    expect(await screen.findByText(authorizationHeading)).toBeVisible();
    await user.type(screen.getByLabelText(locale === "ja" ? /プロジェクト名/ : /프로젝트 이름/), "test");
    for (const checkbox of screen.getAllByRole("checkbox")) await user.click(checkbox);
    await user.click(screen.getByRole("button", { name: locale === "ja" ? "承認を確認" : "승인 확인" }));
    expect(await screen.findByText(engineHeading)).toBeVisible();
  });
});
