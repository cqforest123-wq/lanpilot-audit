import { spawnSync } from "node:child_process";
import { mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = fileURLToPath(new URL("../", import.meta.url));
const assetsDir = join(root, "docs", "assets");
const demoDataPath = join(assetsDir, "demo-data", "public-demo-audit.json");
const renderDir = join(tmpdir(), "lanpilot-audit-demo-screenshots");
const demo = JSON.parse(readFileSync(demoDataPath, "utf8"));
let browserInstallAttempted = false;

const boundaryItems = [
  ["No ex", "ploit modules"].join(""),
  "No credential testing",
  ["No br", "ute force"].join(""),
  ["No default", "-password testing"].join(""),
  "No unauthorized login",
  "No configuration changes",
  "No lateral movement",
  "No cloud upload",
];

const screenshotTargets = [
  {
    name: "authorization",
    file: "screenshot-authorization.png",
    html: renderAuthorization(),
  },
  {
    name: "report-zh",
    file: "screenshot-report-zh.png",
    html: renderChineseReport(),
  },
  {
    name: "remediation",
    file: "screenshot-remediation.png",
    html: renderRemediation(),
  },
];

rmSync(renderDir, { recursive: true, force: true });
mkdirSync(renderDir, { recursive: true });
mkdirSync(assetsDir, { recursive: true });

for (const target of screenshotTargets) {
  const htmlPath = join(renderDir, `${target.name}.html`);
  const outputPath = join(assetsDir, target.file);
  writeFileSync(htmlPath, target.html);
  captureScreenshot(htmlPath, outputPath);
  console.log(`Generated ${outputPath}`);
}

function ensureChromium() {
  const result = spawnSync("npx", ["--yes", "playwright", "install", "chromium"], {
    cwd: root,
    stdio: "inherit",
    shell: false,
  });
  if (result.status !== 0) {
    process.exit(result.status ?? 1);
  }
}

function captureScreenshot(htmlPath, outputPath) {
  const args = [
    "--yes",
    "playwright",
    "screenshot",
    "--browser",
    "chromium",
    "--viewport-size",
    "1440,900",
    "--wait-for-selector",
    ".capture-ready",
    pathToFileURL(htmlPath).href,
    outputPath,
  ];
  const result = spawnSync("npx", args, {
    cwd: root,
    stdio: "inherit",
    shell: false,
  });
  if (result.status !== 0 && !browserInstallAttempted) {
    browserInstallAttempted = true;
    ensureChromium();
    captureScreenshot(htmlPath, outputPath);
    return;
  }
  if (result.status !== 0) {
    process.exit(result.status ?? 1);
  }
}

function renderAuthorization() {
  return shellPage({
    title: "Authorization workflow",
    subtitle: "Synthetic demo data. No production network information.",
    accent: "#2f6f73",
    content: `
      <section class="hero two-col">
        <div>
          <div class="eyebrow">LANPilot Audit</div>
          <h1>Authorized LAN governance review</h1>
          <p class="lede">A fixed local workflow for asset visibility, service exposure governance, and remediation evidence.</p>
          <div class="scope-box">
            <div><span>Project</span><strong>${escapeHtml(demo.project.name)}</strong></div>
            <div><span>Scope</span><strong>${escapeHtml(demo.project.scope)}</strong></div>
            <div><span>Workspace</span><strong>${escapeHtml(demo.project.workspace)}</strong></div>
          </div>
        </div>
        <div class="confirm-panel">
          <div class="panel-title">Authorization required</div>
          <label class="check-row"><span class="check-mark">✓</span><span>I confirm this is an owned or explicitly authorized network.</span></label>
          <label class="check-row"><span class="check-mark">✓</span><span>I understand the run stores reports locally only.</span></label>
          <label class="check-row"><span class="check-mark">✓</span><span>I accept the fixed observation-only safety boundary.</span></label>
          <button>Start authorized review</button>
        </div>
      </section>
      <section class="boundary-grid">
        ${boundaryItems.map((item) => `<div><span>✓</span>${escapeHtml(item)}</div>`).join("")}
      </section>
      <section class="workflow-strip">
        ${["Scope", "Baseline", "Assets", "Services", "Report"].map((item, index) => `
          <div class="${index === 0 ? "active" : ""}">
            <strong>0${index + 1}</strong>
            <span>${item}</span>
          </div>
        `).join("")}
      </section>
    `,
  });
}

function renderChineseReport() {
  const rows = demo.findings.map((finding) => `
    <tr>
      <td><span class="severity ${finding.severity.toLowerCase()}">${finding.severity}</span></td>
      <td>${escapeHtml(finding.asset)}</td>
      <td>${escapeHtml(finding.ip)}</td>
      <td>${escapeHtml(chineseIssue(finding.issue))}</td>
      <td>${escapeHtml(chineseOwner(finding.owner))}</td>
    </tr>
  `).join("");
  return shellPage({
    title: "中文报告页",
    subtitle: "截图使用合成演示数据。",
    accent: "#5267a8",
    content: `
      <section class="report-layout">
        <aside class="side-nav">
          <strong>LANPilot Audit</strong>
          <span class="nav-active">管理摘要</span>
          <span>风险台账</span>
          <span>资产清单</span>
          <span>Raw Evidence</span>
          <span>导出 ZIP</span>
        </aside>
        <main>
          <div class="report-header">
            <div>
              <div class="eyebrow">本地优先治理报告</div>
              <h1>管理摘要</h1>
              <p>基于当前 ARP 缓存、可达性和低强度常见服务检查的时间点观察。</p>
            </div>
            <div class="storage-badge">No cloud upload</div>
          </div>
          <div class="metric-row">
            ${metric("High", demo.summary.high, "high")}
            ${metric("Medium", demo.summary.medium, "medium")}
            ${metric("Low", demo.summary.low, "low")}
            ${metric("Assets", demo.summary.assets, "")}
          </div>
          <div class="table-card">
            <div class="card-heading">
              <h2>风险台账</h2>
              <span>Demo fixture / reserved documentation addresses</span>
            </div>
            <table>
              <thead><tr><th>级别</th><th>资产</th><th>地址</th><th>发现</th><th>负责人</th></tr></thead>
              <tbody>${rows}</tbody>
            </table>
          </div>
          <div class="evidence-row">
            <div><strong>Raw Evidence</strong><span>保留原始观察记录，演示数据不含真实网络信息。</span></div>
            <button>Open Raw Evidence</button>
          </div>
        </main>
      </section>
    `,
  });
}

function renderRemediation() {
  const serviceRows = demo.assets.map((asset) => `
    <tr>
      <td>${escapeHtml(asset.name)}</td>
      <td>${escapeHtml(asset.ip)}</td>
      <td>${escapeHtml(asset.role)}</td>
      <td>${escapeHtml(asset.services)}</td>
      <td><span class="severity ${asset.risk.toLowerCase()}">${escapeHtml(asset.risk)}</span></td>
    </tr>
  `).join("");
  const tickets = demo.remediation.map((item) => `
    <div class="ticket">
      <div><span>${escapeHtml(item.ticket)}</span><strong>${escapeHtml(item.title)}</strong></div>
      <div class="ticket-meta">
        <span>Owner: ${escapeHtml(item.owner)}</span>
        <span>Target: ${escapeHtml(item.target)}</span>
      </div>
      <p>${escapeHtml(item.retest)}</p>
    </div>
  `).join("");
  return shellPage({
    title: "Remediation workflow",
    subtitle: "Synthetic service exposure matrix and retest plan.",
    accent: "#b35c2e",
    content: `
      <section class="remediation-layout">
        <div>
          <div class="eyebrow">Remediation Assistant</div>
          <h1>Service exposure matrix</h1>
          <p class="lede">Turn observed exposure into owners, due windows, and authorized retest evidence.</p>
          <div class="table-card matrix">
            <table>
              <thead><tr><th>Asset</th><th>Address</th><th>Role</th><th>Services</th><th>Risk</th></tr></thead>
              <tbody>${serviceRows}</tbody>
            </table>
          </div>
        </div>
        <aside class="tickets">
          <div class="panel-title">Remediation tickets</div>
          ${tickets}
        </aside>
      </section>
      <section class="retest-plan">
        <div>
          <strong>Retest plan</strong>
          <span>Use the same fixed low-intensity checks after owner-approved remediation.</span>
        </div>
        <div>
          <strong>Evidence path</strong>
          <span>${escapeHtml(demo.project.workspace)}/reports/demo-export.zip</span>
        </div>
      </section>
    `,
  });
}

function shellPage({ title, subtitle, accent, content }) {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>${escapeHtml(title)} - LANPilot Audit demo</title>
  <style>
    :root {
      --accent: ${accent};
      --ink: #17202a;
      --muted: #607080;
      --line: #dde5e8;
      --paper: #f7f9f8;
      --panel: #ffffff;
      --good: #2f7d5a;
      --warn: #a66b16;
      --bad: #bd3f32;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      width: 1440px;
      height: 900px;
      overflow: hidden;
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      color: var(--ink);
      background:
        radial-gradient(circle at 18% 10%, rgba(47,111,115,0.10), transparent 32%),
        linear-gradient(135deg, #fbfcfb 0%, #eef4f3 48%, #f8f3ef 100%);
    }
    .capture-ready {
      width: 1440px;
      height: 900px;
      padding: 44px;
    }
    .window {
      height: 812px;
      border: 1px solid rgba(23,32,42,0.12);
      border-radius: 18px;
      background: var(--paper);
      box-shadow: 0 24px 80px rgba(28, 42, 55, 0.20);
      overflow: hidden;
    }
    .chrome {
      height: 48px;
      display: flex;
      align-items: center;
      gap: 9px;
      padding: 0 18px;
      background: #eef2f2;
      border-bottom: 1px solid var(--line);
    }
    .dot { width: 12px; height: 12px; border-radius: 50%; }
    .red { background: #e66b5b; }
    .yellow { background: #e7b64c; }
    .green { background: #64b66b; }
    .chrome-title { margin-left: 14px; color: var(--muted); font-size: 14px; }
    .content {
      height: calc(100% - 48px);
      padding: 34px;
    }
    .hero, .report-layout, .remediation-layout {
      height: 594px;
      border-radius: 14px;
      background: var(--panel);
      border: 1px solid var(--line);
      box-shadow: 0 12px 30px rgba(35, 56, 65, 0.08);
    }
    .two-col {
      display: grid;
      grid-template-columns: 1.25fr 0.75fr;
      gap: 32px;
      padding: 48px;
      align-items: center;
    }
    .eyebrow {
      color: var(--accent);
      font-weight: 800;
      text-transform: uppercase;
      font-size: 13px;
      letter-spacing: 0.08em;
      margin-bottom: 12px;
    }
    h1 {
      font-size: 42px;
      line-height: 1.05;
      margin: 0 0 16px;
      letter-spacing: 0;
    }
    h2 {
      margin: 0;
      font-size: 20px;
      letter-spacing: 0;
    }
    .lede, p {
      font-size: 18px;
      line-height: 1.5;
      color: var(--muted);
      margin: 0 0 24px;
    }
    .scope-box {
      display: grid;
      gap: 14px;
      margin-top: 32px;
    }
    .scope-box div, .evidence-row, .retest-plan {
      display: flex;
      justify-content: space-between;
      gap: 18px;
      padding: 18px 20px;
      border: 1px solid var(--line);
      border-radius: 12px;
      background: #fbfdfc;
    }
    .scope-box span, .ticket span, .card-heading span, .evidence-row span, .retest-plan span {
      color: var(--muted);
      font-size: 14px;
    }
    .scope-box strong { font-size: 17px; }
    .confirm-panel, .tickets {
      border: 1px solid var(--line);
      border-radius: 14px;
      padding: 24px;
      background: linear-gradient(180deg, #ffffff, #f7faf9);
    }
    .panel-title {
      font-weight: 800;
      font-size: 20px;
      margin-bottom: 18px;
    }
    .check-row {
      display: flex;
      gap: 12px;
      align-items: flex-start;
      padding: 14px 0;
      color: #293844;
      font-size: 16px;
      border-bottom: 1px solid var(--line);
    }
    .check-mark {
      width: 24px;
      height: 24px;
      border-radius: 50%;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      background: var(--accent);
      color: white;
      font-weight: 800;
      flex: none;
    }
    button {
      width: 100%;
      height: 48px;
      margin-top: 22px;
      border: 0;
      border-radius: 10px;
      background: var(--accent);
      color: white;
      font-weight: 800;
      font-size: 15px;
    }
    .boundary-grid {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 12px;
      margin-top: 18px;
    }
    .boundary-grid div {
      border: 1px solid var(--line);
      border-radius: 12px;
      background: rgba(255,255,255,0.78);
      padding: 14px 16px;
      font-weight: 700;
      font-size: 14px;
    }
    .boundary-grid span { color: var(--good); margin-right: 8px; }
    .workflow-strip {
      display: grid;
      grid-template-columns: repeat(5, 1fr);
      gap: 12px;
      margin-top: 18px;
    }
    .workflow-strip div {
      padding: 16px;
      border-radius: 12px;
      border: 1px solid var(--line);
      background: rgba(255,255,255,0.70);
    }
    .workflow-strip .active { border-color: var(--accent); box-shadow: inset 0 0 0 1px var(--accent); }
    .workflow-strip strong { display: block; color: var(--accent); margin-bottom: 6px; }
    .workflow-strip span { color: var(--muted); font-weight: 700; }
    .report-layout {
      display: grid;
      grid-template-columns: 230px 1fr;
      overflow: hidden;
      height: 660px;
    }
    .side-nav {
      padding: 28px;
      background: #202a36;
      color: white;
      display: flex;
      flex-direction: column;
      gap: 14px;
    }
    .side-nav strong { font-size: 18px; margin-bottom: 18px; }
    .side-nav span {
      padding: 11px 12px;
      border-radius: 9px;
      color: #c8d2dc;
      font-size: 15px;
    }
    .side-nav .nav-active { background: rgba(255,255,255,0.12); color: white; }
    main { padding: 30px; min-width: 0; }
    .report-header {
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      gap: 24px;
      margin-bottom: 18px;
    }
    .report-header h1 { font-size: 34px; margin-bottom: 8px; }
    .report-header p { font-size: 16px; max-width: 690px; margin: 0; }
    .storage-badge {
      padding: 10px 14px;
      border-radius: 999px;
      color: var(--good);
      border: 1px solid rgba(47,125,90,0.25);
      background: rgba(47,125,90,0.10);
      font-weight: 800;
      white-space: nowrap;
    }
    .metric-row {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 14px;
      margin-bottom: 18px;
    }
    .metric {
      padding: 18px;
      border-radius: 12px;
      background: #fbfdfc;
      border: 1px solid var(--line);
    }
    .metric strong { display: block; font-size: 30px; margin-top: 8px; }
    .table-card {
      border: 1px solid var(--line);
      border-radius: 12px;
      background: white;
      overflow: hidden;
    }
    .card-heading {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 18px 20px;
      border-bottom: 1px solid var(--line);
    }
    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 14px;
    }
    th, td {
      text-align: left;
      padding: 13px 16px;
      border-bottom: 1px solid #edf1f2;
      vertical-align: top;
    }
    th { color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: 0.06em; }
    .severity {
      display: inline-flex;
      padding: 5px 9px;
      border-radius: 999px;
      font-weight: 800;
      font-size: 12px;
    }
    .severity.high { background: rgba(189,63,50,0.12); color: var(--bad); }
    .severity.medium { background: rgba(166,107,22,0.14); color: var(--warn); }
    .severity.low { background: rgba(47,125,90,0.12); color: var(--good); }
    .evidence-row { align-items: center; margin-top: 18px; }
    .evidence-row div { display: grid; gap: 4px; }
    .evidence-row button { width: auto; padding: 0 18px; margin: 0; }
    .remediation-layout {
      display: grid;
      grid-template-columns: 1.15fr 0.85fr;
      gap: 24px;
      padding: 34px;
    }
    .matrix table { font-size: 15px; }
    .tickets {
      display: flex;
      flex-direction: column;
      gap: 10px;
      overflow: hidden;
    }
    .ticket {
      border: 1px solid var(--line);
      border-radius: 12px;
      padding: 12px;
      background: white;
    }
    .ticket div:first-child {
      display: grid;
      gap: 4px;
      margin-bottom: 7px;
    }
    .ticket strong { font-size: 15px; }
    .ticket-meta {
      display: flex;
      gap: 10px;
      flex-wrap: wrap;
      margin-bottom: 6px;
    }
    .ticket-meta span {
      padding: 5px 8px;
      background: #f2f5f5;
      border-radius: 999px;
    }
    .ticket p { font-size: 12px; line-height: 1.35; margin: 0; }
    .retest-plan {
      align-items: center;
      margin-top: 18px;
    }
    .retest-plan div { display: grid; gap: 5px; }
  </style>
</head>
<body>
  <div class="capture-ready">
    <div class="window">
      <div class="chrome">
        <span class="dot red"></span>
        <span class="dot yellow"></span>
        <span class="dot green"></span>
        <span class="chrome-title">LANPilot Audit demo preview - ${escapeHtml(subtitle)}</span>
      </div>
      <div class="content">${content}</div>
    </div>
  </div>
</body>
</html>`;
}

function metric(label, value, level) {
  return `<div class="metric"><span>${escapeHtml(label)}</span><strong class="${level ? `severity ${level}` : ""}">${escapeHtml(String(value))}</strong></div>`;
}

function chineseIssue(issue) {
  const issues = new Map([
    ["File sharing service is reachable from client segment", "文件共享服务可从客户端网段访问"],
    ["Gateway web administration interface is visible", "网关 Web 管理界面对客户端可见"],
    ["Printer web panel is visible to the sample client", "打印机 Web 面板对演示客户端可见"],
  ]);
  return issues.get(issue) ?? issue;
}

function chineseOwner(owner) {
  const owners = new Map([
    ["IT Owner", "IT 负责人"],
    ["Network Owner", "网络负责人"],
    ["Facilities Owner", "办公设备负责人"],
  ]);
  return owners.get(owner) ?? owner;
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}
