import { createHash } from "node:crypto";
import { copyFileSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../", import.meta.url));
const version = JSON.parse(readFileSync(join(root, "package.json"), "utf8")).version;
const dmgName = `LANPilot Audit_${version}_aarch64.dmg`;
const sourceDmg = join(root, "src-tauri", "target", "release", "bundle", "dmg", dmgName);
const website = join(root, "release", "website");
const downloads = join(website, "downloads");
const outputDmg = join(downloads, dmgName);
const checksum = createHash("sha256").update(readFileSync(sourceDmg)).digest("hex");

const style = `<style>
body{font:16px system-ui;max-width:900px;margin:48px auto;padding:20px;line-height:1.65;color:#182433}
nav{display:flex;gap:18px;flex-wrap:wrap;margin-bottom:36px}a{color:#075f7a}.button{display:inline-block;background:#126a88;color:white;padding:12px 18px;border-radius:7px;text-decoration:none}
h1,h2{line-height:1.2}section{border-top:1px solid #d9e1e5;padding-top:18px;margin-top:30px}code{word-break:break-all;background:#eef3f5;padding:2px 5px}pre{overflow:auto;background:#eef3f5;padding:14px}
.notice{border-left:4px solid #be7b00;padding:8px 14px;background:#fff8e8}.good{border-left-color:#20734b;background:#edf8f2}
</style>`;
const nav = `<nav><a href="index.html">Download</a><a href="faq.html">FAQ</a><a href="privacy.html">Privacy</a><a href="release-notes.html">Release notes</a><a href="SHA256SUMS.txt">Checksums</a></nav>`;
const page = (title, content) => `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>${title}</title>${style}${nav}${content}</html>`;

rmSync(website, { recursive: true, force: true });
mkdirSync(downloads, { recursive: true });
copyFileSync(sourceDmg, outputDmg);
writeFileSync(join(website, "SHA256SUMS.txt"), `${checksum}  downloads/${dmgName}\n`);

writeFileSync(join(website, "index.html"), page(`LANPilot Audit ${version}`, `<h1>LANPilot Audit ${version}</h1>
<p>Authorized LAN governance and exposure assessment for small-business networks.</p>
<p><a class="button" href="downloads/${encodeURIComponent(dmgName)}">Download for Apple silicon</a></p>
<p class="notice"><strong>Internal testing build.</strong> This build is ad-hoc signed, not notarized, and Apple Developer ID signing is pending. macOS may show a security warning. Verify the SHA-256 checksum before opening it.</p>

<section><h2>Download instructions</h2>
<p><strong>English:</strong> Download the DMG, verify its SHA-256 checksum, open it, and drag LANPilot Audit to Applications.</p>
<p><strong>简体中文：</strong> 下载 DMG，验证 SHA-256 校验值，打开后将 LANPilot Audit 拖入“应用程序”。</p>
<p><strong>日本語：</strong> DMG をダウンロードし、SHA-256 を確認してから開き、LANPilot Audit を Applications に移動してください。</p>
<p><strong>한국어:</strong> DMG를 다운로드하고 SHA-256을 확인한 뒤 열어서 LANPilot Audit를 Applications로 이동하세요.</p></section>

<section><h2>macOS security warning</h2>
<p><strong>English:</strong> The warning appears because this internal build is not yet Developer ID signed or notarized. After verifying SHA-256, use Finder's Open action for authorized internal testing. A formally signed and notarized build will reduce these warnings.</p>
<p><strong>简体中文：</strong> 当前内部测试版尚未完成 Developer ID 签名和公证，因此会出现安全警告。验证 SHA-256 后，可在 Finder 中使用“打开”进行授权内部测试。正式签名公证后，警告会减少。</p>
<p><strong>日本語：</strong> この内部テスト版は Developer ID 署名および公証が未完了のため、警告が表示されます。SHA-256 を確認後、Finder の「開く」から承認済み内部テストに使用してください。</p>
<p><strong>한국어:</strong> 이 내부 테스트 빌드는 Developer ID 서명 및 공증이 완료되지 않아 경고가 표시됩니다. SHA-256 확인 후 Finder의 열기를 사용해 승인된 내부 테스트를 진행하세요.</p></section>

<section><h2>Verify SHA-256</h2>
<pre>cd ~/Downloads
shasum -a 256 "LANPilot Audit_${version}_aarch64.dmg"</pre>
<p>Expected value: <code>${checksum}</code></p></section>

<section><h2>Governance capabilities</h2>
<ul><li>Asset Inventory</li><li>Service Exposure Matrix</li><li>Local Network Config</li><li>mDNS Observation</li><li>Web/TLS Baseline</li><li>Snapshot Compare</li><li>Remediation Tracking</li></ul></section>

<section><h2>Local-first safety boundary</h2>
<ul><li>No cloud upload of audit evidence.</li><li>No credential testing.</li><li>No unauthorized login.</li><li>No configuration changes.</li><li>Checks run only after explicit authorization through a fixed allowlisted workflow.</li></ul></section>`));

writeFileSync(join(website, "faq.html"), page("LANPilot Audit FAQ", `<h1>FAQ</h1>
<section><h2>Why does macOS show a warning?</h2><p>This readiness build is not yet Developer ID signed or notarized. Confirm the checksum and use it only in an authorized environment.</p></section>
<section><h2>Does LANPilot Audit upload reports?</h2><p>No. Audit evidence and reports remain on your Mac. ZIP export is initiated by the user.</p></section>
<section><h2>Does it test credentials or log in to devices?</h2><p>No. It performs no credential testing and no unauthorized login.</p></section>
<section><h2>Does it change network configuration?</h2><p>No. It reports observations, risks, recommendations, and retest methods without changing devices or clients.</p></section>`));

writeFileSync(join(website, "privacy.html"), page("LANPilot Audit Privacy", `<h1>Privacy</h1>
<p class="good">LANPilot Audit is local-first and does not upload audit evidence, reports, logs, or exports to cloud services.</p>
<ul><li>Audit data is stored on the user's Mac.</li><li>The user controls ZIP export.</li><li>No credential testing or unauthorized login.</li><li>No network configuration changes.</li></ul>`));

writeFileSync(join(website, "release-notes.html"), page(`LANPilot Audit ${version} Release Notes`, `<h1>LANPilot Audit ${version}</h1>
<p>Internal QA and release-hardening update for the governance toolbox, localized views, installed-app validation, fixture coverage, security boundary checks, and remote release verification.</p>
<p>Authorization controls and the existing safety boundary remain unchanged.</p>
<p>Distribution status: ad-hoc signed, not notarized, internal testing build. Developer ID signing is pending.</p>`));

console.log(`Website release: ${website}`);
