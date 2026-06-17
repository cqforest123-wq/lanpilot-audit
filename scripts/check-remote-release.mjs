import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../", import.meta.url));
const version = JSON.parse(readFileSync(join(root, "package.json"), "utf8")).version;
const tag = `v${version}`;
const report = join(root, "docs", "nightly", "v1.4.0-remote-release-check.md");
const temp = mkdtempSync(join(tmpdir(), "lanpilot-remote-release-"));
const results = [];
let failed = false;
const record = (status, name, detail) => { results.push({ status, name, detail }); if (status === "FAIL") failed = true; console.log(`[${status}] ${name}: ${detail}`); };
const view = spawnSync("gh", ["release", "view", tag, "--json", "url,isDraft,isPrerelease,assets"], { cwd: root, encoding: "utf8" });
if (view.status !== 0) {
  record("WARN", "GitHub release", `${tag} is not available yet; run again after publishing.`);
} else {
  const release = JSON.parse(view.stdout);
  record(release.isDraft ? "FAIL" : "PASS", "Draft state", release.isDraft ? "draft" : "published");
  record(release.isPrerelease ? "PASS" : "WARN", "Internal testing state", release.isPrerelease ? "pre-release" : "not marked pre-release");
  const assets = release.assets.map((asset) => asset.name);
  const dmg = assets.find((name) => name.endsWith(".dmg"));
  record(dmg ? "PASS" : "FAIL", "DMG asset", dmg ?? "missing");
  record(assets.includes("SHA256SUMS.txt") ? "PASS" : "FAIL", "SHA256SUMS asset", assets.includes("SHA256SUMS.txt") ? "present" : "missing");
  if (dmg && assets.includes("SHA256SUMS.txt")) {
    const download = spawnSync("gh", ["release", "download", tag, "--dir", temp], { cwd: root, encoding: "utf8" });
    record(download.status === 0 ? "PASS" : "FAIL", "Remote download", download.stderr.trim() || temp);
    if (download.status === 0) {
      const verify = spawnSync("/usr/bin/shasum", ["-a", "256", "-c", "SHA256SUMS.txt"], { cwd: temp, encoding: "utf8" });
      record(verify.status === 0 ? "PASS" : "FAIL", "Remote SHA-256", `${verify.stdout}${verify.stderr}`.trim());
    }
  }
  record("PASS", "Release URL", release.url);
}
mkdirSync(join(root, "docs", "nightly"), { recursive: true });
writeFileSync(report, `# v1.4.0 Remote Release Check

- Version: ${version}
- Command: \`npm run release:remote-check\`
- Checks: release state, pre-release state, DMG asset, SHA256SUMS asset, temporary remote download, and SHA-256 verification.
- Temporary downloads are removed after verification.
- Private repositories may not allow anonymous external downloads; repository visibility is not changed automatically.
- The command prints the current release URL and live PASS/WARN/FAIL results without storing volatile remote state in the repository.
`);
rmSync(temp, { recursive: true, force: true });
if (failed) process.exit(1);
