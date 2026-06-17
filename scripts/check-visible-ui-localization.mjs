import { readFileSync } from "node:fs";

const source = readFileSync(new URL("../src/App.tsx", import.meta.url), "utf8");
const forbidden = [
  "Required before every real audit", "Local engine readiness", "Approved scripts",
  "I am authorized", "I understand", "Local-first engine", "Install or update",
  "Engine installed", "Script readiness", "nmap availability", "Latest lab folder",
  "Installed version", "Bundled version", "Review Authorization", "Fixed audit scope",
  "Eight approved steps", "No later step runs", "Local audit artifacts",
  "Latest audit workspace", "Local-first configuration", "No offensive testing",
];
const found = forbidden.filter((value) => source.includes(value));
if (found.length > 0) {
  console.error(`Visible UI localization check failed:\n${found.map((value) => `- ${value}`).join("\n")}`);
  process.exit(1);
}
console.log("Visible UI localization check passed.");
