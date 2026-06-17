import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../", import.meta.url));
const workflowDirectory = join(root, ".github", "workflows");

for (const name of readdirSync(workflowDirectory).filter((file) => file.endsWith(".yml") || file.endsWith(".yaml"))) {
  const lines = readFileSync(join(workflowDirectory, name), "utf8").split("\n");
  let runIndent = null;
  for (const [index, line] of lines.entries()) {
    const indent = line.match(/^ */)?.[0].length ?? 0;
    if (runIndent !== null && line.trim() && indent <= runIndent) runIndent = null;
    if (/^\s*run:\s*\|/.test(line)) runIndent = indent;
    if (runIndent !== null && line.includes("${{")) {
      throw new Error(`${name}:${index + 1} directly interpolates a GitHub expression inside a shell block.`);
    }
    const action = line.match(/^\s*uses:\s*[^@\s]+@([^#\s]+)/)?.[1];
    if (action && !/^[0-9a-f]{40}$/.test(action)) {
      throw new Error(`${name}:${index + 1} uses an action that is not pinned to a full commit SHA.`);
    }
  }
}

console.log("GitHub workflow security check passed.");
