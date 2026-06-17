import { spawn } from "node:child_process";

const missingTranslationPattern = /Missing(?:\s+\S+)?\s+translation/i;
let output = "";

const child = spawn("npm", ["run", "check:core"], {
  cwd: process.cwd(),
  env: process.env,
  stdio: ["inherit", "pipe", "pipe"],
});

for (const stream of [child.stdout, child.stderr]) {
  stream.on("data", (chunk) => {
    const text = chunk.toString();
    output += text;
    stream === child.stdout ? process.stdout.write(chunk) : process.stderr.write(chunk);
  });
}

child.on("error", (error) => {
  console.error(`Unable to run release checks: ${error.message}`);
  process.exitCode = 1;
});

child.on("close", (code) => {
  if (missingTranslationPattern.test(output)) {
    console.error("Release check failed because a missing translation warning was emitted.");
    process.exitCode = 1;
    return;
  }
  process.exitCode = code ?? 1;
});
