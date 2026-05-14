import { Command } from "commander";
import { existsSync, readFileSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

function getVersion(): string {
  // Walk up from the compiled dist/ directory to find package.json
  const candidates = [
    join(__dirname, "..", "package.json"), // dist/ → root
    join(__dirname, "..", "..", "package.json"), // dist/cli/ → root
    join(__dirname, "package.json"),
  ];

  for (const p of candidates) {
    if (existsSync(p)) {
      try {
        const pkg = JSON.parse(readFileSync(p, "utf-8")) as {
          name?: string;
          version?: string;
        };
        if (
          (pkg.name === "@lbharath/depguard" || pkg.name === "depguard") &&
          pkg.version
        )
          return pkg.version;
      } catch {
        // continue
      }
    }
  }

  return "1.0.14";
}

export function createProgram(): Command {
  return new Command()
    .name("depguard")
    .description(
      "Universal dependency health scanner for JavaScript ecosystems",
    )
    .version(getVersion(), "-v, --version", "Output the current version");
}
