import { execSync } from "child_process";
import { existsSync, readFileSync } from "fs";
import { join } from "path";
import type { RawScanData, RawOutdatedEntry, DepType } from "../types/index.js";

// ─── Helpers ─────────────────────────────────────────────────────────────────

function runCommand(cmd: string, cwd: string): string {
  try {
    return execSync(cmd, {
      cwd,
      encoding: "utf-8",
      stdio: ["pipe", "pipe", "pipe"],
      timeout: 60_000,
    });
  } catch (err: unknown) {
    if (err && typeof err === "object" && "stdout" in err) {
      return String((err as { stdout: unknown }).stdout ?? "");
    }
    return "";
  }
}

function getInstalledPackages(
  directory: string,
  production: boolean,
): RawOutdatedEntry[] {
  const pkgPath = join(directory, "package.json");
  if (!existsSync(pkgPath)) return [];

  try {
    const pkg = JSON.parse(readFileSync(pkgPath, "utf-8")) as {
      dependencies?: Record<string, string>;
      devDependencies?: Record<string, string>;
      optionalDependencies?: Record<string, string>;
      bundleDependencies?: string[] | boolean;
      bundledDependencies?: string[] | boolean;
    };

    const rawBundled = pkg.bundleDependencies ?? pkg.bundledDependencies;
    const bundledSet = new Set<string>(
      Array.isArray(rawBundled) ? rawBundled : [],
    );
    const bundleAll = rawBundled === true;

    const getDepType = (name: string, isDev: boolean): DepType => {
      if (bundledSet.has(name) || bundleAll) return "bundled";
      if (name in (pkg.optionalDependencies ?? {})) return "optional";
      if (isDev) return "dev";
      return "production";
    };

    const seen = new Map<string, { spec: string; isDev: boolean }>();
    const add = (entries: [string, string][], isDev: boolean) => {
      for (const [name, spec] of entries) {
        if (!seen.has(name)) seen.set(name, { spec, isDev });
      }
    };
    add(Object.entries(pkg.dependencies ?? {}), false);
    add(Object.entries(pkg.optionalDependencies ?? {}), false);
    if (!production) add(Object.entries(pkg.devDependencies ?? {}), true);

    return Array.from(seen.entries()).map(([name, { spec, isDev }]) => {
      let current = spec.replace(/^[\^~>=<*]+/, "").split(/\s/)[0] ?? "0.0.0";
      const nmPkg = join(directory, "node_modules", name, "package.json");
      if (existsSync(nmPkg)) {
        try {
          const installed = JSON.parse(readFileSync(nmPkg, "utf-8")) as {
            version?: string;
          };
          current = installed.version ?? current;
        } catch {
          // keep estimate
        }
      }
      return {
        name,
        current,
        wanted: current,
        latest: current,
        isDev,
        depType: getDepType(name, isDev),
      };
    });
  } catch {
    return [];
  }
}

/**
 * Parse `bun outdated` text output.
 *
 * Bun v1.1+ prints a table like:
 *   package       current  update  latest
 *   react         18.2.0   18.3.1  19.0.0
 */
function getBunOutdated(directory: string): Map<string, { latest: string }> {
  const output = runCommand("bun outdated", directory);
  if (!output.trim()) return new Map();

  const map = new Map<string, { latest: string }>();

  for (const line of output.trim().split("\n")) {
    const trimmed = line.trim();

    // Skip header / separator / empty lines
    if (
      !trimmed ||
      trimmed.toLowerCase().startsWith("package") ||
      /^[-─]+/.test(trimmed)
    ) {
      continue;
    }

    // Split on 2+ whitespace — columns: name | current | update | latest
    const parts = trimmed.split(/\s{2,}/);
    if (parts.length >= 3) {
      const name = parts[0]?.trim();
      // "latest" is the 4th column; fall back to 3rd if missing
      const latest = (parts[3] ?? parts[2])?.trim();
      if (name && latest && !/^latest$/i.test(latest)) {
        map.set(name, { latest });
      }
    }
  }

  return map;
}

// ─── Public API ──────────────────────────────────────────────────────────────

export function scanWithBun(
  directory: string,
  options: { production: boolean; deep: boolean },
): RawScanData {
  const installed = getInstalledPackages(directory, options.production);
  const outdatedMap = getBunOutdated(directory);

  const outdated = installed.map((entry) => {
    const info = outdatedMap.get(entry.name);
    if (info) return { ...entry, latest: info.latest, wanted: info.latest };
    return entry;
  });

  // Bun doesn't have a built-in audit command yet.
  // Vulnerability data comes entirely from the OSV.dev enrichment step.
  return { outdated, vulnerabilities: [] };
}
