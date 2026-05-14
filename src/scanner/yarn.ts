import { execSync } from "child_process";
import { existsSync, readFileSync } from "fs";
import { join } from "path";
import type {
  RawScanData,
  RawOutdatedEntry,
  RawAuditVulnerability,
  DepType,
} from "../types/index.js";

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

/** Detect whether this is a Yarn Berry (v2+) project. */
function isYarnBerry(directory: string): boolean {
  if (existsSync(join(directory, ".yarnrc.yml"))) return true;
  const pkgPath = join(directory, "package.json");
  if (existsSync(pkgPath)) {
    try {
      const pkg = JSON.parse(readFileSync(pkgPath, "utf-8")) as {
        packageManager?: string;
      };
      if (pkg.packageManager?.startsWith("yarn@")) {
        const major = parseInt(
          pkg.packageManager.split("@")[1].split(".")[0] ?? "1",
          10,
        );
        return major >= 2;
      }
    } catch {
      // ignore
    }
  }
  return false;
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
      packageManager?: string;
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

/** Parse Yarn v1 JSONL output from `yarn outdated --json` */
function getYarnV1Outdated(
  directory: string,
): Map<string, { wanted: string; latest: string }> {
  const output = runCommand("yarn outdated --json", directory);
  if (!output.trim()) return new Map();

  const map = new Map<string, { wanted: string; latest: string }>();

  for (const line of output.trim().split("\n")) {
    try {
      const obj = JSON.parse(line) as {
        type: string;
        data: { head: string[]; body: string[][] };
      };
      if (obj.type === "table" && Array.isArray(obj.data.body)) {
        // head: ["Package","Current","Wanted","Latest","Package Type","URL"]
        for (const row of obj.data.body) {
          const [name, , wanted, latest] = row;
          if (name && wanted && latest) map.set(name, { wanted, latest });
        }
      }
    } catch {
      // skip malformed lines
    }
  }

  return map;
}

/** Best-effort outdated detection for Yarn Berry */
function getYarnBerryOutdated(
  directory: string,
): Map<string, { wanted: string; latest: string }> {
  // `yarn npm info` can give us registry info per package but that's slow.
  // The most reliable cross-version approach is `yarn upgrade-interactive`
  // with a dry-run flag, which isn't trivial to parse.
  // For now return an empty map; OSV + deprecation checks still apply.
  void directory;
  return new Map();
}

function getYarnAudit(directory: string): RawAuditVulnerability[] {
  const output = runCommand("yarn audit --json", directory);
  if (!output.trim()) return [];

  const vulns: RawAuditVulnerability[] = [];

  for (const line of output.trim().split("\n")) {
    try {
      const obj = JSON.parse(line) as {
        type: string;
        data: {
          advisory?: {
            module_name: string;
            severity: string;
            title: string;
            url: string;
            patched_versions: string;
          };
        };
      };
      if (obj.type === "auditAdvisory" && obj.data.advisory) {
        const a = obj.data.advisory;
        vulns.push({
          name: a.module_name,
          severity: a.severity,
          title: a.title,
          url: a.url,
          range: a.patched_versions,
        });
      }
    } catch {
      // skip
    }
  }

  return vulns;
}

// ─── Public API ──────────────────────────────────────────────────────────────

export function scanWithYarn(
  directory: string,
  options: { production: boolean; deep: boolean },
): RawScanData {
  const berry = isYarnBerry(directory);
  const installed = getInstalledPackages(directory, options.production);
  const outdatedMap = berry
    ? getYarnBerryOutdated(directory)
    : getYarnV1Outdated(directory);

  const outdated = installed.map((entry) => {
    const info = outdatedMap.get(entry.name);
    return info ? { ...entry, ...info } : entry;
  });

  const vulnerabilities = getYarnAudit(directory);
  return { outdated, vulnerabilities };
}
