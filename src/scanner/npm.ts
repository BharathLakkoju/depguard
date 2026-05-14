import { execSync } from "child_process";
import { existsSync, readFileSync } from "fs";
import { join } from "path";
import type {
  RawScanData,
  RawOutdatedEntry,
  RawAuditVulnerability,
  DepType,
} from "../types/index.js";

// ─── Internal Types ───────────────────────────────────────────────────────────

interface NpmOutdatedEntry {
  current: string;
  wanted: string;
  latest: string;
}

interface NpmAuditV2 {
  auditReportVersion: 2;
  vulnerabilities: Record<
    string,
    {
      name: string;
      severity: string;
      via: Array<string | { title: string; url: string; severity: string }>;
      range: string;
      fixAvailable: boolean | { name: string; version: string };
    }
  >;
}

interface NpmAuditV1 {
  advisories: Record<
    string,
    {
      module_name: string;
      severity: string;
      title: string;
      url: string;
      patched_versions: string;
    }
  >;
}

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
    // npm outdated exits with code 1 when packages are out of date
    if (err && typeof err === "object" && "stdout" in err) {
      return String((err as { stdout: unknown }).stdout ?? "");
    }
    return "";
  }
}

/**
 * Read ALL declared dependency fields from package.json and resolve installed
 * versions from node_modules. Covers production, dev, optional and bundled.
 */
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

    // Packages explicitly declared as bundled
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

    // Deduplicate: bundled > optional > production > dev
    const seen = new Map<string, { spec: string; isDev: boolean }>();
    const add = (entries: [string, string][], isDev: boolean) => {
      for (const [name, spec] of entries) {
        if (!seen.has(name)) seen.set(name, { spec, isDev });
      }
    };
    // Add in priority order (bundled first via getDepType later, just deduplicate)
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
          // keep spec estimate
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

function getNpmOutdated(
  directory: string,
  production: boolean,
): Map<string, { wanted: string; latest: string }> {
  const flag = production ? " --omit=dev" : "";
  const output = runCommand(`npm outdated --json${flag}`, directory);
  if (!output.trim()) return new Map();

  try {
    const data = JSON.parse(output) as Record<string, NpmOutdatedEntry>;
    return new Map(
      Object.entries(data).map(([name, info]) => [
        name,
        {
          wanted: info.wanted ?? info.current,
          latest: info.latest ?? info.current,
        },
      ]),
    );
  } catch {
    return new Map();
  }
}

function getNpmAudit(
  directory: string,
  production: boolean,
): RawAuditVulnerability[] {
  const flag = production ? " --omit=dev" : "";
  const output = runCommand(`npm audit --json${flag}`, directory);
  if (!output.trim()) return [];

  try {
    const data = JSON.parse(output) as Partial<NpmAuditV2 & NpmAuditV1>;
    const vulns: RawAuditVulnerability[] = [];

    // npm v7+ (auditReportVersion: 2)
    if (data.vulnerabilities) {
      for (const [name, v] of Object.entries(data.vulnerabilities)) {
        vulns.push({
          name,
          severity: v.severity,
          range: v.range,
          via: v.via,
          fixAvailable: v.fixAvailable,
        });
      }
    }

    // npm v6 (advisories)
    if (data.advisories) {
      for (const a of Object.values(data.advisories)) {
        vulns.push({
          name: a.module_name,
          severity: a.severity,
          title: a.title,
          url: a.url,
          range: a.patched_versions,
        });
      }
    }

    return vulns;
  } catch {
    return [];
  }
}

// ─── Public API ──────────────────────────────────────────────────────────────

export function scanWithNpm(
  directory: string,
  options: { production: boolean; deep: boolean },
): RawScanData {
  const installed = getInstalledPackages(directory, options.production);
  const outdatedMap = getNpmOutdated(directory, options.production);

  const outdated = installed.map((entry) => {
    const info = outdatedMap.get(entry.name);
    return info ? { ...entry, ...info } : entry;
  });

  const vulnerabilities = getNpmAudit(directory, options.production);
  return { outdated, vulnerabilities };
}
