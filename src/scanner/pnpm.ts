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

function getPnpmOutdated(
  directory: string,
): Map<string, { wanted: string; latest: string }> {
  const output = runCommand("pnpm outdated --json", directory);
  if (!output.trim()) return new Map();

  try {
    const data = JSON.parse(output) as Record<
      string,
      { current?: string; wanted?: string; latest?: string }
    >;
    return new Map(
      Object.entries(data).map(([name, info]) => [
        name,
        {
          wanted: info.wanted ?? info.current ?? "0.0.0",
          latest: info.latest ?? info.current ?? "0.0.0",
        },
      ]),
    );
  } catch {
    return new Map();
  }
}

function getPnpmAudit(directory: string): RawAuditVulnerability[] {
  const output = runCommand("pnpm audit --json", directory);
  if (!output.trim()) return [];

  try {
    const data = JSON.parse(output) as {
      advisories?: Record<
        string,
        {
          module_name: string;
          severity: string;
          title: string;
          url: string;
          patched_versions: string;
        }
      >;
    };

    if (!data.advisories) return [];

    return Object.values(data.advisories).map((a) => ({
      name: a.module_name,
      severity: a.severity,
      title: a.title,
      url: a.url,
      range: a.patched_versions,
    }));
  } catch {
    return [];
  }
}

// ─── Public API ──────────────────────────────────────────────────────────────

export function scanWithPnpm(
  directory: string,
  options: { production: boolean; deep: boolean },
): RawScanData {
  const installed = getInstalledPackages(directory, options.production);
  const outdatedMap = getPnpmOutdated(directory);

  const outdated = installed.map((entry) => {
    const info = outdatedMap.get(entry.name);
    return info ? { ...entry, ...info } : entry;
  });

  const vulnerabilities = getPnpmAudit(directory);
  return { outdated, vulnerabilities };
}
