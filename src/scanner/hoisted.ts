import { existsSync, readFileSync, readdirSync } from "fs";
import { join } from "path";
import type {
  HoistedDepIssue,
  RawAuditVulnerability,
  Vulnerability,
  Severity,
} from "../types/index.js";
import { normalizeSeverity } from "../normalizer/index.js";

const SEV_ORDER: Record<string, number> = {
  critical: 0,
  high: 1,
  moderate: 2,
  low: 3,
};

// ─── Public API ───────────────────────────────────────────────────────────────

/**
 * Scans the flattened / hoisted layer of node_modules.
 *
 * npm (v3+) hoists all packages to the root node_modules. This scanner walks
 * that flat list and identifies packages that are:
 *
 *  1. NOT declared in any field of your package.json          → isPhantom = true
 *  2. Have known vulnerabilities in the audit data
 *
 * Phantom packages with vulnerabilities are highest-priority because they
 * cannot be fixed by simply updating a declared dep — the user must either
 * explicitly declare the package or ensure the parent that brings it in pins a
 * safe version.
 *
 * Only packages with vulnerabilities are returned to avoid noisy output.
 * The total phantom count (including those without vulns) is captured in
 * ScanSummary.phantomCount by the caller.
 */
export function scanHoistedDeps(
  directory: string,
  auditVulns: RawAuditVulnerability[],
): HoistedDepIssue[] {
  const nmDir = join(directory, "node_modules");
  if (!existsSync(nmDir)) return [];

  // All names declared in any package.json dependency field
  const declaredNames = getAllDeclaredNames(directory);

  // Build vulnerability lookup map from audit data
  const vulnMap = new Map<string, RawAuditVulnerability[]>();
  for (const v of auditVulns) {
    const arr = vulnMap.get(v.name) ?? [];
    arr.push(v);
    vulnMap.set(v.name, arr);
  }

  // 1-level parent reverse map for packages that have vulnerabilities
  const parentMap = buildParentMap(
    directory,
    declaredNames,
    new Set(vulnMap.keys()),
  );

  // Walk root node_modules (top-level only — this is the hoisted flat layer)
  const hoistedNames = listTopLevelPackages(nmDir);

  const issues: HoistedDepIssue[] = [];

  for (const name of hoistedNames) {
    const vulns = vulnMap.get(name) ?? [];
    const isPhantom = !declaredNames.has(name);

    // Only surface entries that have known vulnerabilities.
    // Phantom packages without vulnerabilities are informational-only and
    // captured in ScanSummary.phantomCount — listing every undeclared
    // transitive dep here would be extremely noisy (can be hundreds).
    if (vulns.length === 0) continue;

    const nmPkg = join(nmDir, name, "package.json");
    let version = "unknown";
    if (existsSync(nmPkg)) {
      try {
        version =
          (
            JSON.parse(readFileSync(nmPkg, "utf-8")) as {
              version?: string;
            }
          ).version ?? "unknown";
      } catch {
        /* keep 'unknown' */
      }
    }

    const vulnerabilities: Vulnerability[] = vulns.map((v, i) => {
      const via = v.via?.[0];
      return {
        id: `hoisted-${name}-${i}`,
        title:
          typeof via === "object"
            ? via.title
            : (v.title ?? `Vulnerability in ${name}`),
        severity: normalizeSeverity(v.severity) ?? "low",
        affectedVersions: v.range ?? "unknown",
        url: typeof via === "object" ? via.url : (v.url ?? undefined),
        source: "npm-audit",
      };
    });

    const severities = vulns
      .map((v) => normalizeSeverity(v.severity))
      .filter((s): s is Severity => s !== null);
    const topSeverity =
      (["critical", "high", "moderate", "low"] as Severity[]).find((s) =>
        severities.includes(s),
      ) ?? null;

    issues.push({
      name,
      version,
      requiredBy: parentMap.get(name) ?? [],
      vulnerabilities,
      severity: topSeverity,
      isPhantom,
    });
  }

  // Sort: vulnerable first, then by severity, then phantom-only last
  return issues.sort((a, b) => {
    if (a.vulnerabilities.length > 0 && b.vulnerabilities.length === 0)
      return -1;
    if (a.vulnerabilities.length === 0 && b.vulnerabilities.length > 0)
      return 1;
    return (
      (SEV_ORDER[a.severity ?? "low"] ?? 3) -
      (SEV_ORDER[b.severity ?? "low"] ?? 3)
    );
  });
}

/**
 * Returns the total count of phantom packages in node_modules (declared +
 * undeclared), used to populate ScanSummary.phantomCount.
 */
export function countPhantomPackages(directory: string): number {
  const nmDir = join(directory, "node_modules");
  if (!existsSync(nmDir)) return 0;
  const declared = getAllDeclaredNames(directory);
  const hoisted = listTopLevelPackages(nmDir);
  return hoisted.filter((n) => !declared.has(n)).length;
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/** Every package name declared in ANY package.json dependency field. */
function getAllDeclaredNames(directory: string): Set<string> {
  const pkgPath = join(directory, "package.json");
  if (!existsSync(pkgPath)) return new Set();
  try {
    const pkg = JSON.parse(readFileSync(pkgPath, "utf-8")) as {
      dependencies?: Record<string, string>;
      devDependencies?: Record<string, string>;
      optionalDependencies?: Record<string, string>;
      peerDependencies?: Record<string, string>;
      bundleDependencies?: string[] | boolean;
      bundledDependencies?: string[] | boolean;
    };
    const names = new Set<string>([
      ...Object.keys(pkg.dependencies ?? {}),
      ...Object.keys(pkg.devDependencies ?? {}),
      ...Object.keys(pkg.optionalDependencies ?? {}),
      ...Object.keys(pkg.peerDependencies ?? {}),
    ]);
    const bundled = pkg.bundleDependencies ?? pkg.bundledDependencies;
    if (Array.isArray(bundled)) bundled.forEach((n) => names.add(n));
    return names;
  } catch {
    return new Set();
  }
}

/** Enumerate top-level package names inside a flat node_modules directory. */
function listTopLevelPackages(nmDir: string): string[] {
  const names: string[] = [];
  try {
    const entries = readdirSync(nmDir);
    for (const entry of entries) {
      if (entry.startsWith(".") || entry.startsWith("_")) continue;
      if (entry.startsWith("@")) {
        // Scoped packages live one level deeper (@scope/name)
        try {
          for (const scoped of readdirSync(join(nmDir, entry))) {
            names.push(`${entry}/${scoped}`);
          }
        } catch {
          /* skip unreadable scoped dir */
        }
      } else {
        names.push(entry);
      }
    }
  } catch {
    /* nmDir unreadable */
  }
  return names;
}

/**
 * Best-effort 1-level reverse map: for each target package (with vulns),
 * find which declared direct deps list it in their own `dependencies`.
 */
function buildParentMap(
  directory: string,
  declaredNames: Set<string>,
  targetNames: Set<string>,
): Map<string, string[]> {
  const result = new Map<string, string[]>();
  for (const dep of declaredNames) {
    const depPkgPath = join(directory, "node_modules", dep, "package.json");
    if (!existsSync(depPkgPath)) continue;
    try {
      const pkg = JSON.parse(readFileSync(depPkgPath, "utf-8")) as {
        dependencies?: Record<string, string>;
      };
      for (const sub of Object.keys(pkg.dependencies ?? {})) {
        if (targetNames.has(sub)) {
          const arr = result.get(sub) ?? [];
          if (!arr.includes(dep)) arr.push(dep);
          result.set(sub, arr);
        }
      }
    } catch {
      /* skip */
    }
  }
  return result;
}
