import { existsSync, readFileSync } from "fs";
import { join } from "path";
import type {
  SubDependencyIssue,
  RawAuditVulnerability,
  Vulnerability,
  Severity,
} from "../types/index.js";
import { normalizeSeverity } from "../normalizer/index.js";

// ─── Public API ───────────────────────────────────────────────────────────────

/**
 * Identifies vulnerable transitive (indirect) dependencies by cross-referencing
 * the existing audit output against the project's direct dependency list.
 *
 * For each transitive dep with vulnerabilities we also try (1-level deep) to
 * identify which direct dependencies pull it in, giving the user an actionable
 * parent to upgrade.
 */
export function scanTransitiveDeps(
  directory: string,
  auditVulns: RawAuditVulnerability[],
): SubDependencyIssue[] {
  if (auditVulns.length === 0) return [];

  const directDeps = getDirectDepNames(directory);
  if (directDeps.size === 0) return [];

  // Keep only vulnerabilities from packages that are NOT direct deps
  const transitiveVulns = auditVulns.filter((v) => !directDeps.has(v.name));
  if (transitiveVulns.length === 0) return [];

  const targetNames = new Set(transitiveVulns.map((v) => v.name));
  const parentMap = buildTransitiveParentMap(
    directory,
    directDeps,
    targetNames,
  );

  // Group multiple audit entries for the same package
  const byName = new Map<string, RawAuditVulnerability[]>();
  for (const v of transitiveVulns) {
    const arr = byName.get(v.name) ?? [];
    arr.push(v);
    byName.set(v.name, arr);
  }

  const SEV_ORDER: Record<string, number> = {
    critical: 0,
    high: 1,
    moderate: 2,
    low: 3,
  };

  const issues: SubDependencyIssue[] = [];

  for (const [name, vulns] of byName) {
    // Resolve installed version from node_modules
    const nmPkg = join(directory, "node_modules", name, "package.json");
    let version = "unknown";
    if (existsSync(nmPkg)) {
      try {
        const pkg = JSON.parse(readFileSync(nmPkg, "utf-8")) as {
          version?: string;
        };
        version = pkg.version ?? "unknown";
      } catch {
        // keep 'unknown'
      }
    }

    // Build Vulnerability objects
    const vulnerabilities: Vulnerability[] = vulns.map((v, i) => {
      const via = v.via?.[0];
      const title =
        typeof via === "object" && via.title
          ? via.title
          : (v.title ?? `Vulnerability in ${name}`);
      const url =
        typeof via === "object" && via.url ? via.url : (v.url ?? undefined);
      const severity = normalizeSeverity(v.severity) ?? "low";
      return {
        id: `transitive-${name}-${i}`,
        title,
        severity,
        affectedVersions: v.range ?? "unknown",
        url,
        source: "npm-audit",
      };
    });

    // Pick highest severity
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
    });
  }

  return issues.sort(
    (a, b) =>
      (SEV_ORDER[a.severity ?? "low"] ?? 3) -
      (SEV_ORDER[b.severity ?? "low"] ?? 3),
  );
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function getDirectDepNames(directory: string): Set<string> {
  const pkgPath = join(directory, "package.json");
  if (!existsSync(pkgPath)) return new Set();
  try {
    const pkg = JSON.parse(readFileSync(pkgPath, "utf-8")) as {
      dependencies?: Record<string, string>;
      devDependencies?: Record<string, string>;
      optionalDependencies?: Record<string, string>;
      bundleDependencies?: string[] | boolean;
      bundledDependencies?: string[] | boolean;
    };
    const names = new Set<string>([
      ...Object.keys(pkg.dependencies ?? {}),
      ...Object.keys(pkg.devDependencies ?? {}),
      ...Object.keys(pkg.optionalDependencies ?? {}),
    ]);
    const bundled = pkg.bundleDependencies ?? pkg.bundledDependencies;
    if (Array.isArray(bundled)) bundled.forEach((n) => names.add(n));
    return names;
  } catch {
    return new Set();
  }
}

/**
 * Best-effort 1-level reverse lookup: for each target transitive package, find
 * which direct dependencies list it in their own `dependencies` field.
 *
 * This is fast (reads only direct-dep package.json files) and covers the
 * overwhelming majority of real-world transitive vulnerability chains.
 */
function buildTransitiveParentMap(
  directory: string,
  directDeps: Set<string>,
  targetNames: Set<string>,
): Map<string, string[]> {
  const result = new Map<string, string[]>();

  for (const dep of directDeps) {
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
      // skip unreadable package.json
    }
  }

  return result;
}
