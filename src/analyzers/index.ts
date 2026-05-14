import type {
  DependencyInfo,
  RawScanData,
  ScanSummary,
  RiskLevel,
  SubDependencyIssue,
  PeerDependencyIssue,
  HoistedDepIssue,
} from "../types/index.js";
import {
  normalizeScanData,
  calculateRiskLevel,
  normalizeSeverity,
} from "../normalizer/index.js";
import { enrichWithOsvVulnerabilities } from "./vulnerability.js";
import { enrichWithDeprecationInfo } from "./deprecation.js";
import { enrichWithMaintenanceInfo } from "./maintenance.js";

// ─── Types ────────────────────────────────────────────────────────────────────

export interface AnalysisOptions {
  deep: boolean;
  ignore: string[];
  auditOnly: boolean;
}

// ─── Public API ──────────────────────────────────────────────────────────────

export async function analyzeDependencies(
  rawData: RawScanData,
  options: AnalysisOptions,
): Promise<DependencyInfo[]> {
  // 1. Normalise raw scanner output
  let deps = normalizeScanData(rawData);

  // 2. Drop ignored packages early
  if (options.ignore.length > 0) {
    const ignoreSet = new Set(options.ignore);
    deps = deps.filter((d) => !ignoreSet.has(d.name));
  }

  // 3. Add any packages that have audit vulnerabilities but weren't outdated
  const knownNames = new Set(deps.map((d) => d.name));
  for (const vuln of rawData.vulnerabilities) {
    if (knownNames.has(vuln.name) || options.ignore.includes(vuln.name))
      continue;
    const severity = normalizeSeverity(vuln.severity);
    deps.push({
      name: vuln.name,
      current: "0.0.0",
      latest: "0.0.0",
      wanted: "0.0.0",
      severity,
      deprecated: false,
      stale: false,
      archived: false,
      riskLevel: severity ? calculateRiskLevel("none", severity) : "none",
      vulnerabilities: [],
      updateType: "none",
      isDev: false,
      depType: "production",
    });
    knownNames.add(vuln.name);
  }

  // 4. Enrich with OSV.dev vulnerability data
  deps = await enrichWithOsvVulnerabilities(deps);

  // 5. Unless audit-only mode, also check deprecation & maintenance health
  if (!options.auditOnly) {
    deps = await enrichWithDeprecationInfo(deps);
    deps = await enrichWithMaintenanceInfo(deps);
  }

  // 6. Re-calculate risk levels now that all enrichments are done
  deps = deps.map((d) => ({ ...d, riskLevel: recalcRisk(d) }));

  // 7. Sort: most risky first
  const riskOrder: Record<RiskLevel, number> = {
    critical: 0,
    high: 1,
    medium: 2,
    low: 3,
    none: 4,
  };
  return deps.sort((a, b) => riskOrder[a.riskLevel] - riskOrder[b.riskLevel]);
}

export function computeSummary(
  dependencies: DependencyInfo[],
  subDepIssues: SubDependencyIssue[] = [],
  peerIssues: PeerDependencyIssue[] = [],
  hoistedIssues: HoistedDepIssue[] = [],
  phantomCount = 0,
): ScanSummary {
  return {
    total: dependencies.length,
    outdated: dependencies.filter((d) => d.updateType !== "none").length,
    vulnerable: dependencies.filter((d) => d.vulnerabilities.length > 0).length,
    deprecated: dependencies.filter((d) => d.deprecated).length,
    stale: dependencies.filter((d) => d.stale).length,
    critical: dependencies.filter((d) => d.severity === "critical").length,
    high: dependencies.filter((d) => d.severity === "high").length,
    moderate: dependencies.filter((d) => d.severity === "moderate").length,
    low: dependencies.filter((d) => d.severity === "low").length,
    optionalScanned: dependencies.filter((d) => d.depType === "optional")
      .length,
    bundledScanned: dependencies.filter((d) => d.depType === "bundled").length,
    transitiveVulnerable: subDepIssues.length,
    peerMissing: peerIssues.filter((p) => p.status === "missing").length,
    peerIncompatible: peerIssues.filter((p) => p.status === "incompatible")
      .length,
    hoistedVulnerable: hoistedIssues.filter((h) => h.vulnerabilities.length > 0)
      .length,
    phantomCount,
  };
}

// ─── Internal ────────────────────────────────────────────────────────────────

function recalcRisk(dep: DependencyInfo): RiskLevel {
  const topSev = dep.vulnerabilities.length > 0 ? dep.severity : null;
  if (topSev === "critical") return "critical";
  if (topSev === "high") return "high";
  if (dep.deprecated) return "high";
  if (dep.updateType === "major") return "high";
  if (topSev === "moderate") return "medium";
  if (dep.stale) return "medium";
  if (dep.updateType === "minor") return "medium";
  if (dep.updateType === "patch") return "low";
  return "none";
}
