import semver from "semver";
import type {
  DependencyInfo,
  RawScanData,
  UpdateType,
  RiskLevel,
  Severity,
  DepType,
} from "../types/index.js";

// ─── Public API ──────────────────────────────────────────────────────────────

/**
 * Converts raw scanner output (outdated list + audit list) into
 * a normalised array of DependencyInfo objects ready for analysis.
 */
export function normalizeScanData(data: RawScanData): DependencyInfo[] {
  // Build a quick severity map from the audit results
  const auditSeverityMap = new Map<string, string>();
  for (const vuln of data.vulnerabilities) {
    const existing = auditSeverityMap.get(vuln.name);
    const newRank = severityRank(normalizeSeverity(vuln.severity));
    if (!existing || newRank > severityRank(normalizeSeverity(existing))) {
      auditSeverityMap.set(vuln.name, vuln.severity);
    }
  }

  return data.outdated.map((entry) => {
    const rawSev = auditSeverityMap.get(entry.name);
    const severity = rawSev ? normalizeSeverity(rawSev) : null;
    const updateType = determineUpdateType(entry.current, entry.latest);
    const riskLevel = calculateRiskLevel(updateType, severity);

    const dep: DependencyInfo = {
      name: entry.name,
      current: entry.current,
      latest: entry.latest,
      wanted: entry.wanted,
      severity,
      deprecated: false,
      stale: false,
      archived: false,
      riskLevel,
      vulnerabilities: [],
      updateType,
      isDev: entry.isDev,
      depType: (entry.depType ?? "production") as DepType,
    };

    return dep;
  });
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

export function determineUpdateType(
  current: string,
  latest: string,
): UpdateType {
  if (!current || !latest) return "none";

  const cleanCurrent = semver.coerce(current)?.version;
  const cleanLatest = semver.coerce(latest)?.version;

  if (!cleanCurrent || !cleanLatest) return "none";
  if (cleanCurrent === cleanLatest) return "none";
  if (!semver.gt(cleanLatest, cleanCurrent)) return "none";

  if (semver.major(cleanLatest) > semver.major(cleanCurrent)) return "major";
  if (semver.minor(cleanLatest) > semver.minor(cleanCurrent)) return "minor";
  if (semver.patch(cleanLatest) > semver.patch(cleanCurrent)) return "patch";

  return "none";
}

export function normalizeSeverity(severity: string): Severity | null {
  switch (severity.toLowerCase()) {
    case "critical":
      return "critical";
    case "high":
      return "high";
    case "moderate":
    case "medium":
      return "moderate";
    case "low":
      return "low";
    default:
      return null;
  }
}

export function calculateRiskLevel(
  updateType: UpdateType,
  severity: Severity | null,
): RiskLevel {
  if (severity === "critical") return "critical";
  if (severity === "high") return "high";
  if (updateType === "major") return "high";
  if (severity === "moderate") return "medium";
  if (updateType === "minor") return "medium";
  if (updateType === "patch") return "low";
  return "none";
}

function severityRank(sev: Severity | null): number {
  switch (sev) {
    case "critical":
      return 4;
    case "high":
      return 3;
    case "moderate":
      return 2;
    case "low":
      return 1;
    default:
      return 0;
  }
}
