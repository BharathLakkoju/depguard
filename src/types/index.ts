// ─── Core Union Types ────────────────────────────────────────────────────────

export type PackageManager =
  | "npm"
  | "pnpm"
  | "yarn"
  | "bun"
  | "deno"
  | "unknown";

export type Severity = "critical" | "high" | "moderate" | "low";

export type RiskLevel = "critical" | "high" | "medium" | "low" | "none";

export type UpdateType = "major" | "minor" | "patch" | "none";

/**
 * Which field in package.json declared this dependency.
 *  production – dependencies
 *  dev        – devDependencies
 *  optional   – optionalDependencies
 *  bundled    – bundleDependencies / bundledDependencies
 */
export type DepType = "production" | "dev" | "optional" | "bundled";

// ─── Domain Models ───────────────────────────────────────────────────────────

export interface Vulnerability {
  id: string;
  title: string;
  severity: Severity;
  affectedVersions: string;
  fixedVersion?: string;
  url?: string;
  source: "npm-audit" | "osv";
}

export interface DependencyInfo {
  name: string;
  current: string;
  latest: string;
  wanted: string;
  severity: Severity | null;
  deprecated: boolean;
  deprecationMessage?: string;
  stale: boolean;
  archived: boolean;
  riskLevel: RiskLevel;
  vulnerabilities: Vulnerability[];
  lastPublished?: string;
  updateType: UpdateType;
  isDev: boolean; // true when depType === 'dev' (kept for backward compat)
  depType: DepType; // explicit declaration category
}

export interface WorkspaceInfo {
  name: string;
  directory: string;
  packageManager: PackageManager;
}

export interface ProjectInfo {
  name: string;
  directory: string;
  packageManager: PackageManager;
  isMonorepo: boolean;
  workspaces: WorkspaceInfo[];
}

// ─── Scan Result Types ───────────────────────────────────────────────────────

export interface ScanResult {
  project: string;
  packageManager: PackageManager;
  directory: string;
  /** Direct deps: production + dev + optional + bundled */
  dependencies: DependencyInfo[];
  /** Vulnerable transitive (indirect) deps brought in by direct deps */
  subDependencyIssues: SubDependencyIssue[];
  /** Peer-dependency mismatches across installed packages */
  peerDependencyIssues: PeerDependencyIssue[];
  /** Packages physically in node_modules but undeclared in package.json */
  hoistedIssues: HoistedDepIssue[];
  scanDate: string;
  summary: ScanSummary;
  errors: string[];
  suggestions: FixSuggestion[];
}

export interface ScanSummary {
  // Direct deps
  total: number;
  outdated: number;
  vulnerable: number;
  deprecated: number;
  stale: number;
  critical: number;
  high: number;
  moderate: number;
  low: number;
  // Dep-type breakdown
  optionalScanned: number;
  bundledScanned: number;
  // Extended layers
  transitiveVulnerable: number;
  peerMissing: number;
  peerIncompatible: number;
  hoistedVulnerable: number;
  phantomCount: number;
}

// ─── Sub-dependency Issues (transitive layer) ─────────────────────────────────

export interface SubDependencyIssue {
  /** Package name of the transitive (indirect) dependency */
  name: string;
  /** Currently installed version */
  version: string;
  /**
   * Direct deps in package.json whose own `dependencies` list this package.
   * Populated on a best-effort 1-level basis.
   */
  requiredBy: string[];
  /** Known security vulnerabilities */
  vulnerabilities: Vulnerability[];
  /** Highest severity across all vulnerabilities */
  severity: Severity | null;
}

// ─── Peer-dependency Issues ───────────────────────────────────────────────────

export interface PeerDependencyIssue {
  /** Name of the peer dependency that is missing or incompatible */
  peerName: string;
  /** Currently installed version (null when entirely absent) */
  installedVersion: string | null;
  /** 'missing' = not installed at all; 'incompatible' = wrong version */
  status: "missing" | "incompatible";
  /** True only when every requiring package marks this peer as optional */
  optional: boolean;
  /** Which installed packages declare this peer requirement */
  requiredBy: Array<{
    package: string;
    packageVersion: string;
    requiredRange: string;
  }>;
}

// ─── Hoisted / Phantom Dependency Issues ─────────────────────────────────────

export interface HoistedDepIssue {
  /** Package name found in root node_modules */
  name: string;
  /** Installed version */
  version: string;
  /**
   * Direct deps whose own `dependencies` field lists this package (1-level).
   * Empty when no known parent → truly orphaned phantom dep.
   */
  requiredBy: string[];
  /** Security vulnerabilities (from audit data) */
  vulnerabilities: Vulnerability[];
  /** Highest severity, null when no vulns */
  severity: Severity | null;
  /**
   * True when the package is NOT declared in any dependency field of the
   * project's package.json (phantom dependency).
   */
  isPhantom: boolean;
}

// ─── Fix Suggestions ──────────────────────────────────────────────────────────

export interface FixSuggestion {
  /** Category of the issue being fixed */
  type:
    | "vulnerability"
    | "deprecated"
    | "outdated"
    | "maintenance"
    | "peer"
    | "phantom";
  /** The specific package this suggestion targets (omitted for batch commands) */
  packageName?: string;
  /** The exact command to run */
  command: string;
  /** Human-readable description of what the command does */
  description: string;
  /** How urgent this fix is */
  priority: "critical" | "high" | "medium" | "low";
}

export interface ScanOptions {
  directory: string;
  json: boolean;
  markdown: boolean;
  failOnHigh: boolean;
  ignore: string[];
  workspace: boolean;
  deep: boolean;
  auditOnly: boolean;
  production: boolean;
}

// ─── Raw Scanner Output Types ────────────────────────────────────────────────

export interface RawOutdatedEntry {
  name: string;
  current: string;
  wanted: string;
  latest: string;
  isDev: boolean;
  depType: DepType;
}

export interface RawAuditVulnerability {
  name: string;
  severity: string;
  title?: string;
  url?: string;
  range?: string;
  fixAvailable?: boolean | { name: string; version: string };
  via?: Array<string | { title: string; url: string; severity: string }>;
}

export interface RawScanData {
  outdated: RawOutdatedEntry[];
  vulnerabilities: RawAuditVulnerability[];
}
