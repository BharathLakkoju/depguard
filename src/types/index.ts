// ─── Core Union Types ────────────────────────────────────────────────────────

export type PackageManager = 'npm' | 'pnpm' | 'yarn' | 'bun' | 'deno' | 'unknown';

export type Severity = 'critical' | 'high' | 'moderate' | 'low';

export type RiskLevel = 'critical' | 'high' | 'medium' | 'low' | 'none';

export type UpdateType = 'major' | 'minor' | 'patch' | 'none';

// ─── Domain Models ───────────────────────────────────────────────────────────

export interface Vulnerability {
  id: string;
  title: string;
  severity: Severity;
  affectedVersions: string;
  fixedVersion?: string;
  url?: string;
  source: 'npm-audit' | 'osv';
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
  isDev: boolean;
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
  dependencies: DependencyInfo[];
  scanDate: string;
  summary: ScanSummary;
  errors: string[];
}

export interface ScanSummary {
  total: number;
  outdated: number;
  vulnerable: number;
  deprecated: number;
  stale: number;
  critical: number;
  high: number;
  moderate: number;
  low: number;
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
