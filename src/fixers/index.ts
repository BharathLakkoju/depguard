import semver from "semver";
import type {
  DependencyInfo,
  FixSuggestion,
  PackageManager,
  SubDependencyIssue,
  PeerDependencyIssue,
  HoistedDepIssue,
} from "../types/index.js";

// ─── Public API ───────────────────────────────────────────────────────────────

/**
 * Generates an ordered list of actionable fix commands from all scan layers:
 *   direct deps → transitive → peer deps → hoisted/phantom
 *
 * Priority order: critical → high → medium → low
 */
export function generateFixSuggestions(
  dependencies: DependencyInfo[],
  subDepIssues: SubDependencyIssue[],
  peerIssues: PeerDependencyIssue[],
  hoistedIssues: HoistedDepIssue[],
  phantomCount: number,
  packageManager: PackageManager,
): FixSuggestion[] {
  const pm = packageManager === "unknown" ? "npm" : packageManager;
  const suggestions: FixSuggestion[] = [];

  const vulnDeps = dependencies.filter((d) => d.vulnerabilities.length > 0);
  const deprecatedDeps = dependencies.filter((d) => d.deprecated);
  const vulnNames = new Set(vulnDeps.map((d) => d.name));
  const deprecatedNames = new Set(deprecatedDeps.map((d) => d.name));

  // Packages that are ONLY outdated — no competing vulnerability/deprecated fix
  const patchMinorOnly = dependencies.filter(
    (d) =>
      (d.updateType === "patch" || d.updateType === "minor") &&
      !vulnNames.has(d.name) &&
      !deprecatedNames.has(d.name),
  );
  const majorOnly = dependencies.filter(
    (d) =>
      d.updateType === "major" &&
      !vulnNames.has(d.name) &&
      !deprecatedNames.has(d.name),
  );
  const staleDeps = dependencies.filter(
    (d) =>
      (d.stale || d.archived) &&
      !vulnNames.has(d.name) &&
      !deprecatedNames.has(d.name),
  );

  // ── 1. Direct dep vulnerabilities ─────────────────────────────────────────
  if (vulnDeps.length > 0)
    suggestions.push(...buildVulnSuggestions(vulnDeps, pm));

  // ── 2. Deprecated direct deps ─────────────────────────────────────────────
  for (const dep of deprecatedDeps)
    suggestions.push(...buildDeprecatedSuggestions(dep, pm));

  // ── 3. Transitive (sub-dep) vulnerabilities ───────────────────────────────
  if (subDepIssues.length > 0)
    suggestions.push(...buildTransitiveSuggestions(subDepIssues, pm));

  // ── 4. Peer dependency fixes ──────────────────────────────────────────────
  for (const issue of peerIssues)
    suggestions.push(...buildPeerSuggestions(issue, pm));

  // ── 5. Hoisted / phantom dep fixes ───────────────────────────────────────
  for (const issue of hoistedIssues)
    suggestions.push(...buildHoistedSuggestions(issue, pm));

  // Batch notice for phantom deps without known vulnerabilities
  // (those WITH vulns already got per-package suggestions above)
  const phantomVulnCount = hoistedIssues.filter(
    (i) => i.isPhantom && i.vulnerabilities.length > 0,
  ).length;
  const phantomCleanCount = phantomCount - phantomVulnCount;
  if (phantomCleanCount > 0) {
    suggestions.push({
      type: "phantom",
      command: `# ${phantomCleanCount} phantom dep${phantomCleanCount > 1 ? "s" : ""} in node_modules (no known vulnerabilities)`,
      description: `${phantomCleanCount} transitive package${phantomCleanCount > 1 ? "s are" : " is"} hoisted in node_modules but undeclared in package.json. No vulnerabilities detected — this is informational only.`,
      priority: "low",
    });
  }

  // ── 6. Outdated: patch / minor (batch) ────────────────────────────────────
  if (patchMinorOnly.length > 0) {
    suggestions.push({
      type: "outdated",
      command: updateAllCmd(pm),
      description: `Update all patch/minor dependencies (${patchMinorOnly.length} pkg${patchMinorOnly.length > 1 ? "s" : ""}: ${patchMinorOnly.map((d) => d.name).join(", ")})`,
      priority: "low",
    });
  }

  // ── 7. Outdated: major (individual) ──────────────────────────────────────
  for (const dep of majorOnly) {
    suggestions.push({
      type: "outdated",
      packageName: dep.name,
      command: installCmd(pm, dep.name, dep.latest, dep.isDev),
      description: `Upgrade \`${dep.name}\` ${dep.current} → ${dep.latest} (major — review changelog)`,
      priority: "medium",
    });
  }

  // ── 8. Stale / archived ───────────────────────────────────────────────────
  for (const dep of staleDeps) {
    suggestions.push({
      type: "maintenance",
      packageName: dep.name,
      command: dep.archived
        ? `# Find a maintained alternative for ${dep.name}`
        : `# Monitor ${dep.name} — no recent releases`,
      description: dep.archived
        ? `\`${dep.name}\` is archived — find an actively maintained replacement`
        : `\`${dep.name}\` has not released in a long time — monitor or replace`,
      priority: dep.archived ? "medium" : "low",
    });
  }

  // Sort by priority
  const order: Record<FixSuggestion["priority"], number> = {
    critical: 0,
    high: 1,
    medium: 2,
    low: 3,
  };
  return suggestions.sort((a, b) => order[a.priority] - order[b.priority]);
}

// ─── Direct vulnerability suggestions ────────────────────────────────────────

function buildVulnSuggestions(
  vulnDeps: DependencyInfo[],
  pm: string,
): FixSuggestion[] {
  const out: FixSuggestion[] = [];

  if (pm === "npm") {
    out.push({
      type: "vulnerability",
      command: "npm audit fix",
      description:
        "Auto-fix compatible vulnerability updates (no breaking changes)",
      priority: "critical",
    });
    out.push({
      type: "vulnerability",
      command: "npm audit fix --force",
      description:
        "Force-fix ALL vulnerabilities including breaking upgrades (test thoroughly)",
      priority: "high",
    });
  } else if (pm === "pnpm") {
    out.push({
      type: "vulnerability",
      command: "pnpm audit --fix",
      description: "Auto-fix compatible vulnerability updates",
      priority: "critical",
    });
  } else if (pm === "yarn") {
    out.push({
      type: "vulnerability",
      command: "yarn audit",
      description:
        "Review vulnerabilities (Yarn has no auto-fix — upgrade manually)",
      priority: "critical",
    });
  } else if (pm === "bun") {
    out.push({
      type: "vulnerability",
      command: "bun update",
      description: "Update all deps — Bun has no dedicated audit-fix command",
      priority: "critical",
    });
  }

  for (const dep of vulnDeps) {
    const fixed = dep.vulnerabilities.find((v) => v.fixedVersion);
    if (fixed?.fixedVersion) {
      out.push({
        type: "vulnerability",
        packageName: dep.name,
        command: installCmd(pm, dep.name, fixed.fixedVersion, dep.isDev),
        description: `Fix \`${dep.name}\` — upgrade to ${fixed.fixedVersion} (patches the vulnerability)`,
        priority: dep.severity === "critical" ? "critical" : "high",
      });
    }
  }
  return out;
}

// ─── Transitive vulnerability suggestions ────────────────────────────────────

function buildTransitiveSuggestions(
  issues: SubDependencyIssue[],
  pm: string,
): FixSuggestion[] {
  const out: FixSuggestion[] = [];

  // Batch audit fix covers transitive vulns too
  if (pm === "npm") {
    out.push({
      type: "vulnerability",
      command: "npm audit fix",
      description: `Fix ${issues.length} transitive (indirect) vulnerable dep${issues.length > 1 ? "s" : ""} — runs recursively through the dependency tree`,
      priority: "critical",
    });
  }

  // For each transitive issue, suggest upgrading the direct parent
  for (const issue of issues) {
    if (issue.requiredBy.length > 0) {
      const parents = issue.requiredBy.slice(0, 3).join(", ");
      out.push({
        type: "vulnerability",
        packageName: issue.name,
        command: `# Update parent dep(s) to resolve ${issue.name}@${issue.version}: ${parents}`,
        description: `Transitive vulnerability in \`${issue.name}@${issue.version}\` — brought in by: ${parents}. Upgrade the parent to get a safe version.`,
        priority: issue.severity === "critical" ? "critical" : "high",
      });
    }
  }
  return out;
}

// ─── Deprecated dep suggestions ───────────────────────────────────────────────

function parseReplacement(msg: string): string | null {
  const patterns = [
    /use\s+([`'"]?@?[\w/-]+[`'"]?)\s+instead/i,
    /replaced\s+(?:by|with)\s+([`'"]?@?[\w/-]+[`'"]?)/i,
    /please\s+use\s+([`'"]?@?[\w/-]+[`'"]?)/i,
    /migrate\s+to\s+([`'"]?@?[\w/-]+[`'"]?)/i,
    /switch\s+to\s+([`'"]?@?[\w/-]+[`'"]?)/i,
    /consider\s+(?:using\s+)?([`'"]?@?[\w/-]+[`'"]?)\s+instead/i,
  ];
  for (const re of patterns) {
    const m = msg.match(re);
    if (m?.[1]) return m[1].replace(/[`'"]/g, "");
  }
  return null;
}

function buildDeprecatedSuggestions(
  dep: DependencyInfo,
  pm: string,
): FixSuggestion[] {
  const replacement = parseReplacement(dep.deprecationMessage ?? "");
  if (replacement) {
    return [
      {
        type: "deprecated",
        packageName: dep.name,
        command: `${uninstallCmd(pm, dep.name)} && ${installCmd(pm, replacement, "latest", dep.isDev)}`,
        description: `Replace deprecated \`${dep.name}\` with \`${replacement}\` (maintainer's recommendation)`,
        priority: "high",
      },
    ];
  }
  return [
    {
      type: "deprecated",
      packageName: dep.name,
      command: installCmd(pm, dep.name, "latest", dep.isDev),
      description: `Update \`${dep.name}\` to latest — check the package page for a recommended replacement`,
      priority: "high",
    },
  ];
}

// ─── Peer dep suggestions ─────────────────────────────────────────────────────

function buildPeerSuggestions(
  issue: PeerDependencyIssue,
  pm: string,
): FixSuggestion[] {
  const requiredRanges = issue.requiredBy.map((r) => r.requiredRange);
  const uniqueRanges = [...new Set(requiredRanges)];
  const requirers = issue.requiredBy
    .map((r) => `${r.package}@${r.packageVersion}`)
    .join(", ");

  if (issue.status === "missing") {
    // Try to compute a sensible install target from the required range
    const range = uniqueRanges[0] ?? "latest";
    const minVer = tryMinVersion(range);
    const target = minVer ?? "latest";
    return [
      {
        type: "peer",
        packageName: issue.peerName,
        command: installCmd(pm, issue.peerName, target, false),
        description: `Install missing peer dep \`${issue.peerName}\` (required: ${uniqueRanges.join(" / ")} by ${requirers})`,
        priority: issue.optional ? "low" : "high",
      },
    ];
  }

  // Incompatible — installed but wrong version
  const installed = issue.installedVersion ?? "?";
  const range = uniqueRanges[0] ?? "latest";
  const minVer = tryMinVersion(range);
  const target = minVer ?? "latest";
  return [
    {
      type: "peer",
      packageName: issue.peerName,
      command: installCmd(pm, issue.peerName, target, false),
      description: `Fix incompatible peer dep \`${issue.peerName}\` — installed ${installed} but ${uniqueRanges.join(" / ")} required by ${requirers}`,
      priority: issue.optional ? "low" : "medium",
    },
  ];
}

/** Resolve the minimum satisfying semver version string from a range. */
function tryMinVersion(range: string): string | null {
  try {
    const min = semver.minVersion(range);
    return min ? min.version : null;
  } catch {
    return null;
  }
}

// ─── Hoisted / phantom dep suggestions ───────────────────────────────────────

function buildHoistedSuggestions(
  issue: HoistedDepIssue,
  pm: string,
): FixSuggestion[] {
  const out: FixSuggestion[] = [];

  if (issue.vulnerabilities.length > 0) {
    if (issue.isPhantom) {
      // Phantom + vulnerable: audit fix won't help since it's not in package.json
      out.push({
        type: "phantom",
        packageName: issue.name,
        command: installCmd(pm, issue.name, "latest", false),
        description: `Declare phantom dep \`${issue.name}@${issue.version}\` explicitly and upgrade it — it is undeclared but has vulnerabilities`,
        priority: issue.severity === "critical" ? "critical" : "high",
      });
    } else {
      // Declared dep that is hoisted and vulnerable — covered by audit fix
      out.push({
        type: "vulnerability",
        packageName: issue.name,
        command: installCmd(pm, issue.name, "latest", false),
        description: `Hoisted dep \`${issue.name}@${issue.version}\` has vulnerabilities — upgrade to latest`,
        priority: issue.severity === "critical" ? "critical" : "high",
      });
    }
  } else if (issue.isPhantom) {
    // Phantom but no vuln — skip per-package; caller emits a batch summary
    // (see generateFixSuggestions phantom batch block)
  }

  return out;
}

// ─── Command helpers ──────────────────────────────────────────────────────────

function installCmd(
  pm: string,
  name: string,
  version: string,
  isDev: boolean,
): string {
  const ver = version === "latest" ? "@latest" : `@${version}`;
  switch (pm) {
    case "pnpm":
      return `pnpm add ${name}${ver}${isDev ? " --save-dev" : ""}`;
    case "yarn":
      return `yarn add ${name}${ver}${isDev ? " --dev" : ""}`;
    case "bun":
      return `bun add ${name}${ver}${isDev ? " --dev" : ""}`;
    default:
      return `npm install ${name}${ver}${isDev ? " --save-dev" : ""}`;
  }
}

function uninstallCmd(pm: string, name: string): string {
  switch (pm) {
    case "pnpm":
      return `pnpm remove ${name}`;
    case "yarn":
      return `yarn remove ${name}`;
    case "bun":
      return `bun remove ${name}`;
    default:
      return `npm uninstall ${name}`;
  }
}

function updateAllCmd(pm: string): string {
  switch (pm) {
    case "pnpm":
      return "pnpm update";
    case "yarn":
      return "yarn upgrade";
    case "bun":
      return "bun update";
    default:
      return "npm update";
  }
}
