import type { DependencyInfo, FixSuggestion, PackageManager } from '../types/index.js';

// ─── Public API ───────────────────────────────────────────────────────────────

/**
 * Given a list of analysed dependencies and the detected package manager,
 * returns an ordered list of actionable fix commands the user can run.
 *
 * Priority order: critical → high → medium → low
 * Within each priority: vulnerability → deprecated → outdated → maintenance
 */
export function generateFixSuggestions(
  dependencies: DependencyInfo[],
  packageManager: PackageManager,
): FixSuggestion[] {
  const pm = packageManager === 'unknown' ? 'npm' : packageManager;
  const suggestions: FixSuggestion[] = [];

  const vulnDeps        = dependencies.filter((d) => d.vulnerabilities.length > 0);
  const deprecatedDeps  = dependencies.filter((d) => d.deprecated);

  // Packages that are ONLY outdated (not also vulnerable or deprecated) to
  // avoid suggesting conflicting commands for the same package.
  const vulnNames       = new Set(vulnDeps.map((d) => d.name));
  const deprecatedNames = new Set(deprecatedDeps.map((d) => d.name));
  const patchMinorOnly  = dependencies.filter(
    (d) =>
      (d.updateType === 'patch' || d.updateType === 'minor') &&
      !vulnNames.has(d.name) &&
      !deprecatedNames.has(d.name),
  );
  const majorOnly = dependencies.filter(
    (d) =>
      d.updateType === 'major' &&
      !vulnNames.has(d.name) &&
      !deprecatedNames.has(d.name),
  );
  const staleDeps = dependencies.filter(
    (d) => (d.stale || d.archived) && !vulnNames.has(d.name) && !deprecatedNames.has(d.name),
  );

  // ── 1. Vulnerability fixes ─────────────────────────────────────────────────
  if (vulnDeps.length > 0) {
    suggestions.push(...buildVulnerabilitySuggestions(vulnDeps, pm));
  }

  // ── 2. Deprecated package fixes ───────────────────────────────────────────
  for (const dep of deprecatedDeps) {
    suggestions.push(...buildDeprecatedSuggestions(dep, pm));
  }

  // ── 3. Outdated: patch / minor (batch command) ─────────────────────────────
  if (patchMinorOnly.length > 0) {
    suggestions.push({
      type: 'outdated',
      command: updateAllCmd(pm),
      description: `Update all patch/minor dependencies at once (${patchMinorOnly.length} package${patchMinorOnly.length > 1 ? 's' : ''}: ${patchMinorOnly.map((d) => d.name).join(', ')})`,
      priority: 'low',
    });
  }

  // ── 4. Outdated: major (individual commands) ───────────────────────────────
  for (const dep of majorOnly) {
    suggestions.push({
      type: 'outdated',
      packageName: dep.name,
      command: installCmd(pm, dep.name, dep.latest, dep.isDev),
      description: `Upgrade \`${dep.name}\` from ${dep.current} → ${dep.latest} (major update — review the changelog first)`,
      priority: 'medium',
    });
  }

  // ── 5. Stale / archived packages ──────────────────────────────────────────
  for (const dep of staleDeps) {
    if (dep.archived) {
      suggestions.push({
        type: 'maintenance',
        packageName: dep.name,
        command: `# Find an actively maintained alternative for ${dep.name}`,
        description: `\`${dep.name}\` is archived — search for a maintained replacement and update your code`,
        priority: 'medium',
      });
    } else {
      suggestions.push({
        type: 'maintenance',
        packageName: dep.name,
        command: `# Monitor ${dep.name} — no releases in a long time`,
        description: `\`${dep.name}\` has not been published recently — monitor it or find an alternative`,
        priority: 'low',
      });
    }
  }

  // Sort by priority
  const order: Record<FixSuggestion['priority'], number> = {
    critical: 0,
    high: 1,
    medium: 2,
    low: 3,
  };
  return suggestions.sort((a, b) => order[a.priority] - order[b.priority]);
}

// ─── Vulnerability helpers ────────────────────────────────────────────────────

function buildVulnerabilitySuggestions(
  vulnDeps: DependencyInfo[],
  pm: string,
): FixSuggestion[] {
  const out: FixSuggestion[] = [];

  // Batch audit-fix command (npm / pnpm only)
  if (pm === 'npm') {
    out.push({
      type: 'vulnerability',
      command: 'npm audit fix',
      description: 'Auto-fix compatible vulnerability updates (safe — no breaking changes)',
      priority: 'critical',
    });
    out.push({
      type: 'vulnerability',
      command: 'npm audit fix --force',
      description: 'Force-fix ALL vulnerabilities, including breaking-change upgrades (test thoroughly after running)',
      priority: 'high',
    });
  } else if (pm === 'pnpm') {
    out.push({
      type: 'vulnerability',
      command: 'pnpm audit --fix',
      description: 'Auto-fix compatible vulnerability updates',
      priority: 'critical',
    });
  } else if (pm === 'yarn') {
    out.push({
      type: 'vulnerability',
      command: 'yarn audit',
      description: 'Review vulnerability report (Yarn Classic has no auto-fix — upgrade packages manually below)',
      priority: 'critical',
    });
  } else if (pm === 'bun') {
    out.push({
      type: 'vulnerability',
      command: 'bun update',
      description: 'Update all dependencies — Bun does not have a dedicated audit-fix command',
      priority: 'critical',
    });
  }

  // Per-package fix when a specific fixed version is known
  for (const dep of vulnDeps) {
    const fixedVuln = dep.vulnerabilities.find((v) => v.fixedVersion);
    if (fixedVuln?.fixedVersion) {
      out.push({
        type: 'vulnerability',
        packageName: dep.name,
        command: installCmd(pm, dep.name, fixedVuln.fixedVersion, dep.isDev),
        description: `Fix \`${dep.name}\` — upgrade to ${fixedVuln.fixedVersion} which patches the vulnerability`,
        priority: dep.severity === 'critical' ? 'critical' : 'high',
      });
    }
  }

  return out;
}

// ─── Deprecated helpers ───────────────────────────────────────────────────────

/**
 * Try to extract a replacement package name from common deprecation message
 * patterns (e.g. "Use X instead", "Replaced by X", "Please use X").
 */
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
    if (m?.[1]) return m[1].replace(/[`'"]/g, '');
  }
  return null;
}

function buildDeprecatedSuggestions(dep: DependencyInfo, pm: string): FixSuggestion[] {
  const msg = dep.deprecationMessage ?? '';
  const replacement = parseReplacement(msg);

  if (replacement) {
    return [
      {
        type: 'deprecated',
        packageName: dep.name,
        command: `${uninstallCmd(pm, dep.name, dep.isDev)} && ${installCmd(pm, replacement, 'latest', dep.isDev)}`,
        description: `Replace deprecated \`${dep.name}\` with \`${replacement}\` (as suggested by the package maintainer)`,
        priority: 'high',
      },
    ];
  }

  // No clear replacement — suggest updating to latest, which may no longer be deprecated
  return [
    {
      type: 'deprecated',
      packageName: dep.name,
      command: installCmd(pm, dep.name, 'latest', dep.isDev),
      description: `Update \`${dep.name}\` to its latest version — check the package page for a recommended replacement`,
      priority: 'high',
    },
  ];
}

// ─── Command builders ─────────────────────────────────────────────────────────

function installCmd(pm: string, name: string, version: string, isDev: boolean): string {
  const ver = version === 'latest' ? '@latest' : `@${version}`;
  switch (pm) {
    case 'pnpm': return `pnpm add ${name}${ver}${isDev ? ' --save-dev' : ''}`;
    case 'yarn': return `yarn add ${name}${ver}${isDev ? ' --dev' : ''}`;
    case 'bun':  return `bun add ${name}${ver}${isDev ? ' --dev' : ''}`;
    default:     return `npm install ${name}${ver}${isDev ? ' --save-dev' : ''}`;
  }
}

function uninstallCmd(pm: string, name: string, _isDev: boolean): string {
  switch (pm) {
    case 'pnpm': return `pnpm remove ${name}`;
    case 'yarn': return `yarn remove ${name}`;
    case 'bun':  return `bun remove ${name}`;
    default:     return `npm uninstall ${name}`;
  }
}

function updateAllCmd(pm: string): string {
  switch (pm) {
    case 'pnpm': return 'pnpm update';
    case 'yarn': return 'yarn upgrade';
    case 'bun':  return 'bun update';
    default:     return 'npm update';
  }
}
