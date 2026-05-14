import type { ScanResult, Severity } from '../types/index.js';

// ─── Public API ──────────────────────────────────────────────────────────────

export function renderMarkdownReport(results: ScanResult[]): string {
  return results.map(renderResult).join('\n\n---\n\n');
}

// ─── Per-Result Rendering ─────────────────────────────────────────────────────

function renderResult(result: ScanResult): string {
  const lines: string[] = [];
  const { dependencies, summary } = result;

  lines.push('# Dependency Health Report');
  lines.push('');
  lines.push('| Field | Value |');
  lines.push('|-------|-------|');
  lines.push(`| **Project** | \`${result.project}\` |`);
  lines.push(`| **Package Manager** | ${result.packageManager} |`);
  lines.push(`| **Directory** | \`${result.directory}\` |`);
  lines.push(`| **Scan Date** | ${new Date(result.scanDate).toLocaleString()} |`);
  lines.push('');

  // ── Summary badges ──────────────────────────────────────────────────────────
  lines.push('## Summary');
  lines.push('');
  lines.push(
    [
      badge('Total', summary.total, 'blue'),
      badge('Outdated', summary.outdated, summary.outdated > 0 ? 'yellow' : 'brightgreen'),
      badge('Vulnerable', summary.vulnerable, summary.vulnerable > 0 ? 'red' : 'brightgreen'),
      badge('Deprecated', summary.deprecated, summary.deprecated > 0 ? 'orange' : 'brightgreen'),
      badge('Stale', summary.stale, summary.stale > 0 ? 'orange' : 'brightgreen'),
    ].join(' '),
  );
  lines.push('');

  // ── Vulnerabilities ─────────────────────────────────────────────────────────
  const vulnDeps = dependencies.filter((d) => d.vulnerabilities.length > 0);
  if (vulnDeps.length > 0) {
    lines.push('## 🔴 Vulnerabilities');
    lines.push('');
    lines.push('| Package | Version | Severity | Title | Reference |');
    lines.push('|---------|---------|----------|-------|-----------|');
    for (const dep of vulnDeps) {
      for (const v of dep.vulnerabilities) {
        const sevBadge = severityBadge(v.severity);
        const ref = v.url ? `[${v.id}](${v.url})` : v.id;
        lines.push(`| \`${dep.name}\` | \`${dep.current}\` | ${sevBadge} | ${v.title} | ${ref} |`);
      }
    }
    lines.push('');
  }

  // ── Deprecated ──────────────────────────────────────────────────────────────
  const deprecatedDeps = dependencies.filter((d) => d.deprecated);
  if (deprecatedDeps.length > 0) {
    lines.push('## ⚠️ Deprecated Packages');
    lines.push('');
    lines.push('| Package | Version | Message |');
    lines.push('|---------|---------|---------|');
    for (const dep of deprecatedDeps) {
      const msg = dep.deprecationMessage ?? 'Deprecated by maintainers';
      lines.push(`| \`${dep.name}\` | \`${dep.current}\` | ${msg.slice(0, 80)} |`);
    }
    lines.push('');
  }

  // ── Outdated ────────────────────────────────────────────────────────────────
  const outdatedDeps = dependencies.filter((d) => d.updateType !== 'none');
  if (outdatedDeps.length > 0) {
    lines.push('## 📦 Outdated Dependencies');
    lines.push('');
    lines.push('| Package | Current | Latest | Update Type |');
    lines.push('|---------|---------|--------|-------------|');
    const sorted = [...outdatedDeps].sort((a, b) => {
      const o = { major: 0, minor: 1, patch: 2, none: 3 };
      return o[a.updateType] - o[b.updateType];
    });
    for (const dep of sorted) {
      lines.push(`| \`${dep.name}\` | \`${dep.current}\` | \`${dep.latest}\` | **${dep.updateType}** |`);
    }
    lines.push('');
  }

  // ── Maintenance Risks ───────────────────────────────────────────────────────
  const staleDeps = dependencies.filter((d) => d.stale || d.archived);
  if (staleDeps.length > 0) {
    lines.push('## 🧱 Maintenance Risks');
    lines.push('');
    lines.push('| Package | Version | Last Published | Status |');
    lines.push('|---------|---------|----------------|--------|');
    for (const dep of staleDeps) {
      const lastPub = dep.lastPublished
        ? new Date(dep.lastPublished).toLocaleDateString()
        : 'Unknown';
      const status = dep.archived ? '🗄️ Archived' : '⏰ Stale';
      lines.push(`| \`${dep.name}\` | \`${dep.current}\` | ${lastPub} | ${status} |`);
    }
    lines.push('');
  }

  // ── Errors ──────────────────────────────────────────────────────────────────
  if (result.errors.length > 0) {
    lines.push('## ⚠️ Scan Errors');
    lines.push('');
    for (const e of result.errors) lines.push(`- ${e}`);
    lines.push('');
  }

  return lines.join('\n');
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function badge(label: string, value: number, color: string): string {
  return `![${label}](https://img.shields.io/badge/${encodeURIComponent(label)}-${value}-${color})`;
}

function severityBadge(s: Severity): string {
  const colorMap: Record<Severity, string> = {
    critical: 'red',
    high: 'orange',
    moderate: 'yellow',
    low: 'blue',
  };
  return `![${s}](https://img.shields.io/badge/${s}-${colorMap[s]})`;
}
