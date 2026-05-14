import type {
  ScanResult,
  Severity,
  FixSuggestion,
  DepType,
  SubDependencyIssue,
  PeerDependencyIssue,
  HoistedDepIssue,
} from "../types/index.js";

// ─── Public API ──────────────────────────────────────────────────────────────

export function renderMarkdownReport(results: ScanResult[]): string {
  return results.map(renderResult).join("\n\n---\n\n");
}

// ─── Per-Result ───────────────────────────────────────────────────────────────

function renderResult(result: ScanResult): string {
  const lines: string[] = [];
  const { dependencies, summary } = result;

  lines.push("# Dependency Health Report");
  lines.push("");
  lines.push("| Field | Value |");
  lines.push("|-------|-------|");
  lines.push(`| **Project** | \`${result.project}\` |`);
  lines.push(`| **Package Manager** | ${result.packageManager} |`);
  lines.push(`| **Directory** | \`${result.directory}\` |`);
  lines.push(
    `| **Scan Date** | ${new Date(result.scanDate).toLocaleString()} |`,
  );
  lines.push("");

  // ── Summary badges ──────────────────────────────────────────────────────────
  lines.push("## Summary");
  lines.push("");
  lines.push(
    [
      badge("Total", summary.total, "blue"),
      badge(
        "Outdated",
        summary.outdated,
        summary.outdated > 0 ? "yellow" : "brightgreen",
      ),
      badge(
        "Vulnerable",
        summary.vulnerable,
        summary.vulnerable > 0 ? "red" : "brightgreen",
      ),
      badge(
        "Deprecated",
        summary.deprecated,
        summary.deprecated > 0 ? "orange" : "brightgreen",
      ),
      badge(
        "Stale",
        summary.stale,
        summary.stale > 0 ? "orange" : "brightgreen",
      ),
      badge(
        "Transitive Vulns",
        summary.transitiveVulnerable,
        summary.transitiveVulnerable > 0 ? "red" : "brightgreen",
      ),
      badge(
        "Peer Issues",
        summary.peerMissing + summary.peerIncompatible,
        summary.peerMissing + summary.peerIncompatible > 0
          ? "orange"
          : "brightgreen",
      ),
      badge(
        "Phantom",
        summary.phantomCount,
        summary.phantomCount > 0 ? "yellow" : "brightgreen",
      ),
    ].join(" "),
  );
  lines.push("");

  if (summary.optionalScanned > 0 || summary.bundledScanned > 0) {
    lines.push("| Dep Type | Count |");
    lines.push("|----------|-------|");
    if (summary.optionalScanned > 0)
      lines.push(`| optional | ${summary.optionalScanned} |`);
    if (summary.bundledScanned > 0)
      lines.push(`| bundled  | ${summary.bundledScanned} |`);
    lines.push("");
  }

  // ── Vulnerabilities ─────────────────────────────────────────────────────────
  const vulnDeps = dependencies.filter((d) => d.vulnerabilities.length > 0);
  if (vulnDeps.length > 0) {
    lines.push("## 🔴 Vulnerabilities (Direct)");
    lines.push("");
    lines.push("| Package | Version | Scope | Severity | Title | Reference |");
    lines.push("|---------|---------|-------|----------|-------|-----------|");
    for (const dep of vulnDeps) {
      for (const v of dep.vulnerabilities) {
        const ref = v.url ? `[${v.id}](${v.url})` : v.id;
        lines.push(
          `| \`${dep.name}\` | \`${dep.current}\` | ${dep.depType} | ${severityBadge(v.severity)} | ${v.title} | ${ref} |`,
        );
      }
    }
    lines.push("");
  }

  // ── Transitive Vulnerabilities ──────────────────────────────────────────────
  if (result.subDependencyIssues.length > 0) {
    lines.push("## 🔗 Transitive Dependency Vulnerabilities");
    lines.push("");
    lines.push(
      "> These vulnerabilities are in **indirect** (2nd-level) dependencies brought in by your direct deps.",
    );
    lines.push("");
    lines.push("| Package | Version | Brought in by | Severity | Title |");
    lines.push("|---------|---------|---------------|----------|-------|");
    for (const issue of result.subDependencyIssues) {
      for (const v of issue.vulnerabilities) {
        const parents =
          issue.requiredBy.length > 0 ? issue.requiredBy.join(", ") : "—";
        lines.push(
          `| \`${issue.name}\` | \`${issue.version}\` | ${parents} | ${severityBadge(v.severity)} | ${v.title} |`,
        );
      }
    }
    lines.push("");
  }

  // ── Deprecated ──────────────────────────────────────────────────────────────
  const deprecatedDeps = dependencies.filter((d) => d.deprecated);
  if (deprecatedDeps.length > 0) {
    lines.push("## ⚠️ Deprecated Packages");
    lines.push("");
    lines.push("| Package | Version | Scope | Message |");
    lines.push("|---------|---------|-------|---------|");
    for (const dep of deprecatedDeps) {
      const msg = dep.deprecationMessage ?? "Deprecated by maintainers";
      lines.push(
        `| \`${dep.name}\` | \`${dep.current}\` | ${dep.depType} | ${msg.slice(0, 80)} |`,
      );
    }
    lines.push("");
  }

  // ── Outdated ────────────────────────────────────────────────────────────────
  const outdatedDeps = dependencies.filter((d) => d.updateType !== "none");
  if (outdatedDeps.length > 0) {
    lines.push("## 📦 Outdated Dependencies");
    lines.push("");
    lines.push("| Package | Current | Latest | Update Type | Scope |");
    lines.push("|---------|---------|--------|-------------|-------|");
    const sorted = [...outdatedDeps].sort((a, b) => {
      const o = { major: 0, minor: 1, patch: 2, none: 3 };
      return o[a.updateType] - o[b.updateType];
    });
    for (const dep of sorted) {
      lines.push(
        `| \`${dep.name}\` | \`${dep.current}\` | \`${dep.latest}\` | **${dep.updateType}** | ${dep.depType} |`,
      );
    }
    lines.push("");
  }

  // ── Maintenance Risks ───────────────────────────────────────────────────────
  const staleDeps = dependencies.filter((d) => d.stale || d.archived);
  if (staleDeps.length > 0) {
    lines.push("## 🧱 Maintenance Risks");
    lines.push("");
    lines.push("| Package | Version | Scope | Last Published | Status |");
    lines.push("|---------|---------|-------|----------------|--------|");
    for (const dep of staleDeps) {
      const lastPub = dep.lastPublished
        ? new Date(dep.lastPublished).toLocaleDateString()
        : "Unknown";
      const status = dep.archived ? "🗄️ Archived" : "⏰ Stale";
      lines.push(
        `| \`${dep.name}\` | \`${dep.current}\` | ${dep.depType} | ${lastPub} | ${status} |`,
      );
    }
    lines.push("");
  }

  // ── Peer Dependency Issues ───────────────────────────────────────────────────
  if (result.peerDependencyIssues.length > 0) {
    lines.push("## 🤝 Peer Dependency Issues");
    lines.push("");
    lines.push("| Status | Peer | Installed | Required Range | Required by |");
    lines.push("|--------|------|-----------|----------------|-------------|");
    for (const issue of result.peerDependencyIssues) {
      const status =
        issue.status === "missing" ? "❌ Missing" : "⚠️ Incompatible";
      const installed = issue.installedVersion ?? "—";
      const ranges = issue.requiredBy.map((r) => r.requiredRange).join(", ");
      const reqBy = issue.requiredBy
        .map((r) => `${r.package}@${r.packageVersion}`)
        .join(", ");
      lines.push(
        `| ${status} | \`${issue.peerName}\` | \`${installed}\` | ${ranges} | ${reqBy} |`,
      );
    }
    lines.push("");
  }

  // ── Hoisted / Phantom ───────────────────────────────────────────────────────
  if (result.hoistedIssues.length > 0) {
    lines.push("## 👻 Hoisted / Phantom Dependencies");
    lines.push("");
    lines.push(
      "> Packages present in `node_modules` that are **not declared** in `package.json`.",
    );
    lines.push("");
    lines.push(
      "| Package | Version | Phantom | Severity | Brought in by | Notes |",
    );
    lines.push(
      "|---------|---------|---------|----------|---------------|-------|",
    );
    for (const issue of result.hoistedIssues) {
      const phantom = issue.isPhantom ? "👻 Yes" : "No";
      const topSev = issue.severity ? severityBadge(issue.severity) : "—";
      const parents =
        issue.requiredBy.length > 0 ? issue.requiredBy.join(", ") : "—";
      const vulnNote =
        issue.vulnerabilities.length > 0
          ? issue.vulnerabilities.map((v) => v.title).join("; ")
          : issue.isPhantom
            ? "Undeclared dependency"
            : "";
      lines.push(
        `| \`${issue.name}\` | \`${issue.version}\` | ${phantom} | ${topSev} | ${parents} | ${vulnNote} |`,
      );
    }
    lines.push("");
  }

  // ── Errors ──────────────────────────────────────────────────────────────────
  if (result.errors.length > 0) {
    lines.push("## ⚠️ Scan Errors");
    lines.push("");
    for (const e of result.errors) lines.push(`- ${e}`);
    lines.push("");
  }

  // ── Suggested Fixes ────────────────────────────────────────────────────────
  if (result.suggestions.length > 0) {
    lines.push("## 🔧 Suggested Fixes");
    lines.push("");
    lines.push("Run these commands to resolve the issues found above.");
    lines.push("");

    const groups: Record<FixSuggestion["type"], FixSuggestion[]> = {
      vulnerability: [],
      deprecated: [],
      outdated: [],
      maintenance: [],
      peer: [],
      phantom: [],
    };
    for (const s of result.suggestions) groups[s.type].push(s);

    const sections: Array<[FixSuggestion["type"], string]> = [
      ["vulnerability", "🔴 Security"],
      ["peer", "🤝 Peer Deps"],
      ["phantom", "👻 Phantom"],
      ["deprecated", "⚠️ Deprecated"],
      ["outdated", "📦 Outdated"],
      ["maintenance", "🧱 Maintenance"],
    ];

    for (const [key, label] of sections) {
      const items = groups[key];
      if (items.length === 0) continue;
      lines.push(`### ${label}`);
      lines.push("");
      lines.push("| Priority | Command | Description |");
      lines.push("|----------|---------|-------------|");
      for (const item of items) {
        const p = fixPriorityBadge(item.priority);
        const cmd = `\`${item.command}\``;
        lines.push(`| ${p} | ${cmd} | ${item.description} |`);
      }
      lines.push("");
    }
  }

  return lines.join("\n");
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function badge(label: string, value: number, color: string): string {
  return `![${label}](https://img.shields.io/badge/${encodeURIComponent(label)}-${value}-${color})`;
}

function severityBadge(s: Severity): string {
  const colorMap: Record<Severity, string> = {
    critical: "red",
    high: "orange",
    moderate: "yellow",
    low: "blue",
  };
  return `![${s}](https://img.shields.io/badge/${s}-${colorMap[s]})`;
}

function fixPriorityBadge(priority: FixSuggestion["priority"]): string {
  const colorMap: Record<FixSuggestion["priority"], string> = {
    critical: "red",
    high: "orange",
    medium: "yellow",
    low: "blue",
  };
  return `![${priority}](https://img.shields.io/badge/${priority}-${colorMap[priority]})`;
}

// kept for potential future use — dep-type badge in markdown
// eslint-disable-next-line @typescript-eslint/no-unused-vars
function _depTypeBadge(depType: DepType): string {
  const colorMap: Record<DepType, string> = {
    production: "blue",
    dev: "grey",
    optional: "cyan",
    bundled: "purple",
  };
  return `![${depType}](https://img.shields.io/badge/${depType}-${colorMap[depType]})`;
}
