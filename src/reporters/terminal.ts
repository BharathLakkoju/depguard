import chalk, { type ChalkInstance } from "chalk";
import Table from "cli-table3";
import type {
  ScanResult,
  DependencyInfo,
  Severity,
  FixSuggestion,
  SubDependencyIssue,
  PeerDependencyIssue,
  HoistedDepIssue,
  DepType,
} from "../types/index.js";

const RULE = chalk.gray("─".repeat(60));
const SHORT = chalk.gray("─".repeat(44));

// ─── Public API ──────────────────────────────────────────────────────────────

export function renderTerminalReport(results: ScanResult[]): void {
  for (const result of results) renderResult(result);
}

// ─── Per-Result ───────────────────────────────────────────────────────────────

function renderResult(result: ScanResult): void {
  const { dependencies, summary, errors } = result;

  console.log("\n");
  console.log(chalk.bold.cyan("  DepGuard  —  Dependency Health Report"));
  console.log(RULE);
  console.log(chalk.gray("  Project         ") + chalk.white(result.project));
  console.log(
    chalk.gray("  Package Manager ") + chalk.white(result.packageManager),
  );
  console.log(chalk.gray("  Directory       ") + chalk.white(result.directory));
  console.log(
    chalk.gray("  Scanned         ") +
      chalk.white(new Date(result.scanDate).toLocaleString()),
  );
  console.log(RULE);

  if (errors.length > 0) {
    console.log("");
    for (const e of errors) console.log(chalk.red(`  ⚠  ${e}`));
  }

  const vulnDeps = dependencies.filter((d) => d.vulnerabilities.length > 0);
  const deprecatedDeps = dependencies.filter((d) => d.deprecated);
  const outdatedDeps = dependencies.filter((d) => d.updateType !== "none");
  const staleDeps = dependencies.filter((d) => d.stale || d.archived);

  const hasDirectIssues =
    vulnDeps.length +
      deprecatedDeps.length +
      outdatedDeps.length +
      staleDeps.length >
    0;
  const hasExtended =
    result.subDependencyIssues.length > 0 ||
    result.peerDependencyIssues.length > 0 ||
    result.hoistedIssues.length > 0;

  if (!hasDirectIssues && !hasExtended) {
    console.log("");
    console.log(chalk.bold.green("  ✔  All dependencies look healthy!"));
    console.log("");
    console.log(RULE);
  } else {
    if (vulnDeps.length > 0) renderVulnerabilities(vulnDeps);
    if (deprecatedDeps.length > 0) renderDeprecated(deprecatedDeps);
    if (outdatedDeps.length > 0) renderOutdated(outdatedDeps);
    if (staleDeps.length > 0) renderMaintenance(staleDeps);

    if (result.subDependencyIssues.length > 0)
      renderTransitive(result.subDependencyIssues);
    if (result.peerDependencyIssues.length > 0)
      renderPeerDeps(result.peerDependencyIssues);
    if (result.hoistedIssues.length > 0) renderHoisted(result.hoistedIssues);
  }

  renderSummary(summary);

  if (result.suggestions.length > 0) renderFixSuggestions(result.suggestions);
}

// ─── Direct dep sections ──────────────────────────────────────────────────────

function renderVulnerabilities(deps: DependencyInfo[]): void {
  console.log("");
  console.log(chalk.bold.red("  🔴  Vulnerabilities"));
  console.log(SHORT);

  for (const dep of deps) {
    console.log("");
    console.log(
      "  " +
        chalk.bold.white(dep.name) +
        chalk.gray(`@${dep.current}`) +
        "  " +
        depTypeBadge(dep.depType),
    );
    for (const vuln of dep.vulnerabilities) {
      console.log(`    ${sevBadge(vuln.severity)}  ${chalk.white(vuln.title)}`);
      if (vuln.affectedVersions && vuln.affectedVersions !== "unknown")
        console.log(
          chalk.gray(`             Affected : ${vuln.affectedVersions}`),
        );
      if (vuln.fixedVersion)
        console.log(chalk.gray(`             Fixed in : ${vuln.fixedVersion}`));
      if (vuln.url) console.log(chalk.gray(`             ${vuln.url}`));
    }
  }
  console.log("");
}

function renderDeprecated(deps: DependencyInfo[]): void {
  console.log("");
  console.log(chalk.bold.yellow("  ⚠   Deprecated Packages"));
  console.log(SHORT);

  for (const dep of deps) {
    console.log("");
    console.log(
      "  " +
        chalk.bold.white(dep.name) +
        chalk.gray(`@${dep.current}`) +
        "  " +
        depTypeBadge(dep.depType),
    );
    const msg = dep.deprecationMessage ?? "Deprecated by maintainers";
    console.log(
      chalk.yellow(`    ${msg.length > 110 ? msg.slice(0, 107) + "..." : msg}`),
    );
  }
  console.log("");
}

function renderOutdated(deps: DependencyInfo[]): void {
  console.log("");
  console.log(chalk.bold.blue("  📦  Outdated Dependencies"));
  console.log(SHORT);

  const table = new Table({
    head: [
      chalk.bold.white("Package"),
      chalk.bold.white("Current"),
      chalk.bold.white("Latest"),
      chalk.bold.white("Update"),
      chalk.bold.white("Scope"),
    ],
    colWidths: [28, 12, 12, 9, 11],
    style: { head: [], border: ["gray"] },
  });

  const sorted = [...deps].sort((a, b) => {
    const o = { major: 0, minor: 1, patch: 2, none: 3 };
    return o[a.updateType] - o[b.updateType];
  });

  for (const dep of sorted) {
    const name =
      dep.name.length > 24 ? dep.name.slice(0, 21) + "..." : dep.name;
    table.push([
      chalk.white(name),
      chalk.gray(dep.current),
      chalk.green(dep.latest),
      updateBadge(dep.updateType),
      depTypeBadge(dep.depType),
    ]);
  }

  console.log(table.toString());
  console.log("");
}

function renderMaintenance(deps: DependencyInfo[]): void {
  console.log("");
  console.log(chalk.bold.magenta("  🧱  Maintenance Risks"));
  console.log(SHORT);

  for (const dep of deps) {
    console.log("");
    console.log(
      "  " +
        chalk.bold.white(dep.name) +
        chalk.gray(`@${dep.current}`) +
        "  " +
        depTypeBadge(dep.depType),
    );
    if (dep.stale && dep.lastPublished) {
      const date = new Date(dep.lastPublished);
      const months = Math.floor(
        (Date.now() - date.getTime()) / (1000 * 60 * 60 * 24 * 30),
      );
      console.log(
        chalk.magenta(`    No release in ${months} months`) +
          chalk.gray(` (last: ${date.toLocaleDateString()})`),
      );
    } else if (dep.stale) {
      console.log(chalk.magenta("    No recent releases"));
    }
    if (dep.archived) console.log(chalk.magenta("    Repository is archived"));
  }
  console.log("");
}

// ─── Extended layer sections ──────────────────────────────────────────────────

function renderTransitive(issues: SubDependencyIssue[]): void {
  console.log("");
  console.log(chalk.bold.red("  🔗  Transitive Dependency Vulnerabilities"));
  console.log(SHORT);
  console.log(
    chalk.gray(
      "  These vulnerabilities are in indirect (2nd-level) dependencies.",
    ),
  );

  for (const issue of issues) {
    console.log("");
    console.log(
      "  " +
        chalk.bold.white(issue.name) +
        chalk.gray(`@${issue.version}`) +
        (issue.requiredBy.length > 0
          ? chalk.gray(`  ← ${issue.requiredBy.join(", ")}`)
          : ""),
    );
    for (const vuln of issue.vulnerabilities) {
      console.log(`    ${sevBadge(vuln.severity)}  ${chalk.white(vuln.title)}`);
      if (vuln.affectedVersions && vuln.affectedVersions !== "unknown")
        console.log(
          chalk.gray(`             Affected : ${vuln.affectedVersions}`),
        );
      if (vuln.url) console.log(chalk.gray(`             ${vuln.url}`));
    }
  }
  console.log("");
}

function renderPeerDeps(issues: PeerDependencyIssue[]): void {
  console.log("");
  console.log(chalk.bold.yellow("  🤝  Peer Dependency Issues"));
  console.log(SHORT);

  for (const issue of issues) {
    console.log("");
    const statusBadge =
      issue.status === "missing"
        ? chalk.bgRed.white.bold(" MISSING      ")
        : chalk.bgYellow.black.bold(" INCOMPATIBLE ");
    const optLabel = issue.optional ? chalk.gray(" (optional)") : "";
    console.log(
      `  ${statusBadge}  ${chalk.bold.white(issue.peerName)}${optLabel}`,
    );

    if (issue.status === "incompatible" && issue.installedVersion) {
      console.log(chalk.gray(`    Installed : ${issue.installedVersion}`));
    }

    for (const req of issue.requiredBy) {
      console.log(
        chalk.gray(`    Required  : ${req.requiredRange}`) +
          chalk.gray(`  ← ${req.package}@${req.packageVersion}`),
      );
    }
  }
  console.log("");
}

function renderHoisted(issues: HoistedDepIssue[]): void {
  console.log("");
  console.log(chalk.bold.magenta("  👻  Hoisted / Phantom Dependencies"));
  console.log(SHORT);
  console.log(
    chalk.gray(
      "  Packages found in node_modules that are not declared in your package.json.",
    ),
  );

  for (const issue of issues) {
    console.log("");
    const phantomBadge = issue.isPhantom
      ? chalk.bgMagenta.white(" PHANTOM ")
      : "";
    const vulnBadge = issue.severity ? sevBadge(issue.severity) : "";
    console.log(
      `  ${phantomBadge}${vulnBadge}  ${chalk.bold.white(issue.name)}` +
        chalk.gray(`@${issue.version}`) +
        (issue.requiredBy.length > 0
          ? chalk.gray(`  ← ${issue.requiredBy.join(", ")}`)
          : ""),
    );
    for (const vuln of issue.vulnerabilities) {
      console.log(`    ${sevBadge(vuln.severity)}  ${chalk.white(vuln.title)}`);
      if (vuln.url) console.log(chalk.gray(`             ${vuln.url}`));
    }
    if (issue.isPhantom && issue.vulnerabilities.length === 0) {
      console.log(
        chalk.gray(
          "    Undeclared — if your code imports this, add it to package.json",
        ),
      );
    }
  }
  console.log("");
}

// ─── Summary ─────────────────────────────────────────────────────────────────

function renderSummary(summary: ScanResult["summary"]): void {
  console.log("");
  console.log(RULE);
  console.log(chalk.bold.white("  Summary"));
  console.log(SHORT);
  console.log("");

  // Direct deps
  const directRows: [string, number, ChalkInstance][] = [
    ["Total direct", summary.total, chalk.white],
    [
      "  ↳ optional",
      summary.optionalScanned,
      summary.optionalScanned > 0 ? chalk.cyan : chalk.gray,
    ],
    [
      "  ↳ bundled",
      summary.bundledScanned,
      summary.bundledScanned > 0 ? chalk.cyan : chalk.gray,
    ],
    [
      "Outdated",
      summary.outdated,
      summary.outdated > 0 ? chalk.yellow : chalk.green,
    ],
    [
      "Vulnerable",
      summary.vulnerable,
      summary.vulnerable > 0 ? chalk.red : chalk.green,
    ],
    [
      "Deprecated",
      summary.deprecated,
      summary.deprecated > 0 ? chalk.yellow : chalk.green,
    ],
    ["Stale", summary.stale, summary.stale > 0 ? chalk.magenta : chalk.green],
  ];
  for (const [label, value, color] of directRows) {
    if (label.startsWith("  ↳") && value === 0) continue;
    console.log(`  ${chalk.gray(label.padEnd(20))} ${color(String(value))}`);
  }

  // Extended layers
  const hasExtended =
    summary.transitiveVulnerable +
      summary.peerMissing +
      summary.peerIncompatible +
      summary.hoistedVulnerable +
      summary.phantomCount >
    0;

  if (hasExtended) {
    console.log("");
    console.log(chalk.bold.white("  Extended Layers"));
    console.log(SHORT);
    const extRows: [string, number, ChalkInstance][] = [
      [
        "Transitive vulns",
        summary.transitiveVulnerable,
        summary.transitiveVulnerable > 0 ? chalk.red : chalk.green,
      ],
      [
        "Peer missing",
        summary.peerMissing,
        summary.peerMissing > 0 ? chalk.red : chalk.green,
      ],
      [
        "Peer incompatible",
        summary.peerIncompatible,
        summary.peerIncompatible > 0 ? chalk.yellow : chalk.green,
      ],
      [
        "Hoisted vulnerable",
        summary.hoistedVulnerable,
        summary.hoistedVulnerable > 0 ? chalk.red : chalk.green,
      ],
      [
        "Phantom packages",
        summary.phantomCount,
        summary.phantomCount > 0 ? chalk.magenta : chalk.green,
      ],
    ];
    for (const [label, value, color] of extRows) {
      console.log(`  ${chalk.gray(label.padEnd(20))} ${color(String(value))}`);
    }
  }

  // Severity breakdown
  const hasSeverity =
    summary.critical + summary.high + summary.moderate + summary.low > 0;
  if (hasSeverity) {
    console.log("");
    console.log(chalk.bold.white("  Severity Breakdown (direct deps)"));
    console.log(SHORT);
    if (summary.critical > 0)
      console.log(
        `  ${chalk.bgRed.white.bold(` CRITICAL: ${summary.critical} `)}  ${chalk.red("Immediate action required")}`,
      );
    if (summary.high > 0)
      console.log(
        `  ${chalk.bgYellow.black.bold(` HIGH: ${summary.high} `)}      ${chalk.yellow("Action recommended")}`,
      );
    if (summary.moderate > 0)
      console.log(
        `  ${chalk.bgHex("#FF8C00").black(` MODERATE: ${summary.moderate} `)}  ${chalk.hex("#FF8C00")("Review suggested")}`,
      );
    if (summary.low > 0)
      console.log(
        `  ${chalk.bgBlue.white(` LOW: ${summary.low} `)}       ${chalk.blue("Low priority")}`,
      );
  }

  console.log("");
  console.log(RULE);
  console.log("");
}

// ─── Fix Suggestions ─────────────────────────────────────────────────────────

function renderFixSuggestions(suggestions: FixSuggestion[]): void {
  console.log("");
  console.log(chalk.bold.green("  🔧  Suggested Fixes"));
  console.log(RULE);

  const groups: Record<FixSuggestion["type"], FixSuggestion[]> = {
    vulnerability: [],
    deprecated: [],
    outdated: [],
    maintenance: [],
    peer: [],
    phantom: [],
  };
  for (const s of suggestions) groups[s.type].push(s);

  const sections: Array<
    [FixSuggestion["type"], string, (s: string) => string]
  > = [
    ["vulnerability", "Security", (s) => chalk.bold.red(s)],
    ["peer", "Peer Deps", (s) => chalk.bold.yellow(s)],
    ["phantom", "Phantom", (s) => chalk.bold.magenta(s)],
    ["deprecated", "Deprecated", (s) => chalk.bold.yellow(s)],
    ["outdated", "Outdated", (s) => chalk.bold.blue(s)],
    ["maintenance", "Maintenance", (s) => chalk.bold.magenta(s)],
  ];

  for (const [key, label, color] of sections) {
    const items = groups[key];
    if (items.length === 0) continue;

    console.log("");
    console.log(
      color(
        `  ${label}  (${items.length} suggestion${items.length > 1 ? "s" : ""})`,
      ),
    );
    console.log(SHORT);

    for (const item of items) {
      console.log("");
      console.log(
        `  ${fixPriorityBadge(item.priority)}  ${chalk.bgBlack.cyan(" $ ")} ${chalk.bold.white(item.command)}`,
      );
      console.log(chalk.gray(`            ${item.description}`));
    }
  }

  console.log("");
  console.log(RULE);
  console.log("");
}

// ─── Badge Helpers ────────────────────────────────────────────────────────────

function sevBadge(severity: Severity): string {
  switch (severity) {
    case "critical":
      return chalk.bgRed.white.bold(" CRITICAL ");
    case "high":
      return chalk.bgYellow.black.bold(" HIGH     ");
    case "moderate":
      return chalk.bgHex("#FF8C00").black(" MODERATE ");
    case "low":
      return chalk.bgBlue.white(" LOW      ");
  }
}

function updateBadge(type: string): string {
  switch (type) {
    case "major":
      return chalk.red("major");
    case "minor":
      return chalk.yellow("minor");
    case "patch":
      return chalk.green("patch");
    default:
      return chalk.gray("—");
  }
}

function depTypeBadge(depType: DepType): string {
  switch (depType) {
    case "production":
      return chalk.cyan("prod");
    case "dev":
      return chalk.gray("dev");
    case "optional":
      return chalk.blue("optional");
    case "bundled":
      return chalk.magenta("bundled");
  }
}

function fixPriorityBadge(priority: FixSuggestion["priority"]): string {
  switch (priority) {
    case "critical":
      return chalk.bgRed.white.bold(" CRITICAL ");
    case "high":
      return chalk.bgYellow.black.bold(" HIGH     ");
    case "medium":
      return chalk.bgHex("#FF8C00").black(" MEDIUM   ");
    case "low":
      return chalk.bgBlue.white(" LOW      ");
  }
}
