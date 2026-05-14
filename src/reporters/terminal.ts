import chalk, { type ChalkInstance } from "chalk";
import Table from "cli-table3";
import type {
  ScanResult,
  DependencyInfo,
  Severity,
  FixSuggestion,
} from "../types/index.js";

const RULE = chalk.gray("─".repeat(60));
const SHORT = chalk.gray("─".repeat(44));

// ─── Public API ──────────────────────────────────────────────────────────────

export function renderTerminalReport(results: ScanResult[]): void {
  for (const result of results) renderResult(result);
}

// ─── Per-Result Rendering ─────────────────────────────────────────────────────

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

  if (dependencies.length === 0) {
    console.log("");
    console.log(chalk.bold.green("  ✔  All dependencies look healthy!"));
    console.log("");
    console.log(RULE);
    return;
  }

  const vulnDeps = dependencies.filter((d) => d.vulnerabilities.length > 0);
  const deprecatedDeps = dependencies.filter((d) => d.deprecated);
  const outdatedDeps = dependencies.filter((d) => d.updateType !== "none");
  const staleDeps = dependencies.filter((d) => d.stale || d.archived);

  if (vulnDeps.length > 0) renderVulnerabilities(vulnDeps);
  if (deprecatedDeps.length > 0) renderDeprecated(deprecatedDeps);
  if (outdatedDeps.length > 0) renderOutdated(outdatedDeps);
  if (staleDeps.length > 0) renderMaintenance(staleDeps);

  renderSummary(summary);

  if (result.suggestions.length > 0) renderFixSuggestions(result.suggestions);
}

// ─── Section Renderers ────────────────────────────────────────────────────────

function renderVulnerabilities(deps: DependencyInfo[]): void {
  console.log("");
  console.log(chalk.bold.red("  🔴  Vulnerabilities"));
  console.log(SHORT);

  for (const dep of deps) {
    console.log("");
    console.log(
      "  " + chalk.bold.white(dep.name) + chalk.gray(`@${dep.current}`),
    );
    for (const vuln of dep.vulnerabilities) {
      const badge = sevBadge(vuln.severity);
      console.log(`    ${badge}  ${chalk.white(vuln.title)}`);
      if (vuln.affectedVersions && vuln.affectedVersions !== "unknown") {
        console.log(
          chalk.gray(`             Affected : ${vuln.affectedVersions}`),
        );
      }
      if (vuln.fixedVersion) {
        console.log(chalk.gray(`             Fixed in : ${vuln.fixedVersion}`));
      }
      if (vuln.url) {
        console.log(chalk.gray(`             ${vuln.url}`));
      }
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
      "  " + chalk.bold.white(dep.name) + chalk.gray(`@${dep.current}`),
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
      chalk.bold.white("Type"),
    ],
    colWidths: [32, 14, 14, 10],
    style: { head: [], border: ["gray"] },
  });

  // Sort: major → minor → patch
  const sorted = [...deps].sort((a, b) => {
    const o = { major: 0, minor: 1, patch: 2, none: 3 };
    return o[a.updateType] - o[b.updateType];
  });

  for (const dep of sorted) {
    const name =
      dep.name.length > 28 ? dep.name.slice(0, 25) + "..." : dep.name;
    table.push([
      chalk.white(name),
      chalk.gray(dep.current),
      chalk.green(dep.latest),
      updateBadge(dep.updateType),
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
      "  " + chalk.bold.white(dep.name) + chalk.gray(`@${dep.current}`),
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
    if (dep.archived) {
      console.log(chalk.magenta("    Repository is archived"));
    }
  }
  console.log("");
}

function renderSummary(summary: ScanResult["summary"]): void {
  console.log("");
  console.log(RULE);
  console.log(chalk.bold.white("  Summary"));
  console.log(SHORT);
  console.log("");

  const rows: [string, number, ChalkInstance][] = [
    ["Total scanned", summary.total, chalk.white],
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

  for (const [label, value, color] of rows) {
    console.log(`  ${chalk.gray(label.padEnd(20))} ${color(String(value))}`);
  }

  const hasSeverity =
    summary.critical + summary.high + summary.moderate + summary.low > 0;
  if (hasSeverity) {
    console.log("");
    console.log(chalk.bold.white("  Severity Breakdown"));
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

  // Group by type
  const groups: Record<FixSuggestion["type"], FixSuggestion[]> = {
    vulnerability: [],
    deprecated: [],
    outdated: [],
    maintenance: [],
  };
  for (const s of suggestions) groups[s.type].push(s);

  const sections: Array<
    [FixSuggestion["type"], string, (s: string) => string]
  > = [
    ["vulnerability", "Security", (s) => chalk.bold.red(s)],
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
      const priorityBadge = fixPriorityBadge(item.priority);
      console.log("");
      // Command in a highlighted box
      console.log(
        `  ${priorityBadge}  ${chalk.bgBlack.cyan(" $ ")} ${chalk.bold.white(item.command)}`,
      );
      // Description underneath
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
