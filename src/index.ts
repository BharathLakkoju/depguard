import chalk from "chalk";
import ora from "ora";
import { createProgram } from "./cli/program.js";
import { detectProjectInfo } from "./detector/index.js";
import { runScan } from "./scanner/index.js";
import { analyzeDependencies, computeSummary } from "./analyzers/index.js";
import { generateReport } from "./reporters/index.js";
import { generateFixSuggestions } from "./fixers/index.js";
import type { ScanOptions, ScanResult } from "./types/index.js";

// ─── CLI Options (raw from commander) ────────────────────────────────────────

type CliOpts = {
  json?: boolean;
  markdown?: boolean;
  failOnHigh?: boolean;
  ignore?: string;
  workspace?: boolean;
  deep?: boolean;
  production?: boolean;
  auditOnly?: boolean;
};

// ─── Core scan logic ──────────────────────────────────────────────────────────

async function scanDirectory(
  directory: string,
  options: ScanOptions,
): Promise<ScanResult> {
  const projectInfo = detectProjectInfo(directory);
  const errors: string[] = [];

  if (projectInfo.packageManager === "unknown") {
    errors.push(
      "Could not detect a package manager. Make sure this is a JavaScript/TypeScript project with a lockfile.",
    );
    return {
      project: projectInfo.name,
      packageManager: "unknown",
      directory,
      dependencies: [],
      scanDate: new Date().toISOString(),
      summary: {
        total: 0,
        outdated: 0,
        vulnerable: 0,
        deprecated: 0,
        stale: 0,
        critical: 0,
        high: 0,
        moderate: 0,
        low: 0,
      },
      errors,
      suggestions: [],
    };
  }

  // Run package-manager-specific scanner
  let rawData;
  try {
    rawData = await runScan(directory, projectInfo.packageManager, {
      production: options.production,
      deep: options.deep,
    });
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    errors.push(`Scanner error: ${msg}`);
    rawData = { outdated: [], vulnerabilities: [] };
  }

  // Enrich with vulnerability / deprecation / maintenance data
  const dependencies = await analyzeDependencies(rawData, {
    deep: options.deep,
    ignore: options.ignore,
    auditOnly: options.auditOnly,
  });

  const suggestions = generateFixSuggestions(
    dependencies,
    projectInfo.packageManager,
  );

  return {
    project: projectInfo.name,
    packageManager: projectInfo.packageManager,
    directory,
    dependencies,
    scanDate: new Date().toISOString(),
    summary: computeSummary(dependencies),
    errors,
    suggestions,
  };
}

// ─── Main scan runner ─────────────────────────────────────────────────────────

async function performScan(directory: string, cliOpts: CliOpts): Promise<void> {
  const options: ScanOptions = {
    directory,
    json: cliOpts.json ?? false,
    markdown: cliOpts.markdown ?? false,
    failOnHigh: cliOpts.failOnHigh ?? false,
    ignore: cliOpts.ignore
      ? cliOpts.ignore
          .split(",")
          .map((s) => s.trim())
          .filter(Boolean)
      : [],
    workspace: cliOpts.workspace ?? false,
    deep: cliOpts.deep ?? false,
    auditOnly: cliOpts.auditOnly ?? false,
    production: cliOpts.production ?? false,
  };

  const silent = options.json || options.markdown;

  const spinner = silent
    ? null
    : ora({ text: chalk.cyan("Detecting project…"), spinner: "dots" }).start();

  try {
    const projectInfo = detectProjectInfo(directory);

    if (!silent) {
      spinner?.succeed(
        chalk.green(
          `Detected ${chalk.bold(projectInfo.packageManager)} project: ${chalk.bold(projectInfo.name)}`,
        ),
      );
    }

    const results: ScanResult[] = [];

    // ── Workspace mode ───────────────────────────────────────────────────────
    if (
      options.workspace &&
      projectInfo.isMonorepo &&
      projectInfo.workspaces.length > 0
    ) {
      for (const ws of projectInfo.workspaces) {
        const wsSpinner = silent
          ? null
          : ora({
              text: chalk.cyan(`Scanning workspace: ${ws.name}…`),
              spinner: "dots",
            }).start();

        const result = await scanDirectory(ws.directory, options);
        results.push(result);

        wsSpinner?.succeed(
          chalk.green(
            `${ws.name}: ${result.dependencies.length} deps analysed`,
          ),
        );
      }
    } else {
      // ── Single-project mode ────────────────────────────────────────────────
      const scanSpinner = silent
        ? null
        : ora({
            text: chalk.cyan("Scanning dependencies…"),
            spinner: "dots",
          }).start();

      const result = await scanDirectory(directory, options);
      results.push(result);

      scanSpinner?.succeed(
        chalk.green(
          `Scan complete — ${result.dependencies.length} dependencies analysed`,
        ),
      );
    }

    // ── Output ───────────────────────────────────────────────────────────────
    generateReport(results, { json: options.json, markdown: options.markdown });

    // ── CI failure mode ───────────────────────────────────────────────────────
    if (options.failOnHigh) {
      const fail = results.some(
        (r) => r.summary.critical > 0 || r.summary.high > 0,
      );
      if (fail) {
        if (!silent) {
          console.error(
            chalk.red(
              "\n  ✗  Exiting with code 1: high or critical issues detected.\n",
            ),
          );
        }
        process.exit(1);
      }
    }
  } catch (err: unknown) {
    spinner?.fail(chalk.red("Scan failed"));
    const msg = err instanceof Error ? err.message : String(err);
    console.error(chalk.red(`\n  Error: ${msg}\n`));
    if (process.env["DEBUG"]) console.error(err);
    process.exit(1);
  }
}

// ─── Program setup ────────────────────────────────────────────────────────────

function addSharedFlags(
  cmd:
    | ReturnType<ReturnType<typeof createProgram>["command"]>
    | ReturnType<typeof createProgram>,
) {
  return cmd
    .option("--json", "Output as JSON (machine-readable)")
    .option("--markdown", "Output as Markdown")
    .option(
      "--fail-on-high",
      "Exit with code 1 if high/critical issues are found (CI mode)",
    )
    .option("--ignore <packages>", "Comma-separated list of packages to skip")
    .option(
      "--production",
      "Only scan production dependencies (skip devDependencies)",
    );
}

async function main(): Promise<void> {
  const program = createProgram();

  // ── Default command: scan current directory ───────────────────────────────
  addSharedFlags(program)
    .option("--workspace", "Scan all workspaces in a monorepo")
    .action(async (opts: CliOpts) => {
      await performScan(".", opts);
    });

  // ── scan [directory] ──────────────────────────────────────────────────────
  addSharedFlags(
    program
      .command("scan [directory]")
      .description("Scan dependencies in a specific directory"),
  )
    .option("--workspace", "Scan all workspaces in a monorepo")
    .option("--deep", "Include transitive (indirect) dependencies")
    .action(async (directory: string | undefined, opts: CliOpts) => {
      await performScan(directory ?? ".", opts);
    });

  // ── audit ─────────────────────────────────────────────────────────────────
  addSharedFlags(
    program
      .command("audit")
      .description(
        "Security-only scan — vulnerabilities only, skips outdated/stale checks",
      ),
  ).action(async (opts: CliOpts) => {
    await performScan(".", { ...opts, auditOnly: true });
  });

  await program.parseAsync(process.argv);
}

main().catch((err: unknown) => {
  const msg = err instanceof Error ? err.message : String(err);
  console.error(chalk.red(`Fatal: ${msg}`));
  process.exit(1);
});
