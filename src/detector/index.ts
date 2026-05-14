import { existsSync, readFileSync } from 'fs';
import { join, resolve, basename } from 'path';
import fg from 'fast-glob';
import type { PackageManager, ProjectInfo, WorkspaceInfo } from '../types/index.js';

// ─── Public API ──────────────────────────────────────────────────────────────

export function detectProjectInfo(directory: string): ProjectInfo {
  const resolvedDir = resolve(directory);
  const packageManager = detectPackageManager(resolvedDir);
  const projectName = getProjectName(resolvedDir);
  const workspaces = detectWorkspaces(resolvedDir, packageManager);

  return {
    name: projectName,
    directory: resolvedDir,
    packageManager,
    isMonorepo: workspaces.length > 0,
    workspaces,
  };
}

export function detectPackageManager(dir: string): PackageManager {
  // Ordered by specificity — bun.lockb is most specific
  if (existsSync(join(dir, 'bun.lockb')) || existsSync(join(dir, 'bun.lock'))) {
    return 'bun';
  }
  if (existsSync(join(dir, 'pnpm-lock.yaml'))) {
    return 'pnpm';
  }
  if (existsSync(join(dir, 'yarn.lock'))) {
    return 'yarn';
  }
  if (existsSync(join(dir, 'package-lock.json'))) {
    return 'npm';
  }
  if (
    existsSync(join(dir, 'deno.json')) ||
    existsSync(join(dir, 'deno.jsonc')) ||
    existsSync(join(dir, 'deno.lock'))
  ) {
    return 'deno';
  }
  // Fallback: bare package.json → assume npm
  if (existsSync(join(dir, 'package.json'))) {
    return 'npm';
  }
  return 'unknown';
}

export function getProjectName(dir: string): string {
  const pkgPath = join(dir, 'package.json');
  if (existsSync(pkgPath)) {
    try {
      const pkg = JSON.parse(readFileSync(pkgPath, 'utf-8')) as { name?: string };
      if (pkg.name) return pkg.name;
    } catch {
      // fall through
    }
  }
  return basename(dir) || 'unknown';
}

// ─── Workspace Detection ─────────────────────────────────────────────────────

function detectWorkspaces(dir: string, pm: PackageManager): WorkspaceInfo[] {
  // pnpm uses a separate YAML file
  if (pm === 'pnpm') {
    const wsPath = join(dir, 'pnpm-workspace.yaml');
    if (existsSync(wsPath)) {
      try {
        const content = readFileSync(wsPath, 'utf-8');
        const patterns = parsePnpmWorkspaceYaml(content);
        return resolveWorkspaceGlobs(dir, patterns, pm);
      } catch {
        // ignore
      }
    }
  }

  // npm / yarn / bun use the "workspaces" field in package.json
  const pkgPath = join(dir, 'package.json');
  if (existsSync(pkgPath)) {
    try {
      const pkg = JSON.parse(readFileSync(pkgPath, 'utf-8')) as {
        workspaces?: string[] | { packages?: string[] };
      };
      if (pkg.workspaces) {
        const patterns = Array.isArray(pkg.workspaces)
          ? pkg.workspaces
          : (pkg.workspaces.packages ?? []);
        return resolveWorkspaceGlobs(dir, patterns, pm);
      }
    } catch {
      // ignore
    }
  }

  return [];
}

function parsePnpmWorkspaceYaml(yaml: string): string[] {
  const patterns: string[] = [];
  const lines = yaml.split('\n');
  let inPackages = false;

  for (const line of lines) {
    if (line.trim() === 'packages:') {
      inPackages = true;
      continue;
    }
    if (inPackages) {
      const match = line.match(/^\s+-\s+['"]?(.+?)['"]?\s*$/);
      if (match) {
        patterns.push(match[1]);
      } else if (!line.startsWith(' ') && line.trim() !== '') {
        inPackages = false;
      }
    }
  }

  return patterns;
}

function resolveWorkspaceGlobs(
  rootDir: string,
  patterns: string[],
  pm: PackageManager,
): WorkspaceInfo[] {
  const workspaces: WorkspaceInfo[] = [];

  for (const pattern of patterns) {
    // Append /package.json so fast-glob locates workspace roots
    const globPattern = pattern.replace(/\/?$/, '') + '/package.json';

    try {
      const matches = fg.sync(globPattern, {
        cwd: rootDir,
        absolute: false,
        ignore: ['**/node_modules/**'],
      });

      for (const match of matches) {
        const wsDir = join(rootDir, match.replace(/[\\/]package\.json$/, ''));
        workspaces.push({
          name: getProjectName(wsDir),
          directory: wsDir,
          packageManager: pm,
        });
      }
    } catch {
      // ignore individual glob errors
    }
  }

  return workspaces;
}
