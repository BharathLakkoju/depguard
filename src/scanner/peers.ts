import { existsSync, readFileSync } from "fs";
import { join } from "path";
import semver from "semver";
import type { PeerDependencyIssue } from "../types/index.js";

// ─── Public API ───────────────────────────────────────────────────────────────

/**
 * Checks peer dependency requirements for every installed direct dependency.
 *
 * Results are grouped by peer package name so that if multiple installed
 * packages all require the same peer, the user sees one entry (with a list
 * of who requires it) instead of noisy duplicates.
 *
 * Optional peers are only reported when they ARE installed but at an
 * incompatible version; completely absent optional peers are silently ignored.
 */
export function scanPeerDeps(directory: string): PeerDependencyIssue[] {
  const directDeps = getDirectDeps(directory);
  if (Object.keys(directDeps).length === 0) return [];

  // Grouped map: peerName → accumulated issue
  const peerMap = new Map<
    string,
    {
      installedVersion: string | null;
      status: "missing" | "incompatible";
      optional: boolean;
      requiredBy: Array<{
        package: string;
        packageVersion: string;
        requiredRange: string;
      }>;
    }
  >();

  for (const [depName] of Object.entries(directDeps)) {
    const depPkgPath = join(directory, "node_modules", depName, "package.json");
    if (!existsSync(depPkgPath)) continue;

    let depPkg: {
      version?: string;
      peerDependencies?: Record<string, string>;
      peerDependenciesMeta?: Record<string, { optional?: boolean }>;
    };
    try {
      depPkg = JSON.parse(readFileSync(depPkgPath, "utf-8"));
    } catch {
      continue;
    }

    const {
      peerDependencies,
      peerDependenciesMeta,
      version: depVersion = "unknown",
    } = depPkg;

    if (!peerDependencies || Object.keys(peerDependencies).length === 0)
      continue;

    for (const [peerName, requiredRange] of Object.entries(peerDependencies)) {
      // Skip wildcard ranges — always satisfied
      if (!requiredRange || requiredRange === "*" || requiredRange === "")
        continue;

      const optional = peerDependenciesMeta?.[peerName]?.optional ?? false;

      const peerPkgPath = join(
        directory,
        "node_modules",
        peerName,
        "package.json",
      );

      let installedVersion: string | null = null;
      let status: "missing" | "incompatible" | null = null;

      if (!existsSync(peerPkgPath)) {
        // Only report missing for non-optional peers
        if (!optional) {
          status = "missing";
        } else {
          continue; // optional & absent = fine
        }
      } else {
        try {
          const peerPkg = JSON.parse(readFileSync(peerPkgPath, "utf-8")) as {
            version?: string;
          };
          installedVersion = peerPkg.version ?? null;
        } catch {
          continue;
        }

        if (installedVersion) {
          try {
            const satisfies = semver.satisfies(
              installedVersion,
              requiredRange,
              { includePrerelease: false },
            );
            if (!satisfies) status = "incompatible";
          } catch {
            // Invalid semver range — skip
            continue;
          }
        }
      }

      if (status === null) continue; // version is fine

      const entry = peerMap.get(peerName);
      if (entry) {
        entry.requiredBy.push({
          package: depName,
          packageVersion: depVersion,
          requiredRange,
        });
        // Escalate to 'missing' if any requiring package sees it as missing
        if (status === "missing") entry.status = "missing";
        // Mark non-optional if any requiree deems it mandatory
        if (!optional) entry.optional = false;
      } else {
        peerMap.set(peerName, {
          installedVersion,
          status,
          optional,
          requiredBy: [
            {
              package: depName,
              packageVersion: depVersion,
              requiredRange,
            },
          ],
        });
      }
    }
  }

  return Array.from(peerMap.entries()).map(([peerName, info]) => ({
    peerName,
    installedVersion: info.installedVersion,
    status: info.status,
    optional: info.optional,
    requiredBy: info.requiredBy,
  }));
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function getDirectDeps(directory: string): Record<string, string> {
  const pkgPath = join(directory, "package.json");
  if (!existsSync(pkgPath)) return {};
  try {
    const pkg = JSON.parse(readFileSync(pkgPath, "utf-8")) as {
      dependencies?: Record<string, string>;
      devDependencies?: Record<string, string>;
      optionalDependencies?: Record<string, string>;
      bundleDependencies?: string[] | boolean;
      bundledDependencies?: string[] | boolean;
    };
    const result: Record<string, string> = {
      ...(pkg.dependencies ?? {}),
      ...(pkg.optionalDependencies ?? {}),
      ...(pkg.devDependencies ?? {}),
    };
    const bundled = pkg.bundleDependencies ?? pkg.bundledDependencies;
    if (Array.isArray(bundled)) {
      for (const name of bundled) {
        if (!(name in result)) result[name] = "*";
      }
    }
    return result;
  } catch {
    return {};
  }
}
