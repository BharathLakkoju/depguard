import type { DependencyInfo } from '../types/index.js';

const NPM_REGISTRY = 'https://registry.npmjs.org';
const CONCURRENCY = 5;

// ─── Registry Types ───────────────────────────────────────────────────────────

interface NpmPackage {
  name: string;
  'dist-tags': Record<string, string>;
  versions: Record<string, { deprecated?: string }>;
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

async function fetchNpmPackage(name: string): Promise<NpmPackage | null> {
  try {
    const res = await fetch(`${NPM_REGISTRY}/${encodeURIComponent(name)}`, {
      signal: AbortSignal.timeout(10_000),
    });
    if (!res.ok) return null;
    return res.json() as Promise<NpmPackage>;
  } catch {
    return null;
  }
}

// ─── Public API ──────────────────────────────────────────────────────────────

export async function enrichWithDeprecationInfo(
  dependencies: DependencyInfo[],
): Promise<DependencyInfo[]> {
  const results = [...dependencies];

  for (let i = 0; i < results.length; i += CONCURRENCY) {
    await Promise.all(
      results.slice(i, i + CONCURRENCY).map(async (dep, offset) => {
        const idx = i + offset;
        const pkg = await fetchNpmPackage(dep.name);
        if (!pkg) return;

        // 1. Check if the installed version itself is deprecated
        const installedDeprecation = pkg.versions?.[dep.current]?.deprecated;
        if (installedDeprecation) {
          results[idx] = {
            ...results[idx],
            deprecated: true,
            deprecationMessage: installedDeprecation,
          };
          return;
        }

        // 2. Fall back: check if the latest published version is deprecated
        //    (indicates the whole package is being phased out)
        const latestTag = pkg['dist-tags']?.latest;
        const latestDeprecation = latestTag
          ? pkg.versions?.[latestTag]?.deprecated
          : undefined;
        if (latestDeprecation) {
          results[idx] = {
            ...results[idx],
            deprecated: true,
            deprecationMessage: latestDeprecation,
          };
        }
      }),
    );
  }

  return results;
}
