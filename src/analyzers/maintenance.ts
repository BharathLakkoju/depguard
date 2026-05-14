import type { DependencyInfo } from '../types/index.js';

const NPM_REGISTRY = 'https://registry.npmjs.org';
const STALE_MONTHS = 24;
const CONCURRENCY = 5;

// ─── Registry Types ───────────────────────────────────────────────────────────

interface NpmPackageMeta {
  name: string;
  time?: Record<string, string>;
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

async function fetchPackageMeta(name: string): Promise<NpmPackageMeta | null> {
  try {
    const res = await fetch(`${NPM_REGISTRY}/${encodeURIComponent(name)}`, {
      signal: AbortSignal.timeout(10_000),
    });
    if (!res.ok) return null;
    return res.json() as Promise<NpmPackageMeta>;
  } catch {
    return null;
  }
}

function monthsAgo(isoDate: string): number {
  const then = new Date(isoDate);
  const now = new Date();
  return (
    (now.getFullYear() - then.getFullYear()) * 12 +
    (now.getMonth() - then.getMonth())
  );
}

// ─── Public API ──────────────────────────────────────────────────────────────

export async function enrichWithMaintenanceInfo(
  dependencies: DependencyInfo[],
): Promise<DependencyInfo[]> {
  const results = [...dependencies];

  for (let i = 0; i < results.length; i += CONCURRENCY) {
    await Promise.all(
      results.slice(i, i + CONCURRENCY).map(async (dep, offset) => {
        const idx = i + offset;
        const meta = await fetchPackageMeta(dep.name);
        if (!meta?.time) return;

        // Collect only version timestamps (exclude 'created' and 'modified')
        const versionDates = Object.entries(meta.time)
          .filter(([key]) => key !== 'created' && key !== 'modified')
          .map(([, date]) => date)
          .sort((a, b) => new Date(b).getTime() - new Date(a).getTime());

        if (versionDates.length === 0) return;

        const lastPublished = versionDates[0];
        const stale = monthsAgo(lastPublished) > STALE_MONTHS;

        results[idx] = { ...results[idx], lastPublished, stale };
      }),
    );
  }

  return results;
}
