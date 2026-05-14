import type { ScanResult } from '../types/index.js';

export function renderJsonReport(results: ScanResult[]): void {
  // If scanning a single project, unwrap the array for a cleaner output
  const output = results.length === 1 ? results[0] : results;
  console.log(JSON.stringify(output, null, 2));
}
