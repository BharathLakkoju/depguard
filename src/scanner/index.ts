import type { PackageManager, RawScanData } from '../types/index.js';
import { scanWithNpm } from './npm.js';
import { scanWithPnpm } from './pnpm.js';
import { scanWithYarn } from './yarn.js';
import { scanWithBun } from './bun.js';

export interface ScannerOptions {
  production: boolean;
  deep: boolean;
}

export async function runScan(
  directory: string,
  packageManager: PackageManager,
  options: ScannerOptions,
): Promise<RawScanData> {
  switch (packageManager) {
    case 'npm':
      return scanWithNpm(directory, options);
    case 'pnpm':
      return scanWithPnpm(directory, options);
    case 'yarn':
      return scanWithYarn(directory, options);
    case 'bun':
      return scanWithBun(directory, options);
    default:
      return { outdated: [], vulnerabilities: [] };
  }
}
