import type { ScanResult } from '../types/index.js';
import { renderTerminalReport } from './terminal.js';
import { renderJsonReport } from './json.js';
import { renderMarkdownReport } from './markdown.js';

export interface ReportOptions {
  json: boolean;
  markdown: boolean;
}

export function generateReport(results: ScanResult[], options: ReportOptions): void {
  if (options.json) {
    renderJsonReport(results);
    return;
  }
  if (options.markdown) {
    console.log(renderMarkdownReport(results));
    return;
  }
  renderTerminalReport(results);
}
