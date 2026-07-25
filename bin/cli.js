#!/usr/bin/env node
import { scan } from '../lib/scan.js';

const SEVERITY_ICON = { error: '[ERROR]', warn: '[WARN]', info: '[INFO]' };

function printReport(report) {
  const findings = report.sorted();
  if (findings.length === 0) {
    console.log('cc-doctor: no issues found.');
    return;
  }

  for (const f of findings) {
    const icon = SEVERITY_ICON[f.severity];
    const location = f.file ? ` (${f.file})` : '';
    console.log(`${icon} [${f.severity}] ${f.check}: ${f.message}${location}`);
  }

  const counts = report.counts();
  console.log('');
  console.log(`cc-doctor: ${counts.error} error(s), ${counts.warn} warning(s), ${counts.info} info.`);
}

async function main() {
  const root = process.argv[2] ? process.argv[2] : process.cwd();
  const report = await scan(root);
  printReport(report);
  process.exitCode = report.hasErrors() ? 1 : 0;
}

main().catch((err) => {
  console.error('cc-doctor: unexpected error:', err);
  process.exitCode = 2;
});
