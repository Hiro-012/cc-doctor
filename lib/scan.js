import { Report } from './report.js';
import { checkSettingsPermissions } from './checks/settings-permissions.js';
import { checkClaudeMd } from './checks/claude-md.js';
import { checkMcpConfig } from './checks/mcp-config.js';
import { checkSecretsScan } from './checks/secrets-scan.js';

export async function scan(root) {
  const report = new Report();
  await checkSettingsPermissions(root, report);
  await checkClaudeMd(root, report);
  await checkMcpConfig(root, report);
  await checkSecretsScan(root, report);
  return report;
}
