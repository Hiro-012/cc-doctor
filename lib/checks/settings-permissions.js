import { readFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { join } from 'node:path';

const DANGEROUS_BASH_PATTERNS = [
  /^Bash\(\*\)$/,
  /^Bash\(rm\s+-rf/,
  /^Bash\(git\s+push\s+--force/,
  /^Bash\(sudo(\s|\))/,
  /^Bash\(curl.*\|\s*sh\)/,
  /^Bash\(.*--dangerously-skip-permissions/,
];

async function readJson(path) {
  const raw = await readFile(path, 'utf8');
  return JSON.parse(raw);
}

async function checkSettingsFile(root, relPath, report) {
  const fullPath = join(root, relPath);
  if (!existsSync(fullPath)) return;

  let settings;
  try {
    settings = await readJson(fullPath);
  } catch (err) {
    report.error(
      'settings-permissions',
      `${relPath} is not valid JSON: ${err.message}`,
      relPath
    );
    return;
  }

  const allow = settings.permissions?.allow ?? [];
  const deny = settings.permissions?.deny ?? [];

  for (const rule of allow) {
    if (typeof rule !== 'string') continue;
    for (const pattern of DANGEROUS_BASH_PATTERNS) {
      if (pattern.test(rule)) {
        report.error(
          'settings-permissions',
          `${relPath} allows a high-risk command pattern: "${rule}"`,
          relPath
        );
      }
    }
  }

  if (allow.includes('Bash(*)') && deny.length === 0) {
    report.error(
      'settings-permissions',
      `${relPath} grants unrestricted Bash access ("Bash(*)") with no deny rules.`,
      relPath
    );
  }

  const hooks = settings.hooks ?? {};
  for (const [event, matchers] of Object.entries(hooks)) {
    if (!Array.isArray(matchers)) continue;
    for (const matcher of matchers) {
      const hookList = matcher.hooks ?? [];
      for (const hook of hookList) {
        if (hook.type === 'command' && typeof hook.command === 'string') {
          const scriptPathMatch = hook.command.match(/^([^\s]+\.(sh|js|py|mjs|cjs))/);
          if (scriptPathMatch) {
            const scriptPath = scriptPathMatch[1];
            const resolved = scriptPath.startsWith('/')
              ? scriptPath
              : join(root, scriptPath);
            if (!existsSync(resolved)) {
              report.warn(
                'settings-permissions',
                `${relPath} hook for "${event}" references a script that does not exist: ${scriptPath}`,
                relPath
              );
            }
          }
        }
      }
    }
  }
}

export async function checkSettingsPermissions(root, report) {
  await checkSettingsFile(root, join('.claude', 'settings.json'), report);
  await checkSettingsFile(root, join('.claude', 'settings.local.json'), report);
}
