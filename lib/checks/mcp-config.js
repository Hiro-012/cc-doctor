import { readFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { join } from 'node:path';

// Values that look like a literal secret rather than a ${VAR} / $VAR reference or placeholder.
function looksLikeHardcodedSecret(value) {
  if (typeof value !== 'string') return false;
  if (value.includes('${') || value.startsWith('$')) return false;
  if (/^(your[-_].*|<.*>|xxx+|changeme|todo)$/i.test(value)) return false;

  return (
    /^sk-[a-zA-Z0-9]{16,}$/.test(value) || // OpenAI/Anthropic-style secret keys
    /^ghp_[a-zA-Z0-9]{20,}$/.test(value) || // GitHub PAT
    /^AKIA[0-9A-Z]{16}$/.test(value) || // AWS access key id
    /^xox[baprs]-[a-zA-Z0-9-]{10,}$/.test(value) // Slack token
  );
}

export async function checkMcpConfig(root, report) {
  const path = join(root, '.mcp.json');
  if (!existsSync(path)) return;

  let config;
  try {
    config = JSON.parse(await readFile(path, 'utf8'));
  } catch (err) {
    report.error('mcp-config', `.mcp.json is not valid JSON: ${err.message}`, '.mcp.json');
    return;
  }

  const servers = config.mcpServers ?? {};
  for (const [name, server] of Object.entries(servers)) {
    const env = server.env ?? {};
    for (const [key, value] of Object.entries(env)) {
      if (looksLikeHardcodedSecret(value)) {
        report.error(
          'mcp-config',
          `.mcp.json server "${name}" has what looks like a hardcoded secret in env.${key}. Use an env var reference (e.g. "\${${key}}") instead of committing the literal value.`,
          '.mcp.json'
        );
      }
    }
  }
}
