import { readFile } from 'node:fs/promises';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { join } from 'node:path';

const execFileAsync = promisify(execFile);

const MAX_FILE_BYTES = 1_000_000; // skip huge files, they're almost never source with secrets

const SECRET_PATTERNS = [
  { name: 'AWS Access Key ID', regex: /AKIA[0-9A-Z]{16}/g },
  { name: 'GitHub Personal Access Token', regex: /ghp_[a-zA-Z0-9]{36}/g },
  { name: 'Anthropic/OpenAI-style secret key', regex: /sk-[a-zA-Z0-9]{20,}/g },
  { name: 'Slack token', regex: /xox[baprs]-[a-zA-Z0-9-]{10,}/g },
  { name: 'Private key block', regex: /-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----/g },
];

// Handled separately from SECRET_PATTERNS because it needs to inspect the
// captured value and skip obvious placeholders (docs/examples), which is
// where this catch-all pattern otherwise false-positives most often.
const GENERIC_SECRET_PATTERN =
  /(?:api[_-]?key|secret|password|token)\s*[:=]\s*['"]([a-zA-Z0-9_\-/+=]{20,})['"]/gi;

// Mirrors the placeholder allowlist in mcp-config.js's looksLikeHardcodedSecret.
const PLACEHOLDER_VALUE_PATTERN =
  /^(your[-_].*|<.*>|x{3,}.*|changeme|todo|replace[-_]with.*|example.*|placeholder.*|\$\{.*\}|\$[A-Z_]+)$/i;

function isPlaceholderValue(value) {
  return PLACEHOLDER_VALUE_PATTERN.test(value);
}

async function listTrackedFiles(root) {
  try {
    const { stdout } = await execFileAsync('git', ['ls-files'], { cwd: root, maxBuffer: 10 * 1024 * 1024 });
    return stdout.split('\n').filter(Boolean);
  } catch {
    return null; // not a git repo, or git unavailable
  }
}

export async function checkSecretsScan(root, report) {
  const files = await listTrackedFiles(root);
  if (files === null) {
    report.info(
      'secrets-scan',
      'Skipped secret scan: not a git repository (or git is unavailable), so there is no tracked-file list to scan.'
    );
    return;
  }

  for (const relPath of files) {
    const fullPath = join(root, relPath);
    let stat;
    try {
      stat = await import('node:fs').then((fs) => fs.promises.stat(fullPath));
    } catch {
      continue; // e.g. broken symlink
    }
    if (!stat.isFile() || stat.size > MAX_FILE_BYTES) continue;

    let content;
    try {
      content = await readFile(fullPath, 'utf8');
    } catch {
      continue; // binary or unreadable
    }

    for (const { name, regex } of SECRET_PATTERNS) {
      regex.lastIndex = 0;
      if (regex.test(content)) {
        report.error(
          'secrets-scan',
          `Possible ${name} committed in ${relPath}. If real, rotate it immediately and remove it from git history.`,
          relPath
        );
      }
    }

    GENERIC_SECRET_PATTERN.lastIndex = 0;
    for (const match of content.matchAll(GENERIC_SECRET_PATTERN)) {
      if (isPlaceholderValue(match[1])) continue;
      report.error(
        'secrets-scan',
        `Possible Generic assigned secret committed in ${relPath}. If real, rotate it immediately and remove it from git history.`,
        relPath
      );
      break;
    }
  }
}
