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
//
// The value is captured as any run of non-whitespace, non-quote characters so
// that real passwords/secrets containing punctuation (e.g. "!" "@" "#") are
// caught, not just [a-zA-Z0-9_-/+=] tokens. Whitespace is still excluded, which
// keeps prose ("password before deploying") from matching, and the quote chars
// delimit the value. Placeholders and pure-punctuation values are filtered
// below rather than in the regex.
const GENERIC_SECRET_PATTERN =
  /(?:api[_-]?key|secret|password|token)\s*[:=]\s*['"]([^\s'"]{20,})['"]/gi;

// Mirrors the placeholder allowlist in mcp-config.js's looksLikeHardcodedSecret.
const PLACEHOLDER_VALUE_PATTERN =
  /^(your[-_].*|<.*>|x{3,}.*|changeme|todo|replace[-_]with.*|example.*|placeholder.*|\$\{.*\}|\$[A-Z_]+)$/i;

function isPlaceholderValue(value) {
  return PLACEHOLDER_VALUE_PATTERN.test(value);
}

// A real secret always contains at least one alphanumeric character. This
// rejects degenerate divider/filler values (e.g. "--------------------" or
// "####################") assigned to a secret-looking key, which would
// otherwise match the widened value class above and cause false positives.
function hasAlphanumeric(value) {
  return /[a-zA-Z0-9]/.test(value);
}

// Sanitized examples committed to a repo often assign a masked, obviously-fake
// value to a secret-looking key. The widened value class above matches these,
// so filter the two common shapes that survive the placeholder allowlist:
//   1. Redaction words a human wrote in place of the real value, even when
//      embedded in a longer token (e.g. "sk-REDACTED-DO-NOT-COMMIT-1234").
//   2. Single-character masks — the value's alphanumeric characters are all the
//      same one char (e.g. the nil UUID "00000000-0000-...-000000000000" or a
//      run like "aaaaaaaaaaaaaaaaaaaa"). A genuine secret has entropy across at
//      least two distinct alphanumeric characters. (Leading "xxxx" masks are
//      already covered by the placeholder allowlist; this generalizes it.)
const MASK_WORD_PATTERN = /redacted|sanitized/i;

function looksLikeMask(value) {
  if (MASK_WORD_PATTERN.test(value)) return true;
  const alnum = value.match(/[a-zA-Z0-9]/g);
  return alnum !== null && new Set(alnum).size === 1;
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
      if (isPlaceholderValue(match[1]) || !hasAlphanumeric(match[1]) || looksLikeMask(match[1])) continue;
      report.error(
        'secrets-scan',
        `Possible Generic assigned secret committed in ${relPath}. If real, rotate it immediately and remove it from git history.`,
        relPath
      );
      break;
    }
  }
}
