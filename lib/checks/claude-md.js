import { readFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { join } from 'node:path';

const MAX_RECOMMENDED_CHARS = 40000; // rough proxy for "too large to stay useful as context"

export async function checkClaudeMd(root, report) {
  const path = join(root, 'CLAUDE.md');
  if (!existsSync(path)) {
    report.info(
      'claude-md',
      'No CLAUDE.md found. Optional, but it lets Claude Code pick up project-specific conventions automatically.',
      'CLAUDE.md'
    );
    return;
  }

  const content = await readFile(path, 'utf8');

  if (content.trim().length === 0) {
    report.warn('claude-md', 'CLAUDE.md exists but is empty.', 'CLAUDE.md');
    return;
  }

  if (content.length > MAX_RECOMMENDED_CHARS) {
    report.warn(
      'claude-md',
      `CLAUDE.md is very large (${content.length} chars). Large files consume context budget on every session; consider trimming to what's actually load-bearing.`,
      'CLAUDE.md'
    );
  }

  if (/BEGIN PGP|PRIVATE KEY|AKIA[0-9A-Z]{16}/.test(content)) {
    report.error(
      'claude-md',
      'CLAUDE.md appears to contain a credential or private key. Remove it and rotate the credential.',
      'CLAUDE.md'
    );
  }
}
