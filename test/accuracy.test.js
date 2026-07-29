// Accuracy validation corpus for cc-doctor.
//
// This is separate from scan.test.js (which tests individual behaviors in
// isolation). This file measures aggregate accuracy against a corpus of
// known-vulnerable and known-clean fixtures, and prints recall / false
// positive rate so the numbers can be recorded in PROGRESS.md.
//
// Run directly with: node test/accuracy.test.js

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, mkdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { scan } from '../lib/scan.js';

const execFileAsync = promisify(execFile);

async function makeTempRepo() {
  const dir = await mkdtemp(join(tmpdir(), 'cc-doctor-accuracy-'));
  await execFileAsync('git', ['init', '-q'], { cwd: dir });
  await execFileAsync('git', ['config', 'user.email', 'test@example.com'], { cwd: dir });
  await execFileAsync('git', ['config', 'user.name', 'test'], { cwd: dir });
  return dir;
}

async function gitAddAll(dir) {
  await execFileAsync('git', ['add', '-A'], { cwd: dir });
}

function has(findings, pred) {
  return findings.some(pred);
}

// category: 'positive' fixtures represent a real problem cc-doctor should
// catch (used to measure recall). 'negative' fixtures represent a clean /
// benign repo that should NOT produce an error or warn finding for the
// pattern under test (used to measure false positive rate).
const CASES = [
  // --- settings-permissions: positive ---
  {
    id: 'P-settings-bash-star-no-deny',
    category: 'positive',
    async setup(dir) {
      await mkdir(join(dir, '.claude'), { recursive: true });
      await writeFile(
        join(dir, '.claude', 'settings.json'),
        JSON.stringify({ permissions: { allow: ['Bash(*)'], deny: [] } })
      );
    },
    detected: (f) => has(f, (x) => x.check === 'settings-permissions' && x.severity === 'error'),
  },
  {
    id: 'P-settings-bash-star-with-deny',
    category: 'positive',
    async setup(dir) {
      await mkdir(join(dir, '.claude'), { recursive: true });
      await writeFile(
        join(dir, '.claude', 'settings.json'),
        JSON.stringify({ permissions: { allow: ['Bash(*)'], deny: ['Bash(rm -rf /)'] } })
      );
    },
    detected: (f) => has(f, (x) => x.check === 'settings-permissions' && x.severity === 'error'),
  },
  {
    id: 'P-settings-rm-rf',
    category: 'positive',
    async setup(dir) {
      await mkdir(join(dir, '.claude'), { recursive: true });
      await writeFile(
        join(dir, '.claude', 'settings.json'),
        JSON.stringify({ permissions: { allow: ['Bash(rm -rf /tmp/foo)'] } })
      );
    },
    detected: (f) => has(f, (x) => x.check === 'settings-permissions' && x.severity === 'error'),
  },
  {
    id: 'P-settings-force-push',
    category: 'positive',
    async setup(dir) {
      await mkdir(join(dir, '.claude'), { recursive: true });
      await writeFile(
        join(dir, '.claude', 'settings.json'),
        JSON.stringify({ permissions: { allow: ['Bash(git push --force origin main)'] } })
      );
    },
    detected: (f) => has(f, (x) => x.check === 'settings-permissions' && x.severity === 'error'),
  },
  {
    id: 'P-settings-sudo',
    category: 'positive',
    async setup(dir) {
      await mkdir(join(dir, '.claude'), { recursive: true });
      await writeFile(
        join(dir, '.claude', 'settings.json'),
        JSON.stringify({ permissions: { allow: ['Bash(sudo apt-get install foo)'] } })
      );
    },
    detected: (f) => has(f, (x) => x.check === 'settings-permissions' && x.severity === 'error'),
  },
  {
    id: 'P-settings-curl-pipe-sh',
    category: 'positive',
    async setup(dir) {
      await mkdir(join(dir, '.claude'), { recursive: true });
      await writeFile(
        join(dir, '.claude', 'settings.json'),
        JSON.stringify({ permissions: { allow: ['Bash(curl https://example.com/install.sh | sh)'] } })
      );
    },
    detected: (f) => has(f, (x) => x.check === 'settings-permissions' && x.severity === 'error'),
  },
  {
    id: 'P-settings-skip-permissions-flag',
    category: 'positive',
    async setup(dir) {
      await mkdir(join(dir, '.claude'), { recursive: true });
      await writeFile(
        join(dir, '.claude', 'settings.json'),
        JSON.stringify({ permissions: { allow: ['Bash(claude --dangerously-skip-permissions)'] } })
      );
    },
    detected: (f) => has(f, (x) => x.check === 'settings-permissions' && x.severity === 'error'),
  },
  {
    id: 'P-settings-missing-hook-script',
    category: 'positive',
    async setup(dir) {
      await mkdir(join(dir, '.claude'), { recursive: true });
      await writeFile(
        join(dir, '.claude', 'settings.json'),
        JSON.stringify({
          hooks: {
            PreToolUse: [{ matcher: 'Bash', hooks: [{ type: 'command', command: '.claude/hooks/missing.sh' }] }],
          },
        })
      );
    },
    detected: (f) => has(f, (x) => x.check === 'settings-permissions' && x.severity === 'warn'),
  },
  {
    id: 'P-settings-invalid-json',
    category: 'positive',
    async setup(dir) {
      await mkdir(join(dir, '.claude'), { recursive: true });
      await writeFile(join(dir, '.claude', 'settings.json'), '{ not valid json');
    },
    detected: (f) => has(f, (x) => x.check === 'settings-permissions' && x.severity === 'error'),
  },
  {
    id: 'P-settings-local-json-also-checked',
    category: 'positive',
    async setup(dir) {
      await mkdir(join(dir, '.claude'), { recursive: true });
      await writeFile(
        join(dir, '.claude', 'settings.local.json'),
        JSON.stringify({ permissions: { allow: ['Bash(*)'], deny: [] } })
      );
    },
    detected: (f) => has(f, (x) => x.check === 'settings-permissions' && x.severity === 'error'),
  },

  // --- mcp-config: positive ---
  {
    id: 'P-mcp-anthropic-style-key',
    category: 'positive',
    async setup(dir) {
      await writeFile(
        join(dir, '.mcp.json'),
        JSON.stringify({ mcpServers: { x: { command: 'node', env: { API_KEY: 'sk-abcdefghijklmnopqrstuvwx' } } } })
      );
    },
    detected: (f) => has(f, (x) => x.check === 'mcp-config' && x.severity === 'error'),
  },
  {
    id: 'P-mcp-github-pat',
    category: 'positive',
    async setup(dir) {
      await writeFile(
        join(dir, '.mcp.json'),
        JSON.stringify({
          mcpServers: { x: { command: 'node', env: { GITHUB_TOKEN: 'ghp_' + 'a'.repeat(36) } } },
        })
      );
    },
    detected: (f) => has(f, (x) => x.check === 'mcp-config' && x.severity === 'error'),
  },
  {
    id: 'P-mcp-aws-key',
    category: 'positive',
    async setup(dir) {
      await writeFile(
        join(dir, '.mcp.json'),
        JSON.stringify({ mcpServers: { x: { command: 'node', env: { AWS_KEY: 'AKIAABCDEFGHIJKLMNOP' } } } })
      );
    },
    detected: (f) => has(f, (x) => x.check === 'mcp-config' && x.severity === 'error'),
  },
  {
    id: 'P-mcp-slack-token',
    category: 'positive',
    async setup(dir) {
      await writeFile(
        join(dir, '.mcp.json'),
        JSON.stringify({
          mcpServers: { x: { command: 'node', env: { SLACK_TOKEN: 'xoxb-1234567890-abcdefghij' } } },
        })
      );
    },
    detected: (f) => has(f, (x) => x.check === 'mcp-config' && x.severity === 'error'),
  },
  {
    id: 'P-mcp-invalid-json',
    category: 'positive',
    async setup(dir) {
      await writeFile(join(dir, '.mcp.json'), '{ not valid');
    },
    detected: (f) => has(f, (x) => x.check === 'mcp-config' && x.severity === 'error'),
  },
  {
    id: 'P-mcp-header-bearer-token',
    category: 'positive',
    async setup(dir) {
      await writeFile(
        join(dir, '.mcp.json'),
        JSON.stringify({
          mcpServers: {
            remote: { type: 'http', url: 'https://example.com/mcp', headers: { Authorization: 'Bearer sk-abcdefghijklmnopqrstuvwx' } },
          },
        })
      );
    },
    detected: (f) => has(f, (x) => x.check === 'mcp-config' && x.severity === 'error'),
  },
  {
    id: 'P-mcp-header-api-key',
    category: 'positive',
    async setup(dir) {
      await writeFile(
        join(dir, '.mcp.json'),
        JSON.stringify({
          mcpServers: {
            remote: { type: 'sse', url: 'https://example.com/sse', headers: { 'X-Api-Key': 'AKIAABCDEFGHIJKLMNOP' } },
          },
        })
      );
    },
    detected: (f) => has(f, (x) => x.check === 'mcp-config' && x.severity === 'error'),
  },

  // --- claude-md: positive ---
  {
    id: 'P-claude-md-empty',
    category: 'positive',
    async setup(dir) {
      await writeFile(join(dir, 'CLAUDE.md'), '   \n');
    },
    detected: (f) => has(f, (x) => x.check === 'claude-md' && x.severity === 'warn'),
  },
  {
    id: 'P-claude-md-too-large',
    category: 'positive',
    async setup(dir) {
      await writeFile(join(dir, 'CLAUDE.md'), '# notes\n' + 'x'.repeat(45000));
    },
    detected: (f) => has(f, (x) => x.check === 'claude-md' && x.severity === 'warn'),
  },
  {
    id: 'P-claude-md-private-key',
    category: 'positive',
    async setup(dir) {
      await writeFile(
        join(dir, 'CLAUDE.md'),
        '# notes\n-----BEGIN RSA PRIVATE KEY-----\nMIIB...\n-----END RSA PRIVATE KEY-----\n'
      );
    },
    detected: (f) => has(f, (x) => x.check === 'claude-md' && x.severity === 'error'),
  },
  {
    id: 'P-claude-md-aws-key',
    category: 'positive',
    async setup(dir) {
      await writeFile(join(dir, 'CLAUDE.md'), '# notes\nkey: AKIAABCDEFGHIJKLMNOP\n');
    },
    detected: (f) => has(f, (x) => x.check === 'claude-md' && x.severity === 'error'),
  },

  // --- secrets-scan: positive ---
  {
    id: 'P-secrets-aws-key',
    category: 'positive',
    async setup(dir) {
      await writeFile(join(dir, 'config.txt'), 'aws_key = AKIAABCDEFGHIJKLMNOP\n');
    },
    detected: (f) => has(f, (x) => x.check === 'secrets-scan' && x.severity === 'error'),
  },
  {
    id: 'P-secrets-github-pat',
    category: 'positive',
    async setup(dir) {
      await writeFile(join(dir, 'notes.txt'), 'token: ' + 'ghp_' + 'b'.repeat(36) + '\n');
    },
    detected: (f) => has(f, (x) => x.check === 'secrets-scan' && x.severity === 'error'),
  },
  {
    id: 'P-secrets-anthropic-style-key',
    category: 'positive',
    async setup(dir) {
      await writeFile(join(dir, '.env.committed'), 'ANTHROPIC_API_KEY=sk-abcdefghijklmnopqrstuvwx\n');
    },
    detected: (f) => has(f, (x) => x.check === 'secrets-scan' && x.severity === 'error'),
  },
  {
    id: 'P-secrets-slack-token',
    category: 'positive',
    async setup(dir) {
      await writeFile(join(dir, 'notes.txt'), 'xoxb-1234567890-abcdefghij\n');
    },
    detected: (f) => has(f, (x) => x.check === 'secrets-scan' && x.severity === 'error'),
  },
  {
    id: 'P-secrets-private-key-block',
    category: 'positive',
    async setup(dir) {
      await writeFile(join(dir, 'id_rsa'), '-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----\n');
    },
    detected: (f) => has(f, (x) => x.check === 'secrets-scan' && x.severity === 'error'),
  },
  {
    id: 'P-secrets-generic-assigned-password',
    category: 'positive',
    // Known limitation: the generic-secret regex requires the quoted value to
    // be made up entirely of [a-zA-Z0-9_-/+=]. Real passwords often contain
    // other punctuation (e.g. "!"), which breaks the match. Tracked here
    // rather than silently dropped so the recall number reflects it; not
    // widened yet because loosening the char class risks new false positives
    // (see the doc-example-placeholder negative fixture below).
    knownLimitation: true,
    async setup(dir) {
      await writeFile(join(dir, 'db.config'), 'password: "Sup3rSecretDbPassw0rd!!"\n');
    },
    detected: (f) => has(f, (x) => x.check === 'secrets-scan' && x.severity === 'error'),
  },

  // --- negative (clean / benign; measures false positive rate) ---
  {
    id: 'N-clean-minimal-repo',
    category: 'negative',
    async setup(dir) {
      await writeFile(join(dir, 'README.md'), '# hello\n');
      await writeFile(join(dir, 'CLAUDE.md'), '# Project conventions\n\nKeep it simple.\n');
    },
    // info-level (e.g. "no CLAUDE.md") is fine; only error/warn count as a false alarm
    clean: (f) => !has(f, (x) => x.severity === 'error' || x.severity === 'warn'),
  },
  {
    id: 'N-settings-sudo-lookalike-command',
    category: 'negative',
    async setup(dir) {
      await mkdir(join(dir, '.claude'), { recursive: true });
      await writeFile(
        join(dir, '.claude', 'settings.json'),
        JSON.stringify({ permissions: { allow: ['Bash(sudoku-solver --input puzzle.txt)'] } })
      );
    },
    clean: (f) => !has(f, (x) => x.check === 'settings-permissions' && x.severity === 'error'),
  },
  {
    id: 'N-mcp-env-var-reference',
    category: 'negative',
    async setup(dir) {
      await writeFile(
        join(dir, '.mcp.json'),
        JSON.stringify({ mcpServers: { x: { command: 'node', env: { API_KEY: '${API_KEY}' } } } })
      );
    },
    clean: (f) => !has(f, (x) => x.check === 'mcp-config'),
  },
  {
    id: 'N-mcp-placeholder-your-key',
    category: 'negative',
    async setup(dir) {
      await writeFile(
        join(dir, '.mcp.json'),
        JSON.stringify({ mcpServers: { x: { command: 'node', env: { API_KEY: 'your-api-key-here' } } } })
      );
    },
    clean: (f) => !has(f, (x) => x.check === 'mcp-config'),
  },
  {
    id: 'N-mcp-placeholder-angle-brackets',
    category: 'negative',
    async setup(dir) {
      await writeFile(
        join(dir, '.mcp.json'),
        JSON.stringify({ mcpServers: { x: { command: 'node', env: { API_KEY: '<YOUR_TOKEN_HERE>' } } } })
      );
    },
    clean: (f) => !has(f, (x) => x.check === 'mcp-config'),
  },
  {
    id: 'N-mcp-placeholder-changeme',
    category: 'negative',
    async setup(dir) {
      await writeFile(
        join(dir, '.mcp.json'),
        JSON.stringify({ mcpServers: { x: { command: 'node', env: { API_KEY: 'changeme' } } } })
      );
    },
    clean: (f) => !has(f, (x) => x.check === 'mcp-config'),
  },
  {
    id: 'N-mcp-header-env-reference',
    category: 'negative',
    async setup(dir) {
      await writeFile(
        join(dir, '.mcp.json'),
        JSON.stringify({
          mcpServers: {
            remote: { type: 'http', url: 'https://example.com/mcp', headers: { Authorization: 'Bearer ${MCP_TOKEN}' } },
          },
        })
      );
    },
    clean: (f) => !has(f, (x) => x.check === 'mcp-config'),
  },
  {
    id: 'N-mcp-header-placeholder',
    category: 'negative',
    async setup(dir) {
      await writeFile(
        join(dir, '.mcp.json'),
        JSON.stringify({
          mcpServers: {
            remote: { type: 'http', url: 'https://example.com/mcp', headers: { Authorization: 'Bearer your-token-here' } },
          },
        })
      );
    },
    clean: (f) => !has(f, (x) => x.check === 'mcp-config'),
  },
  {
    id: 'N-settings-narrow-safe-rules',
    category: 'negative',
    async setup(dir) {
      await mkdir(join(dir, '.claude'), { recursive: true });
      await writeFile(
        join(dir, '.claude', 'settings.json'),
        JSON.stringify({ permissions: { allow: ['Bash(npm test)', 'Bash(git status)', 'Bash(ls)'], deny: [] } })
      );
    },
    clean: (f) => !has(f, (x) => x.check === 'settings-permissions'),
  },
  {
    id: 'P-settings-local-json-committed',
    category: 'positive',
    async setup(dir) {
      await mkdir(join(dir, '.claude'), { recursive: true });
      await writeFile(
        join(dir, '.claude', 'settings.local.json'),
        JSON.stringify({ permissions: { allow: ['Bash(npm test)'] } })
      );
    },
    detected: (f) => has(f, (x) => x.check === 'settings-permissions' && x.severity === 'warn'),
  },
  {
    id: 'N-settings-hook-script-exists',
    category: 'negative',
    async setup(dir) {
      await mkdir(join(dir, '.claude', 'hooks'), { recursive: true });
      await writeFile(join(dir, '.claude', 'hooks', 'present.sh'), '#!/bin/sh\necho ok\n');
      await writeFile(
        join(dir, '.claude', 'settings.json'),
        JSON.stringify({
          hooks: {
            PreToolUse: [{ matcher: 'Bash', hooks: [{ type: 'command', command: '.claude/hooks/present.sh' }] }],
          },
        })
      );
    },
    clean: (f) => !has(f, (x) => x.check === 'settings-permissions'),
  },
  {
    id: 'N-settings-local-json-gitignored',
    category: 'negative',
    async setup(dir) {
      await mkdir(join(dir, '.claude'), { recursive: true });
      await writeFile(join(dir, '.gitignore'), '.claude/settings.local.json\n');
      await writeFile(
        join(dir, '.claude', 'settings.local.json'),
        JSON.stringify({ permissions: { allow: ['Bash(npm test)'] } })
      );
    },
    clean: (f) => !has(f, (x) => x.check === 'settings-permissions'),
  },
  {
    id: 'N-claude-md-normal',
    category: 'negative',
    async setup(dir) {
      await writeFile(join(dir, 'CLAUDE.md'), '# Conventions\n\nUse two-space indents. Run tests before committing.\n');
    },
    clean: (f) => !has(f, (x) => x.check === 'claude-md' && (x.severity === 'error' || x.severity === 'warn')),
  },
  {
    id: 'N-secrets-gitignored-file-not-scanned',
    category: 'negative',
    async setup(dir) {
      await writeFile(join(dir, '.gitignore'), 'secrets.local\n');
      await writeFile(join(dir, 'secrets.local'), 'AKIAABCDEFGHIJKLMNOP\n');
      // deliberately not git-added: secrets-scan only looks at `git ls-files`
    },
    clean: (f) => !has(f, (x) => x.check === 'secrets-scan'),
  },
  {
    id: 'N-secrets-prose-mention-no-assignment',
    category: 'negative',
    async setup(dir) {
      await writeFile(
        join(dir, 'SETUP.md'),
        '# Setup\n\nRemember to set your database password before deploying to production.\n'
      );
    },
    clean: (f) => !has(f, (x) => x.check === 'secrets-scan'),
  },
  {
    id: 'N-secrets-unrelated-long-value',
    category: 'negative',
    async setup(dir) {
      await writeFile(join(dir, 'build.json'), JSON.stringify({ commit_hash: 'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8' }));
    },
    clean: (f) => !has(f, (x) => x.check === 'secrets-scan'),
  },
  {
    id: 'N-secrets-doc-example-placeholder',
    category: 'negative',
    async setup(dir) {
      await writeFile(
        join(dir, 'README.md'),
        '# Config\n\nSet your key:\n\n```\napi_key = "REPLACE_WITH_YOUR_OWN_API_KEY_HERE"\n```\n'
      );
    },
    clean: (f) => !has(f, (x) => x.check === 'secrets-scan'),
  },
];

test('accuracy corpus', async (t) => {
  const results = [];

  for (const c of CASES) {
    await t.test(c.id, async () => {
      const dir = await makeTempRepo();
      try {
        await c.setup(dir);
        await gitAddAll(dir);
        const report = await scan(dir);
        const findings = report.findings;
        if (c.category === 'positive') {
          const ok = c.detected(findings);
          results.push({ id: c.id, category: c.category, ok, knownLimitation: !!c.knownLimitation });
          if (!c.knownLimitation) {
            assert.ok(ok, `expected ${c.id} to be detected; findings: ${JSON.stringify(findings)}`);
          }
        } else {
          const ok = c.clean(findings);
          results.push({ id: c.id, category: c.category, ok });
          assert.ok(ok, `expected ${c.id} to stay clean; findings: ${JSON.stringify(findings)}`);
        }
      } finally {
        await rm(dir, { recursive: true, force: true });
      }
    });
  }

  t.after(() => {
    const positives = results.filter((r) => r.category === 'positive');
    const negatives = results.filter((r) => r.category === 'negative');
    const truePositives = positives.filter((r) => r.ok).length;
    const falseNegatives = positives.length - truePositives;
    const falsePositives = negatives.filter((r) => !r.ok).length;
    const recall = positives.length ? truePositives / positives.length : null;
    const fpRate = negatives.length ? falsePositives / negatives.length : null;

    console.log('\n=== cc-doctor accuracy report ===');
    console.log(`positive fixtures (known-bad, should be flagged): ${positives.length}`);
    console.log(`  detected (true positives): ${truePositives}`);
    console.log(`  missed (false negatives): ${falseNegatives}`);
    console.log(`  recall: ${recall === null ? 'n/a' : (recall * 100).toFixed(1) + '%'}`);
    console.log(`negative fixtures (known-clean, should stay quiet): ${negatives.length}`);
    console.log(`  false positives: ${falsePositives}`);
    console.log(`  false positive rate: ${fpRate === null ? 'n/a' : (fpRate * 100).toFixed(1) + '%'}`);
    if (falseNegatives > 0) {
      console.log('  missed cases:', positives.filter((r) => !r.ok).map((r) => r.id).join(', '));
    }
    if (falsePositives > 0) {
      console.log('  false positive cases:', negatives.filter((r) => !r.ok).map((r) => r.id).join(', '));
    }
    console.log('==================================\n');
  });
});
