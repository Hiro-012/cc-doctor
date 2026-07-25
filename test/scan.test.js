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
  const dir = await mkdtemp(join(tmpdir(), 'cc-doctor-test-'));
  await execFileAsync('git', ['init', '-q'], { cwd: dir });
  await execFileAsync('git', ['config', 'user.email', 'test@example.com'], { cwd: dir });
  await execFileAsync('git', ['config', 'user.name', 'test'], { cwd: dir });
  return dir;
}

async function gitAddAll(dir) {
  await execFileAsync('git', ['add', '-A'], { cwd: dir });
}

test('clean repo produces no findings', async () => {
  const dir = await makeTempRepo();
  try {
    await writeFile(join(dir, 'README.md'), '# hello\n');
    await writeFile(join(dir, 'CLAUDE.md'), '# Project conventions\n\nKeep it simple.\n');
    await gitAddAll(dir);
    const report = await scan(dir);
    assert.equal(report.findings.length, 0);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('repo without CLAUDE.md only gets an info note, not an error', async () => {
  const dir = await makeTempRepo();
  try {
    await writeFile(join(dir, 'README.md'), '# hello\n');
    await gitAddAll(dir);
    const report = await scan(dir);
    assert.ok(!report.hasErrors());
    assert.ok(report.findings.some((f) => f.check === 'claude-md' && f.severity === 'info'));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('flags unrestricted Bash(*) allow rule', async () => {
  const dir = await makeTempRepo();
  try {
    await mkdir(join(dir, '.claude'), { recursive: true });
    await writeFile(
      join(dir, '.claude', 'settings.json'),
      JSON.stringify({ permissions: { allow: ['Bash(*)'], deny: [] } })
    );
    await gitAddAll(dir);
    const report = await scan(dir);
    assert.ok(report.hasErrors());
    assert.ok(
      report.findings.some((f) => f.check === 'settings-permissions' && f.severity === 'error')
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('flags invalid JSON in settings.json', async () => {
  const dir = await makeTempRepo();
  try {
    await mkdir(join(dir, '.claude'), { recursive: true });
    await writeFile(join(dir, '.claude', 'settings.json'), '{ not valid json');
    await gitAddAll(dir);
    const report = await scan(dir);
    assert.ok(report.findings.some((f) => f.severity === 'error' && f.check === 'settings-permissions'));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('flags hardcoded secret in .mcp.json', async () => {
  const dir = await makeTempRepo();
  try {
    await writeFile(
      join(dir, '.mcp.json'),
      JSON.stringify({
        mcpServers: {
          example: { command: 'node', args: ['server.js'], env: { API_KEY: 'sk-abcdefghijklmnopqrstuvwx' } },
        },
      })
    );
    await gitAddAll(dir);
    const report = await scan(dir);
    assert.ok(report.findings.some((f) => f.check === 'mcp-config' && f.severity === 'error'));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('does not flag env-var-reference secrets in .mcp.json', async () => {
  const dir = await makeTempRepo();
  try {
    await writeFile(
      join(dir, '.mcp.json'),
      JSON.stringify({
        mcpServers: {
          example: { command: 'node', args: ['server.js'], env: { API_KEY: '${API_KEY}' } },
        },
      })
    );
    await gitAddAll(dir);
    const report = await scan(dir);
    assert.ok(!report.findings.some((f) => f.check === 'mcp-config'));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('flags committed AWS access key', async () => {
  const dir = await makeTempRepo();
  try {
    await writeFile(join(dir, 'config.txt'), 'aws_key = AKIAABCDEFGHIJKLMNOP\n');
    await gitAddAll(dir);
    const report = await scan(dir);
    assert.ok(report.findings.some((f) => f.check === 'secrets-scan' && f.severity === 'error'));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('warns on empty CLAUDE.md', async () => {
  const dir = await makeTempRepo();
  try {
    await writeFile(join(dir, 'CLAUDE.md'), '   \n');
    await gitAddAll(dir);
    const report = await scan(dir);
    assert.ok(report.findings.some((f) => f.check === 'claude-md' && f.severity === 'warn'));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
