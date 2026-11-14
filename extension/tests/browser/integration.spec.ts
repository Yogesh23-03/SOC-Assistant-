import { test, expect, chromium } from '@playwright/test';
import { spawn, execFileSync } from 'node:child_process';
import { createServer } from 'node:net';
import { randomBytes } from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { resolve, join } from 'node:path';

// Missing timestamp forces safe escalation: no LLM calls or firewall changes.
test('real backend authentication, reports, reinvestigation and recovery', async () => {
  test.setTimeout(90000);
  const dir = await mkdtemp(join(tmpdir(), 'soc-integration-'));
  const server = createServer();
  await new Promise<void>(done => server.listen(0, '127.0.0.1', done));
  const address = server.address(); if (!address || typeof address === 'string') throw new Error('No port');
  await new Promise<void>(done => server.close(() => done()));
  const root = resolve('..');
  const python = resolve(root, '.venv', process.platform === 'win32' ? 'Scripts/python.exe' : 'bin/python');
  const env = { ...process.env, SOC_DATABASE_PATH: join(dir, 'test.sqlite'), SOC_HMAC_SECRET: randomBytes(48).toString('hex'),
    SOC_JWT_SECRET: randomBytes(48).toString('hex'), SOC_EXECUTE_ON_APPROVAL: 'false', GROQ_API_KEY: 'offline-only', SOC_DATA_MODE: 'fixture' };
  const token = execFileSync(python, ['-m', 'backend.manage', 'analyst.integration'], { cwd: root, env, encoding: 'utf8' }).trim();
  const backend = spawn(python, ['-m', 'uvicorn', 'backend.app:app', '--host', '127.0.0.1', '--port', String(address.port)], { cwd: root, env, windowsHide: true, stdio: 'pipe' });
  let stderr = ''; backend.stderr.on('data', chunk => { stderr += String(chunk); });
  const base = `http://127.0.0.1:${address.port}`;
  const headers = { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' };
  let context: Awaited<ReturnType<typeof chromium.launchPersistentContext>> | undefined;
  try {
    let healthy = false;
    for (let i = 0; i < 100; i++) {
      try { if ((await fetch(`${base}/health`)).ok) { healthy = true; break; } } catch { /* starting */ }
      if (backend.exitCode !== null) throw new Error(stderr);
      await new Promise(done => setTimeout(done, 100));
    }
    expect(healthy, stderr).toBe(true);
    const hostile = '<script>window.compromised=true</script>';
    const response = await fetch(`${base}/api/alerts`, { method: 'POST', headers, body: JSON.stringify({ alert_id: 'integration-case',
      rule_name: 'Review incomplete alert', host: 'server-01', severity: 'high', log_text: hostile }) });
    expect(response.ok).toBe(true);
    const extensionPath = resolve('dist');
    context = await chromium.launchPersistentContext(join(dir, 'profile'), { channel: 'chromium', headless: true,
      ...(process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE ? { executablePath: process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE } : {}),
      args: [`--disable-extensions-except=${extensionPath}`, `--load-extension=${extensionPath}`] });
    const worker = context.serviceWorkers()[0] ?? await context.waitForEvent('serviceworker');
    const page = await context.newPage();
    await page.goto(`chrome-extension://${new URL(worker.url()).host}/sidepanel.html`);
    await page.getByRole('button', { name: 'Connection settings' }).click();
    await page.getByLabel('Backend URL').fill(base);
    await page.getByRole('button', { name: 'Save connection' }).click();
    await expect(page.getByRole('status')).toContainText('saved');
    await page.getByLabel('Session token').fill(token);
    await page.getByRole('button', { name: 'Start lab session' }).click();
    await expect(page.getByText('Signed in as')).toBeVisible();
    await expect(page.getByText('Live connection', { exact: true })).toBeVisible();
    await page.getByRole('button', { name: /Approvals/ }).click();
    await page.getByRole('button', { name: /Review incomplete alert/ }).click();
    await expect(page.getByText(hostile, { exact: true })).toBeVisible();
    expect(await page.evaluate(() => 'compromised' in window)).toBe(false);
    const downloading = page.waitForEvent('download');
    await page.getByRole('button', { name: 'Download PDF report' }).click();
    expect((await downloading).suggestedFilename()).toContain('.pdf');
    await page.getByRole('button', { name: 'Investigate more', exact: true }).click();
    await page.getByRole('button', { name: 'Confirm decision' }).click();
    await expect(page.getByRole('status').filter({ hasText: 'Investigation queued.' })).toBeVisible();
    await expect.poll(async () => (await (await fetch(`${base}/api/cases/integration-case`, { headers })).json()).runs.length).toBe(2);
    await page.getByRole('button', { name: /Approvals/ }).click();
    await page.getByRole('button', { name: 'Refresh queue' }).click();
    await expect(page.getByRole('button', { name: /Review incomplete alert/ })).toBeVisible();
    await page.reload();
    await expect(page.getByRole('button', { name: /Review incomplete alert/ })).toBeVisible();
    await page.getByRole('button', { name: /Review incomplete alert/ }).click();
    await page.getByRole('button', { name: 'Reject', exact: true }).click();
    await page.getByRole('button', { name: 'Confirm decision' }).click();
    await expect(page.getByRole('status')).toContainText('Proposal rejected');
    expect(await (await fetch(`${base}/api/proposals/pending`, { headers })).json()).toHaveLength(0);
  } finally {
    await context?.close(); backend.kill();
    await new Promise<void>(done => { if (backend.exitCode !== null) done(); else backend.once('exit', () => done()); });
    await rm(dir, { recursive: true, force: true, maxRetries: 4 });
  }
});
