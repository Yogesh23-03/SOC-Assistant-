import { test, expect, chromium } from '@playwright/test';
import { createServer } from 'node:http';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { resolve, join } from 'node:path';

test('loaded extension replays hostile evidence and confirms an approval once', async () => {
  let status = 'pending';
  let decisions = 0;
  let failSync = false;
  const proposal = () => ({ proposal_id: 'p-browser', alert_id: 'a-browser', action: 'block_ip', target: '203.0.113.5', reason: 'Repeated failed SSH logins', explanation: 'Review evidence first', confidence: .95, ttl_seconds: 3600, status, created_at: new Date().toISOString(), expires_at: new Date(Date.now() + 300000).toISOString() });
  const hostile = '<script>window.compromised=true</script>';
  const server = createServer(async (req, res) => {
    res.setHeader('Content-Type', 'application/json');
    if (req.url === '/api/session') { expect(req.headers.authorization).toBe('Bearer test-session-token'); res.end(JSON.stringify({ analyst_id: 'analyst.demo', expires_at: Math.floor(Date.now() / 1000) + 3600 })); }
    else if (req.url?.startsWith('/api/cases')) res.end('[]');
    else if (req.url === '/api/metrics') res.end(JSON.stringify({ alerts_handled: 1, auto_closed_runs: 0, proposals: {} }));
    else if (req.url?.startsWith('/api/events')) {
      if (failSync) { res.statusCode = 503; res.end(JSON.stringify({ detail: 'Test outage' })); return; }
      const cursor = Number(new URL(req.url, 'http://localhost').searchParams.get('last_seen_event_id'));
      const events = [
        { event_id: 1, event_type: 'alert.new', payload: { alert_id: 'a-browser', rule_name: 'SSH brute force', severity: 'high', host: 'server-01', source_ip: '203.0.113.5' }, created_at: '' },
        { event_id: 2, event_type: 'alert.update', payload: { alert_id: 'a-browser', findings: [{ alert_id: 'a-browser', source: 'auth.log', detail: hostile }] }, created_at: '' },
      ];
      res.end(JSON.stringify({ events: events.filter(e => e.event_id > cursor) }));
    } else if (req.url === '/api/proposals/pending') res.end(JSON.stringify(status === 'pending' ? [proposal()] : []));
    else if (req.url === '/api/decisions') {
      let body = ''; for await (const chunk of req) body += chunk;
      const data = JSON.parse(body);
      expect(req.headers.authorization).toBe('Bearer test-session-token');
      expect(data.nonce.length).toBeGreaterThan(8);
      decisions++; status = 'approved'; failSync = true; res.end(JSON.stringify({ proposal: proposal() }));
    } else { res.statusCode = 404; res.end('{}'); }
  });
  await new Promise<void>(done => server.listen(0, '127.0.0.1', done));
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('No test port');
  const profile = await mkdtemp(join(tmpdir(), 'soc-extension-'));
  const extensionPath = resolve('dist');
  const context = await chromium.launchPersistentContext(profile, { channel: 'chromium', ...(process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE ? { executablePath: process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE } : {}), headless: true, args: [`--disable-extensions-except=${extensionPath}`, `--load-extension=${extensionPath}`] });
  try {
    const worker = context.serviceWorkers()[0] ?? await context.waitForEvent('serviceworker');
    const id = new URL(worker.url()).host;
    const page = await context.newPage();
    await page.setViewportSize({ width: 380, height: 850 });
    await page.goto(`chrome-extension://${id}/sidepanel.html`);
    await page.getByRole('button', { name: 'Connection settings' }).click();
    await page.getByLabel('Backend URL').fill(`http://127.0.0.1:${address.port}`);
    await page.getByRole('button', { name: 'Save connection' }).click();
    await expect(page.getByRole('status')).toContainText('saved');
    await page.getByLabel('Session token').fill('test-session-token');
    await page.getByRole('button', { name: 'Start lab session' }).click();
    await expect(page.getByText('Signed in as')).toBeVisible();
    await page.getByRole('button', { name: /Approvals/ }).click();
    await page.getByRole('button', { name: /SSH brute force/ }).click();
    await expect(page.getByText(hostile, { exact: true })).toBeVisible();
    expect(await page.evaluate(() => 'compromised' in window)).toBe(false);
    failSync = true;
    await page.getByRole('button', { name: 'Refresh queue' }).click();
    await expect(page.getByText('Backend unavailable', { exact: true })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Approve', exact: true })).toBeDisabled();
    failSync = false;
    await page.getByRole('button', { name: 'Refresh queue' }).click();
    await expect(page.getByRole('button', { name: 'Approve', exact: true })).toBeEnabled();
    await page.getByRole('button', { name: 'Approve', exact: true }).click();
    expect(decisions).toBe(0);
    await page.getByRole('button', { name: 'Confirm decision' }).click();
    await expect(page.getByRole('status')).toContainText('Approval recorded');
    expect(decisions).toBe(1);
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    await page.screenshot({ path: 'test-results/sidepanel.png', fullPage: true });
  } finally { await context.close(); await new Promise<void>(done => server.close(() => done())); await rm(profile, { recursive: true, force: true }); }
});
