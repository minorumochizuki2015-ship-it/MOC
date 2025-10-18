import { test, expect } from '@playwright/test';
import fs from 'fs';
import path from 'path';

function saveOnFail(name: string, data: unknown): string {
  const dir = path.join(process.cwd(), 'observability', 'ui');
  fs.mkdirSync(dir, { recursive: true });
  const ts = new Date().toISOString().replace(/[:.]/g, '-');
  const filePath = path.join(dir, `${name}-${ts}.json`);
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2), 'utf-8');
  return filePath;
}

test.describe('SSE headers and stream health', () => {
  test('GET /events/health returns SSE headers with no-cache and event-stream', async ({ page, baseURL }) => {
    const healthUrl = `${baseURL}/events/health`;

    const [response] = await Promise.all([
      page.waitForResponse((res) => res.url().includes('/events/health') && res.status() === 200),
      page.goto(healthUrl),
    ]);

    const headers = response.headers();
    const mismatches: string[] = [];
    if (!String(headers['content-type'] || '').includes('text/event-stream')) mismatches.push('content-type missing text/event-stream');
    if (!String(headers['cache-control'] || '').includes('no-cache')) mismatches.push('cache-control missing no-cache');
    if ((headers['x-accel-buffering'] || '').toLowerCase() !== 'no') mismatches.push('x-accel-buffering not no');

    if (mismatches.length > 0) {
      const saved = saveOnFail('e2e-sse-headers-failure', { mismatches, headers });
      console.log(`[audit] sse header diff saved: ${saved}`);
    }
    expect(mismatches).toEqual([]);
  });

  test('EventSource can open /events stream', async ({ page, baseURL }) => {
    const eventsUrl = `${baseURL}/events`;
    const opened = await page.evaluate((url) => {
      return new Promise<boolean>((resolve) => {
        const es = new EventSource(url);
        es.onopen = () => { es.close(); resolve(true); };
        es.onerror = () => { es.close(); resolve(false); };
        setTimeout(() => { try { es.close(); } catch {} ; resolve(false); }, 5000);
      });
    }, eventsUrl);
    if (!opened) {
      const saved = saveOnFail('e2e-sse-open-failure', { url: eventsUrl });
      console.log(`[audit] sse open failure saved: ${saved}`);
    }
    expect(opened).toBeTruthy();
  });
});