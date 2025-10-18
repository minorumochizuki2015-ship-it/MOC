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

test.describe('CORS/Expose headers for /preview', () => {
  test('fetch with credentials includes ETag and X-Preview-* in exposed headers', async ({ page, baseURL }) => {
    const previewUrl = `${baseURL}/preview`;
    const result = await page.evaluate(async (url) => {
      const res = await fetch(url, { credentials: 'include' });
      const headers: Record<string, string | null> = {
        'ETag': res.headers.get('ETag'),
        'Access-Control-Expose-Headers': res.headers.get('Access-Control-Expose-Headers'),
        'Access-Control-Allow-Origin': res.headers.get('Access-Control-Allow-Origin'),
        'X-Preview-Id': res.headers.get('X-Preview-Id'),
        'X-Preview-Token': res.headers.get('X-Preview-Token'),
      };
      return { ok: res.ok, status: res.status, headers };
    }, previewUrl);

    // 期待条件の評価
    const expose = result.headers['Access-Control-Expose-Headers'] || '';
    const mismatches: string[] = [];
    if (!result.ok) mismatches.push('response not ok');
    if (!expose.includes('ETag')) mismatches.push('Expose missing ETag');
    if (!/X-Preview-/.test(expose)) mismatches.push('Expose missing X-Preview-*');
    if (!result.headers['ETag']) mismatches.push('ETag header missing');
    const allowOrigin = result.headers['Access-Control-Allow-Origin'];
    if (allowOrigin && allowOrigin === '*') mismatches.push('Allow-Origin should not be * with credentials');

    if (mismatches.length > 0) {
      const saved = saveOnFail('e2e-headers-failure', {
        mismatches,
        actual: result.headers,
        expose,
        status: result.status,
      });
      console.log(`[audit] header diff saved: ${saved}`);
    }
    expect(mismatches).toEqual([]);
  });
});