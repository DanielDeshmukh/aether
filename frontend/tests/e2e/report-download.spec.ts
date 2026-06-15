import { test, expect } from '@playwright/test';
import {
  loginWithMockTokens,
  TEST_USER,
} from './helpers';

const API_BASE = process.env.VITE_API_URL || 'http://localhost:8000';
const FRONTEND_BASE = process.env.PLAYWRIGHT_BASE_URL || 'http://localhost:5173';

test.describe('Report Download', () => {
  test.beforeEach(async ({ page }) => {
    await loginWithMockTokens(page, TEST_USER.id, TEST_USER.email);
  });

  test('should display Download PDF button on scan detail page', async ({ page }) => {
    const scansResponse = await page.request.get(`${API_BASE}/api/v1/scans`, {
      headers: {
        'Authorization': `Bearer ${await page.evaluate(() => localStorage.getItem('aether_access_token'))}`,
      },
    });

    if (!scansResponse.ok()) {
      test.skip();
      return;
    }

    const scans = await scansResponse.json();
    if (!scans || scans.length === 0) {
      test.skip();
      return;
    }

    const scanId = scans[0].id;
    await page.goto(`${FRONTEND_BASE}/dashboard/${scanId}`);
    await page.waitForLoadState('domcontentloaded');

    const downloadBtn = page.locator('button', { hasText: 'Download PDF' });
    await expect(downloadBtn).toBeVisible({ timeout: 10000 });
  });

  test('should trigger PDF download on button click', async ({ page }) => {
    const scansResponse = await page.request.get(`${API_BASE}/api/v1/scans`, {
      headers: {
        'Authorization': `Bearer ${await page.evaluate(() => localStorage.getItem('aether_access_token'))}`,
      },
    });

    if (!scansResponse.ok()) {
      test.skip();
      return;
    }

    const scans = await scansResponse.json();
    if (!scans || scans.length === 0) {
      test.skip();
      return;
    }

    const scanId = scans[0].id;
    await page.goto(`${FRONTEND_BASE}/dashboard/${scanId}`);
    await page.waitForLoadState('domcontentloaded');

    const [download] = await Promise.all([
      page.waitForEvent('download', { timeout: 30000 }),
      page.locator('button', { hasText: 'Download PDF' }).click(),
    ]);

    expect(download).toBeTruthy();
    const filename = download.suggestedFilename();
    expect(filename).toMatch(/aether.*\.pdf/);
  });

  test('should export scan data via API as JSON', async ({ page }) => {
    const scansResponse = await page.request.get(`${API_BASE}/api/v1/scans`, {
      headers: {
        'Authorization': `Bearer ${await page.evaluate(() => localStorage.getItem('aether_access_token'))}`,
      },
    });

    if (!scansResponse.ok()) {
      test.skip();
      return;
    }

    const scans = await scansResponse.json();
    if (!scans || scans.length === 0) {
      test.skip();
      return;
    }

    const scanId = scans[0].id;
    const exportResponse = await page.request.get(`${API_BASE}/api/v1/scans/${scanId}/export?format=json`, {
      headers: {
        'Authorization': `Bearer ${await page.evaluate(() => localStorage.getItem('aether_access_token'))}`,
      },
    });

    expect(exportResponse.ok()).toBeTruthy();
    const exportData = await exportResponse.json();
    expect(exportData.scan_id).toBe(scanId);
    expect(exportData.target_url).toBeTruthy();
    expect(Array.isArray(exportData.vulnerabilities)).toBeTruthy();
  });

  test('should export scan data via API as CSV', async ({ page }) => {
    const scansResponse = await page.request.get(`${API_BASE}/api/v1/scans`, {
      headers: {
        'Authorization': `Bearer ${await page.evaluate(() => localStorage.getItem('aether_access_token'))}`,
      },
    });

    if (!scansResponse.ok()) {
      test.skip();
      return;
    }

    const scans = await scansResponse.json();
    if (!scans || scans.length === 0) {
      test.skip();
      return;
    }

    const scanId = scans[0].id;
    const exportResponse = await page.request.get(`${API_BASE}/api/v1/scans/${scanId}/export?format=csv`, {
      headers: {
        'Authorization': `Bearer ${await page.evaluate(() => localStorage.getItem('aether_access_token'))}`,
      },
    });

    expect(exportResponse.ok()).toBeTruthy();
    const contentType = exportResponse.headers()['content-type'];
    expect(contentType).toContain('text/csv');

    const csvText = await exportResponse.text();
    expect(csvText).toContain('id');
    expect(csvText).toContain('title');
    expect(csvText).toContain('severity');
  });

  test('should return 404 for non-existent scan export', async ({ page }) => {
    const exportResponse = await page.request.get(`${API_BASE}/api/v1/scans/nonexistent123/export?format=json`, {
      headers: {
        'Authorization': `Bearer ${await page.evaluate(() => localStorage.getItem('aether_access_token'))}`,
      },
    });

    expect(exportResponse.status()).toBe(404);
  });

  test('should return 401 for unauthenticated report download', async ({ page }) => {
    const reportResponse = await page.request.get(`${API_BASE}/api/v1/scans/test/report`);
    expect(reportResponse.status()).toBe(401);
  });
});
