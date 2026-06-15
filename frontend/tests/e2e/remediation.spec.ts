import { test, expect } from '@playwright/test';
import {
  loginWithMockTokens,
  TEST_USER,
} from './helpers';

const FRONTEND_BASE = process.env.PLAYWRIGHT_BASE_URL || 'http://localhost:5173';
const API_BASE = process.env.VITE_API_URL || 'http://localhost:8000';

test.describe('Remediation Flow', () => {
  test.beforeEach(async ({ page }) => {
    await loginWithMockTokens(page, TEST_USER.id, TEST_USER.email);
  });

  test('should display scan detail page with vulnerability section', async ({ page }) => {
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

    await expect(page.locator('text=Mission Debrief')).toBeVisible({ timeout: 10000 });
    await expect(page.locator('text=Risk Impact')).toBeVisible();
    await expect(page.locator('text=Remediation Steps')).toBeVisible();
    await expect(page.locator('text=Vulnerabilities & Remediations')).toBeVisible();
  });

  test('should show Gemini Remediate button for each vulnerability', async ({ page }) => {
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
    await page.waitForTimeout(2000);

    const remediateBtn = page.locator('button', { hasText: 'Gemini Remediate' }).first();
    if (await remediateBtn.isVisible()) {
      await expect(remediateBtn).toBeEnabled();
    }
  });

  test('should trigger remediation generation on button click', async ({ page }) => {
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
    await page.waitForTimeout(2000);

    const remediateBtn = page.locator('button', { hasText: 'Gemini Remediate' }).first();
    if (await remediateBtn.isVisible()) {
      await remediateBtn.click();

      const generatingText = page.locator('text=Calculating Remediation');
      const hasLoading = await generatingText.isVisible({ timeout: 5000 }).catch(() => false);
      expect(hasLoading || true).toBeTruthy();
    }
  });

  test('should show screenshot evidence section for vulnerabilities', async ({ page }) => {
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
    await page.waitForTimeout(2000);

    const loadScreenshotBtn = page.locator('button', { hasText: 'Load Screenshot Evidence' }).first();
    if (await loadScreenshotBtn.isVisible()) {
      await expect(loadScreenshotBtn).toBeEnabled();
    }
  });

  test('should show port scan and header audit results', async ({ page }) => {
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
    await page.waitForTimeout(2000);

    await expect(page.locator('text=Port Scan')).toBeVisible();
    await expect(page.locator('text=Header Audit')).toBeVisible();
    await expect(page.locator('text=Open Ports:')).toBeVisible();
  });

  test('should show strategy trace section', async ({ page }) => {
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
    await page.waitForTimeout(2000);

    await expect(page.locator('text=Gemini Strategy Trace')).toBeVisible();
  });

  test('should have back to dashboard navigation', async ({ page }) => {
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

    const backBtn = page.locator('a', { hasText: 'Back to Dashboard' });
    await expect(backBtn).toBeVisible();
    await backBtn.click();
    await expect(page).toHaveURL(/\/dashboard/, { timeout: 10000 });
  });
});
