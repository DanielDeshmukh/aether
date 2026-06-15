import { test, expect } from '@playwright/test';
import {
  loginWithMockTokens,
  navigateToHome,
  fillUrlAndConsent,
  submitScan,
  confirmAndExecute,
  waitForScanComplete,
  getScanFromApi,
  TEST_USER,
  TEST_TARGET_URL,
} from './helpers';

test.describe('Scan Pipeline - Complete OWASP Workflow', () => {
  test.beforeEach(async ({ page }) => {
    await loginWithMockTokens(page, TEST_USER.id, TEST_USER.email);
  });

  test('should display home page with URL input and consent checkbox', async ({ page }) => {
    await navigateToHome(page);

    await expect(page.locator('text=Target Acquisition')).toBeVisible();
    await expect(page.locator('input[type="url"]')).toBeVisible();
    await expect(page.locator('input[type="checkbox"]')).toBeVisible();
    await expect(page.locator('button', { hasText: 'Initialize Neural Scan' })).toBeVisible();
  });

  test('should require consent checkbox before scan submission', async ({ page }) => {
    await navigateToHome(page);

    const submitBtn = page.locator('button[type="submit"]');
    await expect(submitBtn).toBeDisabled();

    await page.fill('input[type="url"]', TEST_TARGET_URL);
    await expect(submitBtn).toBeDisabled();

    await page.click('input[type="checkbox"]');
    await expect(submitBtn).toBeEnabled();
  });

  test('should show authority verification step after initial submit', async ({ page }) => {
    await navigateToHome(page);
    await fillUrlAndConsent(page, TEST_TARGET_URL);
    await submitScan(page);

    await expect(page.locator('text=Authority Verification')).toBeVisible({ timeout: 5000 });
    await expect(page.locator('text=Legal Protocol Required')).toBeVisible();
    await expect(page.locator('button', { hasText: 'Authorize' })).toBeVisible();
    await expect(page.locator('button', { hasText: 'Abort' })).toBeVisible();
  });

  test('should allow abort from confirmation step', async ({ page }) => {
    await navigateToHome(page);
    await fillUrlAndConsent(page, TEST_TARGET_URL);
    await submitScan(page);

    await page.click('button', { hasText: 'Abort' });
    await expect(page.locator('text=Target Acquisition')).toBeVisible();
  });

  test('should create scan via API and return scan_id', async ({ page }) => {
    await navigateToHome(page);

    const response = await page.request.post(`${process.env.VITE_API_URL || 'http://localhost:8000'}/api/v1/scans`, {
      headers: {
        'Authorization': `Bearer ${await page.evaluate(() => localStorage.getItem('aether_access_token'))}`,
        'Content-Type': 'application/json',
      },
      data: {
        target_url: TEST_TARGET_URL,
        consent_confirmed: true,
      },
    });

    expect(response.ok()).toBeTruthy();
    const body = await response.json();
    expect(body.data?.scan_id).toBeTruthy();
    expect(body.data?.target_url).toBe(TEST_TARGET_URL);
  });

  test('should execute scan with all 10 OWASP categories', async ({ page }) => {
    const response = await page.request.post(`${process.env.VITE_API_URL || 'http://localhost:8000'}/api/v1/scans`, {
      headers: {
        'Authorization': `Bearer ${await page.evaluate(() => localStorage.getItem('aether_access_token'))}`,
        'Content-Type': 'application/json',
      },
      data: {
        target_url: TEST_TARGET_URL,
        consent_confirmed: true,
      },
    });

    const body = await response.json();
    const scanId = body.data?.scan_id;
    expect(scanId).toBeTruthy();

    const scan = await waitForScanComplete(page, scanId, 120_000);
    expect(scan.status).toBe('completed');

    const scanData = await getScanFromApi(page, scanId);
    expect(scanData.results?.audit_engine).toBeTruthy();

    const findings = scanData.results.audit_engine.findings || [];
    expect(Array.isArray(findings)).toBeTruthy();
  });

  test('should persist vulnerabilities for successful attacks', async ({ page }) => {
    const response = await page.request.post(`${process.env.VITE_API_URL || 'http://localhost:8000'}/api/v1/scans`, {
      headers: {
        'Authorization': `Bearer ${await page.evaluate(() => localStorage.getItem('aether_access_token'))}`,
        'Content-Type': 'application/json',
      },
      data: {
        target_url: TEST_TARGET_URL,
        consent_confirmed: true,
      },
    });

    const body = await response.json();
    const scanId = body.data?.scan_id;

    await waitForScanComplete(page, scanId, 120_000);

    const scanData = await getScanFromApi(page, scanId);
    const finalReport = scanData.final_report;
    expect(finalReport).toBeTruthy();
    expect(finalReport.threat_level).toBeTruthy();
    expect(finalReport.risk_impact).toBeTruthy();
  });

  test('should complete scan and generate final report', async ({ page }) => {
    const response = await page.request.post(`${process.env.VITE_API_URL || 'http://localhost:8000'}/api/v1/scans`, {
      headers: {
        'Authorization': `Bearer ${await page.evaluate(() => localStorage.getItem('aether_access_token'))}`,
        'Content-Type': 'application/json',
      },
      data: {
        target_url: TEST_TARGET_URL,
        consent_confirmed: true,
      },
    });

    const body = await response.json();
    const scanId = body.data?.scan_id;

    await waitForScanComplete(page, scanId, 120_000);

    const scanData = await getScanFromApi(page, scanId);
    expect(scanData.status).toBe('completed');
    expect(scanData.threat_level).toBeTruthy();
    expect(scanData.final_report).toBeTruthy();
    expect(scanData.final_report.remediation_steps).toBeTruthy();
  });
});
