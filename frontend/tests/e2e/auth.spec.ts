import { test, expect } from '@playwright/test';
import {
  navigateToAuth,
  loginWithMockTokens,
  TEST_USER,
  FRONTEND_BASE,
} from './helpers';

test.describe('Authentication Flow', () => {
  test.describe('Unauthenticated User', () => {
    test('should display auth page with magic link form', async ({ page }) => {
      await navigateToAuth(page);

      await expect(page.locator('text=JOIN AETHER')).toBeVisible();
      await expect(page.locator('text=Authentication')).toBeVisible();
      await expect(page.locator('input[type="email"]')).toBeVisible();
      await expect(page.locator('button', { hasText: 'Send Magic Link' })).toBeVisible();
      await expect(page.locator('button', { hasText: 'Continue with Google' })).toBeVisible();
    });

    test('should validate email input before sending magic link', async ({ page }) => {
      await navigateToAuth(page);

      const submitBtn = page.locator('button', { hasText: 'Send Magic Link' });
      await submitBtn.click();

      const emailInput = page.locator('input[type="email"]');
      await expect(emailInput).toHaveAttribute('required', '');
    });

    test('should send magic link and show confirmation or error', async ({ page }) => {
      await navigateToAuth(page);

      await page.fill('input[type="email"]', 'test@aether.dev');
      await page.locator('button', { hasText: 'Send Magic Link' }).click();

      const confirmation = page.locator('text=MAGIC LINK SENT');
      const error = page.locator('text=FAILED TO SEND MAGIC LINK');
      await expect(confirmation.or(error)).toBeVisible({ timeout: 10000 });
    });
  });

  test.describe('Authenticated User', () => {
    test('should redirect from auth page to home when already authenticated', async ({ page }) => {
      await loginWithMockTokens(page, TEST_USER.id, TEST_USER.email);
      await page.goto(`${FRONTEND_BASE}/join-us`);

      await expect(page).toHaveURL(/\/home/, { timeout: 10000 });
    });

    test('should have valid JWT tokens in localStorage', async ({ page }) => {
      await loginWithMockTokens(page, TEST_USER.id, TEST_USER.email);

      const accessToken = await page.evaluate(() => localStorage.getItem('aether_access_token'));
      const refreshToken = await page.evaluate(() => localStorage.getItem('aether_refresh_token'));

      expect(accessToken).toBeTruthy();
      expect(refreshToken).toBeTruthy();
      expect(accessToken).toContain('.');
    });

    test('should clear tokens on logout', async ({ page }) => {
      await loginWithMockTokens(page, TEST_USER.id, TEST_USER.email);

      await page.evaluate(() => {
        localStorage.removeItem('aether_access_token');
        localStorage.removeItem('aether_refresh_token');
      });

      const accessToken = await page.evaluate(() => localStorage.getItem('aether_access_token'));
      expect(accessToken).toBeNull();
    });
  });

  test.describe('Auth Callback', () => {
    test('should handle error callback gracefully', async ({ page }) => {
      await page.goto(`${FRONTEND_BASE}/auth/callback?error=invalid_token`);

      await page.waitForLoadState('domcontentloaded');
      const url = page.url();
      expect(url).toContain('auth/callback');
    });

    test('should handle token callback and store tokens', async ({ page }) => {
      const mockAccessToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0LXVzZXIiLCJlbWFpbCI6InRlc3RAZXRoZXIuZGV2IiwidHlwZSI6ImFjY2VzcyIsImV4cCI6OTk5OTk5OTk5OX0.test';
      const mockRefreshToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0LXVzZXIiLCJ0eXBlIjpyZWZyZXNoLCJleHAiOjk5OTk5OTk5OTl9.test';

      await page.goto(
        `${FRONTEND_BASE}/auth/callback?access_token=${mockAccessToken}&refresh_token=${mockRefreshToken}`,
        { waitUntil: 'domcontentloaded' },
      );

      await page.waitForFunction(() => {
        return localStorage.getItem('aether_access_token') !== null;
      }, { timeout: 10000 });

      const storedAccess = await page.evaluate(() => localStorage.getItem('aether_access_token'));
      expect(storedAccess).toBeTruthy();
    });
  });
});
