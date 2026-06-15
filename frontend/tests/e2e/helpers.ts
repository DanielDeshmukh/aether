import { createHmac } from 'node:crypto';
import { type Page, type BrowserContext } from '@playwright/test';

export const API_BASE = process.env.VITE_API_URL || 'http://localhost:8000';
export const FRONTEND_BASE = process.env.PLAYWRIGHT_BASE_URL || 'http://localhost:5173';
const JWT_SECRET = process.env.AETHER_JWT_SECRET || 'dev_secret_change_in_production';

function signJwt(payload: Record<string, unknown>): string {
  const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const signature = createHmac('sha256', JWT_SECRET).update(`${header}.${body}`).digest('base64url');
  return `${header}.${body}.${signature}`;
}

export function generateTestToken(userId: string, email: string): string {
  return signJwt({
    sub: userId,
    email,
    type: 'access',
    aud: 'authenticated',
    jti: crypto.randomUUID(),
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 3600,
  });
}

export function generateTestRefreshToken(userId: string): string {
  return signJwt({
    sub: userId,
    type: 'refresh',
    aud: 'authenticated',
    jti: crypto.randomUUID(),
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 604800,
  });
}

export async function loginWithMockTokens(page: Page, userId: string, email: string) {
  const accessToken = generateTestToken(userId, email);
  const refreshToken = generateTestRefreshToken(userId);

  await page.goto(FRONTEND_BASE);
  await page.evaluate(({ access, refresh }) => {
    localStorage.setItem('aether_access_token', access);
    localStorage.setItem('aether_refresh_token', refresh);
  }, { access: accessToken, refresh: refreshToken });
}

export async function navigateToHome(page: Page) {
  await page.goto(`${FRONTEND_BASE}/home`);
  await page.waitForLoadState('domcontentloaded');
}

export async function navigateToDashboard(page: Page) {
  await page.goto(`${FRONTEND_BASE}/dashboard`);
  await page.waitForLoadState('domcontentloaded');
}

export async function navigateToAuth(page: Page) {
  await page.goto(`${FRONTEND_BASE}/join-us`);
  await page.waitForLoadState('domcontentloaded');
}

export async function fillUrlAndConsent(page: Page, targetUrl: string) {
  await page.fill('input[type="url"]', targetUrl);
  await page.locator('input[type="checkbox"]').click({ force: true });
}

export async function submitScan(page: Page) {
  await page.click('button[type="submit"]');
  await page.waitForSelector('text=Authority Verification', { timeout: 5000 }).catch(() => {});
}

export async function confirmAndExecute(page: Page) {
  const authorizeBtn = page.locator('button', { hasText: 'Authorize' });
  if (await authorizeBtn.isVisible()) {
    await authorizeBtn.click();
  }
}

export async function waitForScanComplete(page: Page, scanId: string, timeoutMs = 90000) {
  const token = await page.evaluate(() => localStorage.getItem('aether_access_token'));
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const response = await page.request.get(`${API_BASE}/api/v1/scans/${scanId}`, {
      headers: { 'Authorization': `Bearer ${token}` },
    });
    if (response.ok()) {
      const scan = await response.json();
      if (scan.status === 'completed' || scan.status === 'failed') {
        return scan;
      }
    }
    await page.waitForTimeout(3000);
  }
  throw new Error(`Scan ${scanId} did not complete within ${timeoutMs}ms`);
}

export async function getScanFromApi(page: Page, scanId: string) {
  const token = await page.evaluate(() => localStorage.getItem('aether_access_token'));
  const response = await page.request.get(`${API_BASE}/api/v1/scans/${scanId}`, {
    headers: { 'Authorization': `Bearer ${token}` },
  });
  if (!response.ok()) throw new Error(`Failed to fetch scan ${scanId}`);
  return response.json();
}

export async function downloadPdfReport(page: Page, scanId: string) {
  const [download] = await Promise.all([
    page.waitForEvent('download'),
    page.locator('button', { hasText: 'Download PDF' }).click(),
  ]);
  return download;
}

export async function waitForWebSocketMessage(
  page: Page,
  urlPattern: string | RegExp,
  messagePredicate: (msg: Record<string, unknown>) => boolean,
  timeoutMs = 60000,
): Promise<Record<string, unknown>> {
  return page.evaluate(
    ({ urlPattern, timeoutMs }) => {
      return new Promise((resolve, reject) => {
        const wsUrl = typeof urlPattern === 'string'
          ? urlPattern
          : window.location.origin.replace('http', 'ws') + urlPattern;

        const ws = new WebSocket(wsUrl);
        const deadline = Date.now() + timeoutMs;

        ws.onmessage = (event) => {
          try {
            const data = JSON.parse(event.data);
            if (data.type !== 'error' && data.phase) {
              resolve(data);
            }
          } catch {}
        };

        ws.onerror = () => reject(new Error('WebSocket error'));
        ws.onclose = () => reject(new Error('WebSocket closed'));

        const checkTimeout = setInterval(() => {
          if (Date.now() > deadline) {
            clearInterval(checkTimeout);
            ws.close();
            reject(new Error('WebSocket message timeout'));
          }
        }, 1000);
      });
    },
    { urlPattern: typeof urlPattern === 'string' ? urlPattern : urlPattern.source, timeoutMs },
  );
}

export const TEST_TARGET_URL = 'https://babujichaay.com';

export const TEST_USER = {
  id: 'a1b2c3d4-e5f6-7890-abcd-ef1234567890',
  email: 'e2e-test@aether.dev',
};
