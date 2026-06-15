import { type Page, type BrowserContext } from '@playwright/test';

const API_BASE = process.env.VITE_API_URL || 'http://localhost:8000';
const FRONTEND_BASE = process.env.PLAYWRIGHT_BASE_URL || 'http://localhost:5173';

export function generateTestToken(userId: string, email: string): string {
  const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
  const payload = Buffer.from(JSON.stringify({
    sub: userId,
    email,
    type: 'access',
    jti: crypto.randomUUID(),
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 3600,
  })).toString('base64url');
  const signature = Buffer.from('test-signature').toString('base64url');
  return `${header}.${payload}.${signature}`;
}

export function generateTestRefreshToken(userId: string): string {
  const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
  const payload = Buffer.from(JSON.stringify({
    sub: userId,
    type: 'refresh',
    jti: crypto.randomUUID(),
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 604800,
  })).toString('base64url');
  const signature = Buffer.from('test-signature').toString('base64url');
  return `${header}.${payload}.${signature}`;
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
  await page.click('input[type="checkbox"]');
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
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const response = await page.request.get(`${API_BASE}/api/v1/scans/${scanId}`);
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
  const response = await page.request.get(`${API_BASE}/api/v1/scans/${scanId}`);
  if (!response.ok()) throw new Error(`Failed to fetch scan ${scanId}`);
  return response.json();
}

export async function downloadPdfReport(page: Page, scanId: string) {
  const [download] = await Promise.all([
    page.waitForEvent('download'),
    page.click('button', { hasText: 'Download PDF' }),
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
  id: 'e2e-test-user-001',
  email: 'e2e-test@aether.dev',
};
