import { createHmac } from 'node:crypto';

const API_BASE = process.env.VITE_API_URL || 'http://localhost:8000';
const JWT_SECRET = process.env.AETHER_JWT_SECRET || 'dev_secret_change_in_production';
const TEST_USER_ID = 'a1b2c3d4-e5f6-7890-abcd-ef1234567890';
const TEST_USER_EMAIL = 'e2e-test@aether.dev';
const TEST_TARGET_URL = 'https://babujichaay.com';

function signJwt(payload: Record<string, unknown>): string {
  const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const signature = createHmac('sha256', JWT_SECRET).update(`${header}.${body}`).digest('base64url');
  return `${header}.${body}.${signature}`;
}

export default async function globalSetup() {
  try {
    const token = signJwt({
      sub: TEST_USER_ID,
      email: TEST_USER_EMAIL,
      type: 'access',
      aud: 'authenticated',
      jti: crypto.randomUUID(),
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 3600,
    });

    const response = await fetch(`${API_BASE}/api/v1/scans`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        target_url: TEST_TARGET_URL,
        consent_confirmed: true,
      }),
    });

    if (response.ok) {
      const body = await response.json();
      console.log(`[global-setup] Created seed scan: ${body.data?.scan_id}`);
    } else {
      console.warn(`[global-setup] Failed to create seed scan: ${response.status}`);
    }
  } catch (error) {
    console.warn(`[global-setup] Could not create seed scan: ${error}`);
  }
}
