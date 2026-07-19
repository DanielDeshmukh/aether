import { createHash } from "crypto";
import type { Browser, BrowserContext } from "playwright";

export function buildSafetyHeaders(scanId: string, userId: string): Record<string, string> {
  const token = createHash("sha256").update(`${scanId}:${userId}`).digest("hex");
  return { "X-Aether-Safety-Token": token };
}

export async function createHardenedBrowserContext(
  browser: Browser,
  opts: { scanId: string; userId: string; extraHeaders?: Record<string, string> }
): Promise<BrowserContext> {
  const headers = buildSafetyHeaders(opts.scanId, opts.userId);
  if (opts.extraHeaders) Object.assign(headers, opts.extraHeaders);
  return browser.newContext({ extraHTTPHeaders: headers });
}
