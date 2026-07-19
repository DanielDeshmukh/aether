import { randomUUID } from "crypto";
import type { BrowserContext, Page } from "playwright";
import type { Finding } from "../types";

const SQL_ERROR_PATTERNS = [
  /sql syntax/gi, /mysql/gi, /postgresql/gi, /sqlite/gi,
  /odbc/gi, /sqlstate/gi, /unterminated quoted string/gi,
  /syntax error at or near/gi,
];
const SAFE_XSS_MARKER_PREFIX = "AETHER_XSS_PROBE";
const SAFE_XSS_PAYLOAD_TEMPLATE = '<div data-aether-marker="{marker}">{marker}</div>';
const SAFE_INJECTION_PAYLOADS = ["' OR '1'='1", "'; WAITFOR DELAY '0:0:03' --"];

export interface LaneFinding {
  category: string;
  title: string;
  severity: string;
  detail: string;
  attack_vector: string;
  evidence_snippet: string;
  provided_solution: string;
  evidence: Record<string, unknown>;
}

export interface LaneManagerOpts {
  verificationService: { verifyTarget: (url: string, opts?: { userId: string }) => Promise<{ allowed: boolean; failure_message?: string }> };
  userId: string;
  traceWriter: (phase: string, msg: string) => Promise<void>;
  abortCheck: () => void;
  rateLimit?: () => Promise<void>;
  interactionDelayMs?: () => number;
}

export class ValidationLaneManager {
  private verificationService: LaneManagerOpts["verificationService"];
  private userId: string;
  private traceWriter: LaneManagerOpts["traceWriter"];
  private abortCheck: LaneManagerOpts["abortCheck"];
  private rateLimit?: LaneManagerOpts["rateLimit"];
  private interactionDelayMs: () => number;

  constructor(opts: LaneManagerOpts) {
    this.verificationService = opts.verificationService;
    this.userId = opts.userId;
    this.traceWriter = opts.traceWriter;
    this.abortCheck = opts.abortCheck;
    this.rateLimit = opts.rateLimit;
    this.interactionDelayMs = opts.interactionDelayMs || (() => 0);
  }

  private async throttle() { if (this.rateLimit) await this.rateLimit(); }
  private async waitAfterInteraction() {
    const ms = Math.max(0, this.interactionDelayMs());
    if (ms) await new Promise((r) => setTimeout(r, ms));
  }
  private async requireVerified(url: string) {
    this.abortCheck();
    const v = await this.verificationService.verifyTarget(url, { userId: this.userId });
    if (!v.allowed) throw new Error(v.failure_message || "DOMAIN VERIFICATION FAILED.");
  }

  private async screenshot(page: Page, lane: string, label: string): Promise<Record<string, unknown>> {
    this.abortCheck();
    const buf = await page.screenshot({ fullPage: false, type: "png" });
    return {
      lane, confirmation_label: label, captured_at: Date.now() / 1000,
      final_url: page.url(), title: await page.title(),
      dom_excerpt: (await page.content()).slice(0, 4000),
      screenshot_base64: buf.toString("base64"),
    };
  }

  private async visibleInput(page: Page) {
    const inputs = await page.locator("input[type='text'], input:not([type]), textarea").all();
    return inputs[0] || null;
  }

  async runXssLane(context: BrowserContext, targetUrl: string): Promise<LaneFinding[]> {
    await this.requireVerified(targetUrl);
    const marker = `${SAFE_XSS_MARKER_PREFIX}_${randomUUID().replace(/-/g, "").slice(0, 10)}`;
    const payload = SAFE_XSS_PAYLOAD_TEMPLATE.replace(/\{marker\}/g, marker);
    await this.traceWriter("execute", `XSS LANE INJECTING MARKER ${marker}.`);

    const page = await context.newPage();
    try {
      await this.requireVerified(targetUrl);
      await this.throttle();
      await page.goto(targetUrl, { waitUntil: "domcontentloaded", timeout: 15000 });
      const input = await this.visibleInput(page);
      if (!input) {
        await this.traceWriter("execute", "XSS LANE FOUND NO VISIBLE TEXT INPUTS.");
        return [];
      }
      await this.requireVerified(targetUrl);
      await input.fill(payload);
      await this.requireVerified(targetUrl);
      await input.press("Enter");
      await this.waitAfterInteraction();
      const content = await page.content();
      if (!content.includes(marker)) {
        await this.traceWriter("analyze", "XSS LANE DID NOT OBSERVE UNSANITIZED DOM REFLECTION.");
        return [];
      }
      const artifact = await this.screenshot(page, "xss", "confirmed_dom_reflection");
      await this.traceWriter("analyze", `XSS LANE CONFIRMED UNSANITIZED DOM REFLECTION FOR ${marker}.`);
      return [{
        category: "A03:2021-Injection",
        title: "Confirmed Unsanitized DOM Reflection",
        severity: "High",
        detail: "A Playwright validation lane reflected a controlled marker into the DOM without effective sanitization.",
        attack_vector: "Headless Playwright XSS reflection validation",
        evidence_snippet: `Controlled marker ${marker} rendered in the DOM after input submission.`,
        provided_solution: "Apply contextual output encoding and sanitize untrusted input before rendering it into the DOM.",
        evidence: { confirmation_status: "confirmed", marker, payload, artifact },
      }];
    } finally {
      await page.close();
    }
  }

  async runInjectionLane(context: BrowserContext, targetUrl: string): Promise<LaneFinding[]> {
    await this.requireVerified(targetUrl);
    await this.traceWriter("execute", "INJECTION LANE MONITORING RESPONSE TELEMETRY.");
    const page = await context.newPage();
    const responseEvents: { url: string; status: number; bodyExcerpt: string }[] = [];

    page.on("response", async (response) => {
      try {
        const body = (await response.text()).slice(0, 1000);
        responseEvents.push({ url: response.url(), status: response.status(), bodyExcerpt: body });
      } catch { /* ignore */ }
    });

    try {
      await this.requireVerified(targetUrl);
      await this.throttle();
      await page.goto(targetUrl, { waitUntil: "domcontentloaded", timeout: 15000 });
      const input = await this.visibleInput(page);

      for (const payload of SAFE_INJECTION_PAYLOADS) {
        if (!input) break;
        await this.requireVerified(targetUrl);
        await input.fill(payload);
        await this.requireVerified(targetUrl);
        await input.press("Enter");
        await this.waitAfterInteraction();
      }

      const findings: LaneFinding[] = [];
      for (const event of responseEvents) {
        for (const pattern of SQL_ERROR_PATTERNS) {
          if (pattern.test(event.bodyExcerpt)) {
            findings.push({
              category: "A03:2021-Injection",
              title: "SQL Error Reflected in Response",
              severity: "High",
              detail: `A database error pattern was observed in the response from ${event.url}.`,
              attack_vector: "Playwright SQL injection reflection validation",
              evidence_snippet: event.bodyExcerpt.slice(0, 300),
              provided_solution: "Use parameterized queries and strict input validation.",
              evidence: { url: event.url, status: event.status, body_excerpt: event.bodyExcerpt.slice(0, 500) },
            });
          }
        }
      }

      if (findings.length > 0) {
        const artifact = await this.screenshot(page, "injection", "sql_error_observed");
        for (const f of findings) f.evidence.artifact = artifact;
        await this.traceWriter("analyze", "INJECTION LANE CONFIRMED SQL ERROR REFLECTION.");
      } else {
        await this.traceWriter("analyze", "INJECTION LANE OBSERVED NO SQL ERROR REFLECTION.");
      }
      return findings;
    } finally {
      await page.close();
    }
  }

  async runCryptoFailuresLane(context: BrowserContext, targetUrl: string): Promise<LaneFinding[]> {
    await this.requireVerified(targetUrl);
    await this.traceWriter("execute", "CRYPTO FAILURES LANE CHECKING TRANSPORT SECURITY.");
    if (!targetUrl.startsWith("https://")) {
      return [{
        category: "A02:2021-Cryptographic Failures",
        title: "Non-HTTPS Target",
        severity: "High",
        detail: "Target is not served over HTTPS, exposing traffic to interception.",
        attack_vector: "Transport protocol inspection",
        evidence_snippet: `Target URL scheme: ${new URL(targetUrl).protocol}`,
        provided_solution: "Enforce HTTPS everywhere and set HSTS headers.",
        evidence: { url: targetUrl, protocol: new URL(targetUrl).protocol },
      }];
    }
    await this.traceWriter("analyze", "CRYPTO FAILURES LANE: HTTPS TRANSPORT VERIFIED.");
    return [];
  }

  async runInsecureDesignLane(context: BrowserContext, targetUrl: string): Promise<LaneFinding[]> {
    await this.requireVerified(targetUrl);
    await this.traceWriter("execute", "INSECURE DESIGN LANE EVALUATING ARCHITECTURAL EXPOSURE.");
    const page = await context.newPage();
    try {
      await this.throttle();
      await page.goto(targetUrl, { waitUntil: "domcontentloaded", timeout: 15000 });
      const links = await page.locator("a[href]").evaluateAll((els) =>
        els.map((el) => (el as HTMLAnchorElement).href).filter((h) => h.includes("/admin") || h.includes("/debug") || h.includes("/.env") || h.includes("/api/"))
      );
      if (links.length > 0) {
        const artifact = await this.screenshot(page, "insecure_design", "sensitive_paths_exposed");
        return [{
          category: "A04:2021-Insecure Design",
          title: "Sensitive Path Links Exposed in DOM",
          severity: "Medium",
          detail: `Found ${links.length} links to potentially sensitive paths.`,
          attack_vector: "Playwright DOM link analysis",
          evidence_snippet: links.slice(0, 5).join("\n"),
          provided_solution: "Remove links to debug, admin, or sensitive endpoints from production pages.",
          evidence: { links: links.slice(0, 10), artifact },
        }];
      }
      await this.traceWriter("analyze", "INSECURE DESIGN LANE: NO SENSITIVE PATH LINKS DETECTED.");
      return [];
    } finally {
      await page.close();
    }
  }

  async runMisconfigurationLane(context: BrowserContext, targetUrl: string): Promise<LaneFinding[]> {
    await this.requireVerified(targetUrl);
    await this.traceWriter("execute", "MISCONFIGURATION LANE CHECKING SERVER FOOTER EXPOSURE.");
    const page = await context.newPage();
    try {
      await this.throttle();
      const response = await page.goto(targetUrl, { waitUntil: "domcontentloaded", timeout: 15000 });
      const server = response?.headers()?.["server"] || "";
      const poweredBy = response?.headers()?.["x-powered-by"] || "";
      const findings: LaneFinding[] = [];

      if (server && /\d/.test(server)) {
        findings.push({
          category: "A05:2021-Security Misconfiguration",
          title: "Versioned Server Banner",
          severity: "Low",
          detail: `Server banner discloses version: ${server}`,
          attack_vector: "Response header inspection",
          evidence_snippet: `Server: ${server}`,
          provided_solution: "Remove version information from the Server header.",
          evidence: { server },
        });
      }
      if (poweredBy) {
        findings.push({
          category: "A05:2021-Security Misconfiguration",
          title: "X-Powered-By Header Exposed",
          severity: "Low",
          detail: `X-Powered-By header discloses technology: ${poweredBy}`,
          attack_vector: "Response header inspection",
          evidence_snippet: `X-Powered-By: ${poweredBy}`,
          provided_solution: "Remove the X-Powered-By header.",
          evidence: { "x-powered-by": poweredBy },
        });
      }

      if (findings.length > 0) {
        await this.traceWriter("analyze", "MISCONFIGURATION LANE: TECHNOLOGY DISCLOSURE DETECTED.");
      } else {
        await this.traceWriter("analyze", "MISCONFIGURATION LANE: NO TECHNOLOGY DISCLOSURE DETECTED.");
      }
      return findings;
    } finally {
      await page.close();
    }
  }

  async runVulnerableComponentsLane(context: BrowserContext, targetUrl: string): Promise<LaneFinding[]> {
    await this.requireVerified(targetUrl);
    await this.traceWriter("execute", "VULNERABLE COMPONENTS LANE CHECKING SCRIPT SOURCES.");
    const page = await context.newPage();
    try {
      await this.throttle();
      await page.goto(targetUrl, { waitUntil: "domcontentloaded", timeout: 15000 });
      const scripts = await page.locator("script[src]").evaluateAll((els) =>
        els.map((el) => (el as HTMLScriptElement).src)
      );
      const findings: LaneFinding[] = [];
      for (const src of scripts) {
        if (src.includes("jquery") && /jquery[.-]\d+\.\d+/.test(src)) {
          const versionMatch = src.match(/jquery[.-](\d+\.\d+)/);
          if (versionMatch) {
            const major = parseInt(versionMatch[1].split(".")[0]);
            if (major < 3) {
              findings.push({
                category: "A06:2021-Vulnerable and Outdated Components",
                title: "Outdated jQuery Version Detected",
                severity: "Medium",
                detail: `Script source uses jQuery ${versionMatch[1]} which may contain known vulnerabilities.`,
                attack_vector: "Playwright script source analysis",
                evidence_snippet: src,
                provided_solution: "Upgrade to the latest version of jQuery.",
                evidence: { src, version: versionMatch[1] },
              });
            }
          }
        }
      }
      if (findings.length > 0) {
        await this.traceWriter("analyze", "VULNERABLE COMPONENTS LANE: OUTDATED DEPENDENCIES DETECTED.");
      } else {
        await this.traceWriter("analyze", "VULNERABLE COMPONENTS LANE: NO KNOWN OUTDATED DEPENDENCIES.");
      }
      return findings;
    } finally {
      await page.close();
    }
  }

  async runAuthFailuresLane(context: BrowserContext, targetUrl: string): Promise<LaneFinding[]> {
    await this.requireVerified(targetUrl);
    await this.traceWriter("execute", "AUTH FAILURES LANE CHECKING COOKIE ATTRIBUTES.");
    const page = await context.newPage();
    try {
      await this.throttle();
      await page.goto(targetUrl, { waitUntil: "domcontentloaded", timeout: 15000 });
      const cookies = await page.context().cookies();
      const findings: LaneFinding[] = [];
      for (const cookie of cookies) {
        if (cookie.name.toLowerCase().includes("session") || cookie.name.toLowerCase().includes("token")) {
          if (!cookie.secure) {
            findings.push({
              category: "A07:2021-Identification and Authentication Failures",
              title: `Insecure Cookie: ${cookie.name}`,
              severity: "Medium",
              detail: `Cookie '${cookie.name}' is missing the Secure flag.`,
              attack_vector: "Playwright cookie attribute inspection",
              evidence_snippet: `Cookie: ${cookie.name}, Secure: ${cookie.secure}, HttpOnly: ${cookie.httpOnly}`,
              provided_solution: "Set Secure and HttpOnly flags on all session cookies.",
              evidence: { name: cookie.name, secure: cookie.secure, httpOnly: cookie.httpOnly, sameSite: cookie.sameSite },
            });
          }
          if (!cookie.httpOnly) {
            findings.push({
              category: "A07:2021-Identification and Authentication Failures",
              title: `Non-HttpOnly Cookie: ${cookie.name}`,
              severity: "Medium",
              detail: `Cookie '${cookie.name}' is missing the HttpOnly flag.`,
              attack_vector: "Playwright cookie attribute inspection",
              evidence_snippet: `Cookie: ${cookie.name}, HttpOnly: ${cookie.httpOnly}`,
              provided_solution: "Set HttpOnly flag on session cookies to prevent XSS access.",
              evidence: { name: cookie.name, httpOnly: cookie.httpOnly },
            });
          }
        }
      }
      if (findings.length > 0) {
        await this.traceWriter("analyze", "AUTH FAILURES LANE: INSECURE COOKIE CONFIGURATIONS DETECTED.");
      } else {
        await this.traceWriter("analyze", "AUTH FAILURES LANE: COOKIE CONFIGURATIONS APPEAR SECURE.");
      }
      return findings;
    } finally {
      await page.close();
    }
  }

  async runDataIntegrityLane(context: BrowserContext, targetUrl: string): Promise<LaneFinding[]> {
    await this.requireVerified(targetUrl);
    await this.traceWriter("execute", "DATA INTEGRITY LANE CHECKING SUBRESOURCE INTEGRITY.");
    const page = await context.newPage();
    try {
      await this.throttle();
      await page.goto(targetUrl, { waitUntil: "domcontentloaded", timeout: 15000 });
      const scripts = await page.locator("script[src]").evaluateAll((els) =>
        els.map((el) => ({ src: (el as HTMLScriptElement).src, integrity: el.getAttribute("integrity") }))
      );
      const findings: LaneFinding[] = [];
      const externalScripts = scripts.filter((s) => !s.src.includes(new URL(targetUrl).host));
      const missingIntegrity = externalScripts.filter((s) => !s.integrity);
      if (missingIntegrity.length > 0) {
        findings.push({
          category: "A08:2021-Software and Data Integrity Failures",
          title: "Missing Subresource Integrity",
          severity: "Medium",
          detail: `${missingIntegrity.length} external scripts lack integrity attributes.`,
          attack_vector: "Playwright SRI attribute inspection",
          evidence_snippet: missingIntegrity.slice(0, 3).map((s) => s.src).join("\n"),
          provided_solution: "Add integrity attributes to all external script and link elements.",
          evidence: { scripts: missingIntegrity.slice(0, 10) },
        });
      }
      if (findings.length > 0) {
        await this.traceWriter("analyze", "DATA INTEGRITY LANE: SRI GAPS DETECTED.");
      } else {
        await this.traceWriter("analyze", "DATA INTEGRITY LANE: SRI COVERAGE VERIFIED.");
      }
      return findings;
    } finally {
      await page.close();
    }
  }

  async runLoggingFailuresLane(context: BrowserContext, targetUrl: string): Promise<LaneFinding[]> {
    await this.requireVerified(targetUrl);
    await this.traceWriter("execute", "LOGGING FAILURES LANE CHECKING ERROR EXPOSURE.");
    const page = await context.newPage();
    try {
      await this.throttle();
      const response = await page.goto(`${targetUrl}/aether-nonexistent-404-${randomUUID().slice(0, 8)}`, { waitUntil: "domcontentloaded", timeout: 15000 });
      const status = response?.status() || 0;
      const body = await page.content();
      const findings: LaneFinding[] = [];

      if (status === 200 || (status >= 400 && (body.includes("stack trace") || body.includes("Traceback") || body.includes("Exception")))) {
        findings.push({
          category: "A09:2021-Security Logging and Monitoring Failures",
          title: "Verbose Error Information",
          severity: "Medium",
          detail: "Error responses expose internal implementation details.",
          attack_vector: "Playwright error page inspection",
          evidence_snippet: body.slice(0, 500),
          provided_solution: "Configure custom error pages that do not expose stack traces or internal details.",
          evidence: { status_code: status, body_excerpt: body.slice(0, 1000) },
        });
      }
      if (findings.length > 0) {
        await this.traceWriter("analyze", "LOGGING FAILURES LANE: VERBOSE ERROR EXPOSURE DETECTED.");
      } else {
        await this.traceWriter("analyze", "LOGGING FAILURES LANE: ERROR HANDLING APPEARS SECURE.");
      }
      return findings;
    } finally {
      await page.close();
    }
  }

  async runSsrfLane(context: BrowserContext, targetUrl: string): Promise<LaneFinding[]> {
    await this.requireVerified(targetUrl);
    await this.traceWriter("execute", "SSRF LANE CHECKING URL PARAMETER REFLECTION.");
    const page = await context.newPage();
    try {
      await this.throttle();
      const testUrl = new URL(targetUrl);
      testUrl.searchParams.set("url", "http://169.254.169.254/latest/meta-data/");
      await page.goto(testUrl.toString(), { waitUntil: "domcontentloaded", timeout: 15000 });
      const content = await page.content();
      const findings: LaneFinding[] = [];

      if (content.includes("ami-id") || content.includes("instance-type") || content.includes("iam/security-credentials")) {
        findings.push({
          category: "A10:2021-Server-Side Request Forgery",
          title: "SSRF Metadata Endpoint Accessible",
          severity: "Critical",
          detail: "The application appears to make requests to internal metadata endpoints.",
          attack_vector: "Playwright SSRF probe via URL parameter",
          evidence_snippet: "Cloud metadata endpoint responded with instance information.",
          provided_solution: "Block outbound requests to internal IP ranges and cloud metadata endpoints.",
          evidence: { url: testUrl.toString(), content_excerpt: content.slice(0, 500) },
        });
      }
      if (findings.length > 0) {
        await this.traceWriter("analyze", "SSRF LANE: METADATA ACCESS CONFIRMED.");
      } else {
        await this.traceWriter("analyze", "SSRF LANE: NO METADATA ACCESS DETECTED.");
      }
      return findings;
    } finally {
      await page.close();
    }
  }
}
