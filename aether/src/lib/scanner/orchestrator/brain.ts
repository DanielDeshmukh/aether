import type { InitialPlan, FinalVerdict, Finding, ScanResults, TechStackResult } from "../types";
import { portScan, formatPortLogs } from "../tools/scanner";
import { headerAudit, formatHeaderLogs } from "../tools/headers";
import { heuristicEngine } from "../engine/heuristic-engine";
import { formatAuditLogs } from "../tools/audit-engine";

const NVIDIA_BASE = "https://integrate.api.nvidia.com/v1";
const OWASP_TOP_10 = [
  "A01:2021-Broken Access Control", "A02:2021-Cryptographic Failures",
  "A03:2021-Injection", "A04:2021-Insecure Design",
  "A05:2021-Security Misconfiguration", "A06:2021-Vulnerable and Outdated Components",
  "A07:2021-Identification and Authentication Failures",
  "A08:2021-Software and Data Integrity Failures",
  "A09:2021-Security Logging and Monitoring Failures",
  "A10:2021-Server-Side Request Forgery",
];
const OWASP_REMEDIATIONS: Record<string, string> = {
  "A01:2021-Broken Access Control": "Enforce server-side authorization checks on every object and route.",
  "A02:2021-Cryptographic Failures": "Enforce HTTPS everywhere, set HSTS, and remove mixed-content defaults.",
  "A03:2021-Injection": "Use parameterized queries, strict input validation, and contextual output encoding.",
  "A04:2021-Insecure Design": "Model abuse cases during design review and add guardrails for risky workflows.",
  "A05:2021-Security Misconfiguration": "Harden default headers, reduce exposed metadata, align with OWASP secure defaults.",
  "A06:2021-Vulnerable and Outdated Components": "Inventory framework versions, patch supported releases, automate dependency review.",
  "A07:2021-Identification and Authentication Failures": "Review session handling, MFA coverage, and cookie protections.",
  "A08:2021-Software and Data Integrity Failures": "Sign and verify build artifacts, lock trusted update channels.",
  "A09:2021-Security Logging and Monitoring Failures": "Ensure high-risk actions are logged centrally with alerting.",
  "A10:2021-Server-Side Request Forgery": "Constrain outbound requests with allowlists and strict URL validation.",
};

async function analyzeTechStack(targetUrl: string): Promise<TechStackResult> {
  try {
    const pw = await import("playwright");
    const browser = await pw.chromium.launch({ args: ["--no-sandbox"] });
    try {
      const page = await browser.newPage();
      const response = await page.goto(targetUrl, { waitUntil: "domcontentloaded", timeout: 15000 });
      try { await page.waitForLoadState("networkidle", { timeout: 5000 }); } catch { /* timeout ok */ }

      const title = await page.title();
      const scripts = await page.locator("script[src]").evaluateAll((els) => els.map((el) => (el as HTMLScriptElement).src));
      const html = await page.content();
      const headers: Record<string, string> = {};
      if (response) {
        const respHeaders = response.headers();
        for (const [k, v] of Object.entries(respHeaders)) {
          headers[k.toLowerCase()] = v;
        }
      }

      const frameworks: string[] = [];
      if (html.includes("__NEXT_DATA__") || scripts.some((s) => s.includes("/_next/"))) frameworks.push("Next.js");
      if (html.includes("data-reactroot") || scripts.some((s) => s.toLowerCase().includes("react"))) frameworks.push("React");
      if (scripts.some((s) => s.toLowerCase().includes("vue"))) frameworks.push("Vue");
      if (scripts.some((s) => s.toLowerCase().includes("angular"))) frameworks.push("Angular");
      if (headers["x-powered-by"]) frameworks.push(headers["x-powered-by"]);
      if (headers["server"]) frameworks.push(headers["server"]);

      return { target_url: targetUrl, final_url: page.url(), title, headers, scripts: scripts.slice(0, 25), frameworks: [...new Set(frameworks)] };
    } finally {
      await browser.close();
    }
  } catch (error) {
    return { target_url: targetUrl, frameworks: [], scripts: [], headers: {}, error: `Tech stack analysis failed: ${error}` };
  }
}

async function nvidiaGenerate(prompt: string, apiKey: string, retries = 5): Promise<string> {
  const models = ["nvidia/nemotron-3-super-120b-a12b", "deepseek-ai/deepseek-v4-flash", "minimaxai/minimax-m2.7"];
  for (const model of models) {
    for (let attempt = 0; attempt < retries; attempt++) {
      try {
        const response = await fetch(`${NVIDIA_BASE}/chat/completions`, {
          method: "POST",
          headers: { Authorization: `Bearer ${apiKey}`, "Content-Type": "application/json" },
          body: JSON.stringify({
            model, messages: [{ role: "user", content: prompt }],
            response_format: { type: "json_object" }, max_tokens: 4096,
          }),
        });
        if (!response.ok) {
          const errText = await response.text();
          if (["503", "504", "429"].includes(String(response.status)) || errText.includes("UNAVAILABLE")) {
            await new Promise((r) => setTimeout(r, (2 ** attempt) * 1000 + Math.random() * 1000));
            continue;
          }
          throw new Error(`NVIDIA API error: ${response.status}`);
        }
        const data = await response.json();
        return (data.choices?.[0]?.message?.content || "").trim();
      } catch (e: any) {
        const msg = (e?.message || "").toUpperCase();
        if (["503", "504", "429", "UNAVAILABLE", "TIMEOUT", "RATE_LIMIT"].some((x) => msg.includes(x))) {
          await new Promise((r) => setTimeout(r, (2 ** attempt) * 1000 + Math.random() * 1000));
          continue;
        }
        throw e;
      }
    }
  }
  throw new Error("NVIDIA NIM failed after retries and model fallback.");
}

function fallbackPlan(targetUrl: string): InitialPlan {
  const hostname = new URL(targetUrl).hostname.toUpperCase();
  return {
    steps: [
      { label: "THOUGHT", message: `Target ${hostname} resolved. Analyzing transport clues, security headers, and visible attack surface before first contact.` },
      { label: "OBSERVE", message: `Map passive signals on ${targetUrl} to identify framework fingerprints, route shapes, and authentication boundaries.` },
      { label: "PLAN", message: "Stage a multi-phase hunt across access control, hostile input reflection, and abuse-resilience signals before active execution." },
    ],
  };
}

function fallbackVerdict(results: ScanResults): FinalVerdict {
  const openPorts = results.port_scan?.open_ports || [];
  const headerFindings = results.header_audit?.findings || [];
  const auditFindings = results.audit_engine?.findings || [];
  const total = headerFindings.length + auditFindings.length;

  let threatLevel: FinalVerdict["threat_level"] = "low";
  if (total > 0 || openPorts.length >= 3) threatLevel = "medium";
  if (total >= 3 || openPorts.some((p) => [8080, 3000, 5000].includes(p))) threatLevel = "high";
  if (total >= 5) threatLevel = "critical";

  return {
    threat_level: threatLevel,
    risk_impact: `The exposed ports ${openPorts.length > 0 ? openPorts.join(",") : "none"} and header findings (${total} total hunt signals) indicate a ${threatLevel.toUpperCase()} probability of avoidable web-surface exposure.`,
    remediation_steps: [
      "Restrict public-facing ports to required production services.",
      "Add missing browser security headers including HSTS, CSP, X-Frame-Options, and X-Content-Type-Options.",
      "Review input-handling and abuse-control paths for reflected parameter handling and throttling.",
      "Review upstream proxy and application defaults to align deployment hardening with the observed attack surface.",
    ],
  };
}

function categorySignal(category: string, results: ScanResults): Finding | null {
  const headerFindings = results.header_audit?.findings || [];
  const auditFindings = results.audit_engine?.findings || [];
  const headers = results.tech_stack?.headers || {};

  switch (category) {
    case "A03:2021-Injection": {
      const f = auditFindings.find((x) => x.category.includes("sqli"));
      return f ? { ...f, attack_vector: "Input reflection and SQL error heuristic" } : null;
    }
    case "A05:2021-Security Misconfiguration": {
      const f = headerFindings[0];
      if (f) return { ...f, attack_vector: `Header audit via ${f.category}` };
      if (headers["server"]) {
        return {
          id: "server-banner", category, title: "Verbose Server Banner", severity: "Low",
          detail: "Server banner disclosed implementation details.", attack_vector: "Passive response header inspection",
          detected_threat: `Server: ${headers["server"]}`, evidence_snippet: headers["server"],
          provided_solution: "Remove or obfuscate the Server header.", evidence: { server: headers["server"] },
        };
      }
      return null;
    }
    case "A06:2021-Vulnerable and Outdated Components": {
      const serverBanner = headers["server"] || "";
      if (/\d/.test(serverBanner)) {
        return {
          id: "versioned-banner", category, title: "Versioned Component Disclosure", severity: "Low",
          detail: "Observed a version-bearing server banner.", attack_vector: "Header and DOM fingerprinting",
          detected_threat: `Server: ${serverBanner}`, evidence_snippet: serverBanner,
          provided_solution: "Remove version information from the Server header.",
          evidence: { server: serverBanner, frameworks: results.tech_stack?.frameworks || [] },
        };
      }
      return null;
    }
    case "A02:2021-Cryptographic Failures": {
      const f = headerFindings.find((x) => x.category.includes("strict") || x.category.includes("transport"));
      return f || null;
    }
    default:
      return null;
  }
}

export interface BrainRunOpts {
  targetUrl: string;
  userId: string;
  scanId: string;
  sessionId: string;
  onEvent: (event: Record<string, unknown>) => Promise<void>;
  persistTrace: (findings?: Finding[]) => Promise<void>;
}

export async function runBrainScan(opts: BrainRunOpts): Promise<{ results: ScanResults; finalReport: FinalVerdict; findings: Finding[] }> {
  const { targetUrl, userId, scanId, sessionId, onEvent, persistTrace } = opts;
  const apiKey = process.env.NVIDIA_API_KEY?.trim() || "";
  const results: ScanResults = { tech_stack: null, port_scan: null, header_audit: null, audit_engine: null };
  const allFindings: Finding[] = [];

  // Phase 1: Plan
  let plan: InitialPlan;
  if (!apiKey || apiKey.toLowerCase().startsWith("your_")) {
    plan = fallbackPlan(targetUrl);
  } else {
    try {
      const hostname = new URL(targetUrl).hostname.toUpperCase();
      const prompt = `You are AETHER, a senior vulnerability hunter. Target: ${targetUrl} (${hostname}). Return JSON with exactly { "steps": [{"label":"THOUGHT|OBSERVE|PLAN","message":"..."}] } with 3 steps.`;
      const raw = await nvidiaGenerate(prompt, apiKey);
      const cleaned = raw.replace(/^```json?\n?/, "").replace(/\n?```$/, "");
      plan = JSON.parse(cleaned);
      if (!plan.steps || plan.steps.length !== 3) plan = fallbackPlan(targetUrl);
    } catch {
      plan = fallbackPlan(targetUrl);
    }
  }

  for (const step of plan.steps) {
    await onEvent({ type: "thought", phase: step.label.toLowerCase(), msg: `${step.label}: ${step.message.toUpperCase()}` });
  }

  // Phase 2: Tech stack
  await onEvent({ type: "thought", phase: "observe", msg: "INITIATING PLAYWRIGHT RECON FOR TECHNOLOGY FINGERPRINTING." });
  results.tech_stack = await analyzeTechStack(targetUrl);
  await onEvent({ type: "thought", phase: "observe", msg: `PLAYWRIGHT RECON: STACK=${(results.tech_stack.frameworks || []).join(",") || "UNKNOWN"} TITLE=${results.tech_stack.title || "UNAVAILABLE"}` });

  // Phase 3: Port scan
  await onEvent({ type: "execute", phase: "execute", msg: "INITIATING PORT EXPOSURE MAPPING." });
  results.port_scan = await portScan(targetUrl);
  for (const msg of formatPortLogs(results.port_scan)) await onEvent({ type: "execute", phase: "execute", msg });

  // Phase 4: Header audit
  await onEvent({ type: "execute", phase: "execute", msg: "INITIATING HEADER SECURITY REVIEW." });
  results.header_audit = await headerAudit(targetUrl);
  for (const msg of formatHeaderLogs(results.header_audit)) await onEvent({ type: "execute", phase: "execute", msg });

  // Phase 5: Heuristic engine
  await onEvent({ type: "execute", phase: "execute", msg: "INITIATING BOUNDED APPLICATION AUDIT." });
  const heuristicResult = await heuristicEngine(targetUrl);
  results.audit_engine = { target_url: targetUrl, tested_params: [], base_response: {}, findings: heuristicResult.findings, profiles: heuristicResult.profiles };
  if (results.audit_engine) for (const msg of formatAuditLogs(results.audit_engine)) await onEvent({ type: "execute", phase: "execute", msg });

  // Phase 6: OWASP assessment loop
  for (let i = 0; i < OWASP_TOP_10.length; i++) {
    const category = OWASP_TOP_10[i];
    await onEvent({ type: "thought", phase: "execute", msg: `OWASP LOOP ${i + 1}/10: ${category.toUpperCase()}` });

    const finding = categorySignal(category, results);
    if (finding) {
      allFindings.push(finding);
      await persistTrace([finding]);
      await onEvent({ type: "alert", phase: "analyze", msg: `ACTIVE HIT: ${finding.title.toUpperCase()}`, severity: finding.severity, attack_vector: finding.attack_vector, evidence_snippet: finding.evidence_snippet, provided_solution: finding.provided_solution, category: finding.category });
    } else {
      await onEvent({ type: "thought", phase: "analyze", msg: `ASSESSMENT COMPLETE: ${category.toUpperCase()} EVALUATED WITH NO CONFIRMED SAFE SIGNAL.` });
    }
  }

  // Phase 7: Final verdict
  let finalReport: FinalVerdict;
  if (!apiKey || apiKey.toLowerCase().startsWith("your_")) {
    finalReport = fallbackVerdict(results);
  } else {
    try {
      const prompt = `You are a Lead Security Consultant writing the closing security posture summary. Target: ${targetUrl}. Tool Results: ${JSON.stringify(results)}. Return JSON: { "threat_level": "low|medium|high|critical", "risk_impact": "...", "remediation_steps": ["..."] }.`;
      const raw = await nvidiaGenerate(prompt, apiKey);
      const cleaned = raw.replace(/^```json?\n?/, "").replace(/\n?```$/, "");
      finalReport = JSON.parse(cleaned);
      if (!finalReport.threat_level) finalReport = fallbackVerdict(results);
    } catch {
      finalReport = fallbackVerdict(results);
    }
  }

  await onEvent({ type: "analyze", phase: "analyze", msg: `ANALYZE: FINAL VERDICT LOCKED AT ${finalReport.threat_level.toUpperCase()} RISK.`, finalReport });

  return { results, finalReport, findings: allFindings };
}
