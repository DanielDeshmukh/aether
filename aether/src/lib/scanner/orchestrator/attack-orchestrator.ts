import type { BrowserContext } from "playwright";
import type { Finding, ScanResults, TechStackResult, FinalVerdict } from "../types";
import { ValidationLaneManager, type LaneFinding } from "../engine/validation-lanes";
import { heuristicEngine } from "../engine/heuristic-engine";
import { portScan, formatPortLogs } from "../tools/scanner";
import { headerAudit, formatHeaderLogs } from "../tools/headers";
import { generateRemediation } from "./remediation-agent";

const OWASP_TOP_10 = [
  "A01:2021-Broken Access Control", "A02:2021-Cryptographic Failures",
  "A03:2021-Injection", "A04:2021-Insecure Design",
  "A05:2021-Security Misconfiguration", "A06:2021-Vulnerable and Outdated Components",
  "A07:2021-Identification and Authentication Failures",
  "A08:2021-Software and Data Integrity Failures",
  "A09:2021-Security Logging and Monitoring Failures",
  "A10:2021-Server-Side Request Forgery",
];

export interface AttackRunOpts {
  targetUrl: string;
  userId: string;
  scanId: string;
  sessionId: string;
  verificationService: { verifyTarget: (url: string, opts?: { userId: string }) => Promise<{ allowed: boolean; failure_message?: string }> };
  onEvent: (event: Record<string, unknown>) => Promise<void>;
  persistTrace: (findings?: Finding[]) => Promise<void>;
}

export async function runAttackScan(opts: AttackRunOpts): Promise<{ results: ScanResults; finalReport: FinalVerdict; findings: Finding[] }> {
  const { targetUrl, userId, scanId, sessionId, verificationService, onEvent, persistTrace } = opts;
  const results: ScanResults = { tech_stack: null, port_scan: null, header_audit: null, audit_engine: null };
  const allFindings: Finding[] = [];

  // Phase 1: Passive recon
  await onEvent({ type: "thought", phase: "observe", msg: "INITIATING PASSIVE RECON." });
  results.port_scan = await portScan(targetUrl);
  for (const msg of formatPortLogs(results.port_scan)) await onEvent({ type: "execute", phase: "execute", msg });

  results.header_audit = await headerAudit(targetUrl);
  for (const msg of formatHeaderLogs(results.header_audit)) await onEvent({ type: "execute", phase: "execute", msg });

  // Phase 2: Heuristic engine
  await onEvent({ type: "execute", phase: "execute", msg: "INITIATING HEURISTIC ENGINE." });
  const heuristicResult = await heuristicEngine(targetUrl);
  results.audit_engine = { target_url: targetUrl, tested_params: [], base_response: {}, findings: heuristicResult.findings, profiles: heuristicResult.profiles };
  allFindings.push(...heuristicResult.findings);

  // Phase 3: Playwright validation lanes
  await onEvent({ type: "execute", phase: "execute", msg: "INITIATING PLAYWRIGHT VALIDATION LANES." });
  try {
    const pw = await import("playwright");
    const browser = await pw.chromium.launch({ args: ["--no-sandbox"] });
    try {
      const context = await browser.newContext({
        extraHTTPHeaders: { "X-Aether-Safety-Token": `${scanId}:${userId}` },
      });

      const laneManager = new ValidationLaneManager({
        verificationService,
        userId,
        traceWriter: async (phase, msg) => { await onEvent({ type: "execute", phase, msg }); },
        abortCheck: () => { /* no-op for now */ },
      });

      const laneRuns = [
        { name: "XSS", fn: () => laneManager.runXssLane(context, targetUrl) },
        { name: "Injection", fn: () => laneManager.runInjectionLane(context, targetUrl) },
        { name: "Crypto Failures", fn: () => laneManager.runCryptoFailuresLane(context, targetUrl) },
        { name: "Insecure Design", fn: () => laneManager.runInsecureDesignLane(context, targetUrl) },
        { name: "Misconfiguration", fn: () => laneManager.runMisconfigurationLane(context, targetUrl) },
        { name: "Vulnerable Components", fn: () => laneManager.runVulnerableComponentsLane(context, targetUrl) },
        { name: "Auth Failures", fn: () => laneManager.runAuthFailuresLane(context, targetUrl) },
        { name: "Data Integrity", fn: () => laneManager.runDataIntegrityLane(context, targetUrl) },
        { name: "Logging Failures", fn: () => laneManager.runLoggingFailuresLane(context, targetUrl) },
        { name: "SSRF", fn: () => laneManager.runSsrfLane(context, targetUrl) },
      ];

      for (let i = 0; i < laneRuns.length; i++) {
        const lane = laneRuns[i];
        const owasp = OWASP_TOP_10[i];
        await onEvent({ type: "thought", phase: "execute", msg: `VALIDATION LANE ${i + 1}/10: ${lane.name.toUpperCase()} (${owasp})` });

        try {
          const laneFindings = await lane.fn();
          for (const lf of laneFindings) {
            const f: Finding = {
              id: `lane:${lane.name}:${Math.random().toString(36).slice(2, 10)}`,
              category: lf.category, title: lf.title, severity: lf.severity as Finding["severity"],
              detail: lf.detail, attack_vector: lf.attack_vector,
              detected_threat: lf.title, evidence_snippet: lf.evidence_snippet,
              provided_solution: lf.provided_solution, evidence: lf.evidence,
            };
            allFindings.push(f);
            await onEvent({ type: "alert", phase: "analyze", msg: `LANE HIT: ${f.title.toUpperCase()}`, severity: f.severity, category: f.category });
          }
          if (laneFindings.length === 0) {
            await onEvent({ type: "thought", phase: "analyze", msg: `LANE CLEAR: ${lane.name.toUpperCase()} - NO CONFIRMED SIGNALS.` });
          }
        } catch (e: any) {
          await onEvent({ type: "thought", phase: "analyze", msg: `LANE ERROR: ${lane.name.toUpperCase()} - ${e.message}` });
        }
      }

      await context.close();
    } finally {
      await browser.close();
    }
  } catch (e: any) {
    await onEvent({ type: "error", phase: "execute", msg: `PLAYWRIGHT ERROR: ${e.message}` });
  }

  // Phase 4: Generate remediations for high-severity findings
  const remediationTargets = allFindings.filter((f) => ["High", "Critical"].includes(f.severity));
  for (const finding of remediationTargets.slice(0, 3)) {
    try {
      const remediation = await generateRemediation(targetUrl, finding, results as unknown as Record<string, unknown>);
      await onEvent({ type: "remediation", phase: "remediate", msg: `REMEDIATION: ${finding.title.toUpperCase()}`, remediation });
    } catch { /* ignore */ }
  }

  // Phase 5: Final verdict
  const total = allFindings.length;
  let threatLevel: FinalVerdict["threat_level"] = "low";
  if (total > 0) threatLevel = "medium";
  if (allFindings.some((f) => f.severity === "High")) threatLevel = "high";
  if (allFindings.some((f) => f.severity === "Critical")) threatLevel = "critical";

  const finalReport: FinalVerdict = {
    threat_level: threatLevel,
    risk_impact: `${total} security findings discovered across ${OWASP_TOP_10.length} OWASP validation lanes. Threat level: ${threatLevel.toUpperCase()}.`,
    remediation_steps: [
      "Address all Critical and High severity findings immediately.",
      "Review and harden security headers across all endpoints.",
      "Implement input validation and output encoding for all user-facing inputs.",
      "Conduct a thorough review of authentication and session management.",
    ],
  };

  await persistTrace(allFindings);
  await onEvent({ type: "analyze", phase: "analyze", msg: `FINAL VERDICT: ${threatLevel.toUpperCase()} RISK. ${total} FINDINGS.`, finalReport });

  return { results, finalReport, findings: allFindings };
}
