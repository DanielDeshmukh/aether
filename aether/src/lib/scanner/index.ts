import { prisma } from "@/lib/db";
import type { ScanResults, FinalVerdict, Finding } from "./types";
import { runBrainScan, type BrainRunOpts } from "./orchestrator/brain";
import { runAttackScan, type AttackRunOpts } from "./orchestrator/attack-orchestrator";

export type { ScanResults, FinalVerdict, Finding };

export interface ScanOptions {
  scanId: string;
  targetUrl: string;
  userId: string;
  onEvent: (event: Record<string, unknown>) => Promise<void>;
}

export async function executeScan(opts: ScanOptions): Promise<{ status: "completed" | "failed"; report: FinalVerdict; findings: Finding[] }> {
  const { scanId, targetUrl, userId, onEvent } = opts;

  const sessionId = crypto.randomUUID();

  await prisma.scanSession.create({
    data: { id: sessionId, scanId, userId, targetUrl, status: "running" },
  });

  const persistTrace = async (findings?: Finding[]) => {
    try {
      if (findings && findings.length > 0) {
        for (const f of findings) {
          await prisma.vulnerability.create({
            data: {
              id: crypto.randomUUID(),
              scanId,
              sessionId,
              category: f.category,
              title: f.title,
              severity: f.severity === "Critical" ? "Critical" : f.severity === "High" ? "High" : f.severity === "Medium" ? "Medium" : "Low",
              detail: f.detail,
              attackVector: f.attack_vector,
              detectedThreat: f.detected_threat,
              evidence: f.evidence as any,
            },
          });
        }
      }
    } catch (err) {
      console.error(`[scan:${scanId}] persist error:`, err);
    }
  };

  try {
    const useNvidia = process.env.AETHER_USE_NVIDIA_ORCHESTRATOR === "true";

    let result: { results: ScanResults; finalReport: FinalVerdict; findings: Finding[] };

    if (useNvidia) {
      const verificationService = {
        verifyTarget: async (url: string, _opts?: { userId: string }) => ({ allowed: true }),
      };

      const attackOpts: AttackRunOpts = {
        targetUrl, userId, scanId, sessionId,
        verificationService,
        onEvent,
        persistTrace,
      };

      result = await runAttackScan(attackOpts);
    } else {
      const brainOpts: BrainRunOpts = {
        targetUrl, userId, scanId, sessionId,
        onEvent,
        persistTrace,
      };

      result = await runBrainScan(brainOpts);
    }

    // Persist final report
    await prisma.scan.update({
      where: { id: scanId },
      data: {
        status: "completed",
        completedAt: new Date(),
        threatLevel: result.finalReport.threat_level,
        finalReport: result.finalReport as any,
      },
    });

    return { status: "completed", report: result.finalReport, findings: result.findings };
  } catch (error: any) {
    console.error(`[scan:${scanId}] Scan failed:`, error);

    await prisma.scan.update({
      where: { id: scanId },
      data: {
        status: "failed",
        completedAt: new Date(),
        threatLevel: "critical",
        finalReport: {
          threat_level: "critical",
          risk_impact: `Scan failed: ${error.message}`,
          remediation_steps: ["Retry the scan.", "Check server logs for details."],
        } as any,
      },
    });

    return {
      status: "failed",
      report: {
        threat_level: "critical",
        risk_impact: `Scan failed: ${error.message}`,
        remediation_steps: ["Retry the scan.", "Check server logs for details."],
      },
      findings: [],
    };
  }
}
