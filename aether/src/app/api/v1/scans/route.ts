import { NextRequest } from "next/server";
import { prisma } from "@/lib/db";
import { apiSuccess, apiError } from "@/lib/api-utils";
import crypto from "crypto";

export async function GET(request: NextRequest) {
  const userId = request.headers.get("x-user-id");
  if (!userId) return apiError("Not authenticated", 401);

  const scans = await prisma.scan.findMany({
    where: { userId },
    orderBy: { createdAt: "desc" },
    select: {
      id: true,
      targetUrl: true,
      status: true,
      threatLevel: true,
      createdAt: true,
      completedAt: true,
    },
  });

  return apiSuccess(scans);
}

export async function POST(request: NextRequest) {
  const userId = request.headers.get("x-user-id");
  if (!userId) return apiError("Not authenticated", 401);

  const body = await request.json();
  const { target_url, consent_confirmed } = body;

  if (!target_url) return apiError("target_url is required");
  if (!consent_confirmed) return apiError("CONSENT CONFIRMATION IS REQUIRED BEFORE A HUNT CAN START.");

  const normalizedTarget = normalizeTarget(target_url);
  if (!normalizedTarget) return apiError("Invalid URL");

  if (!isSafeUrl(normalizedTarget)) {
    return apiError("Forbidden target: Internal or private network scanning is not allowed.");
  }

  const scanCount = await prisma.scan.count({ where: { userId } });
  const limit = parseInt(process.env.QUOTA_FREE_LIMIT || "3");
  if (scanCount >= limit) {
    return apiError(`MVP Limit Reached: ${scanCount}/${limit} scans used.`, 403);
  }

  await prisma.consentLog.create({
    data: {
      userId,
      targetUrl: normalizedTarget,
      ipAddress: request.headers.get("x-forwarded-for") || request.headers.get("x-real-ip") || "unknown",
    },
  });

  const domain = new URL(normalizedTarget).hostname;
  await prisma.target.upsert({
    where: { domain },
    update: { userId },
    create: { domain, userId },
  });

  const scanId = crypto.randomUUID();

  await prisma.scan.create({
    data: {
      id: scanId,
      userId,
      targetUrl: normalizedTarget,
      status: "running",
    },
  });

  executeScanInBackground(scanId, normalizedTarget, userId);

  return apiSuccess({ scan_id: scanId, target_url: normalizedTarget });
}

function executeScanInBackground(scanId: string, targetUrl: string, userId: string) {
  const workerUrl = process.env.WORKER_URL || "http://localhost:4000";

  fetch(`${workerUrl}/scan`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ scanId, targetUrl, userId }),
  })
    .then((res) => {
      if (!res.ok) {
        console.error(`[scan:${scanId}] Worker returned ${res.status}`);
        return prisma.scan.update({
          where: { id: scanId },
          data: { status: "failed", completedAt: new Date(), threatLevel: "critical",
            finalReport: { threat_level: "critical", risk_impact: "Worker unavailable", remediation_steps: ["Ensure scan worker is running."] },
          },
        });
      }
      console.log(`[scan:${scanId}] Dispatched to worker`);
    })
    .catch((err) => {
      console.error(`[scan:${scanId}] Worker dispatch failed:`, err);
      prisma.scan.update({
        where: { id: scanId },
        data: { status: "failed", completedAt: new Date(), threatLevel: "critical",
          finalReport: { threat_level: "critical", risk_impact: `Worker unreachable: ${err.message}`, remediation_steps: ["Ensure scan worker is running on port 4000."] },
        },
      }).catch(() => {});
    });
}

function normalizeTarget(url: string): string | null {
  try {
    let u = url.trim();
    if (!u.startsWith("http://") && !u.startsWith("https://")) {
      u = "https://" + u;
    }
    new URL(u);
    return u;
  } catch {
    return null;
  }
}

function isSafeUrl(url: string): boolean {
  try {
    const parsed = new URL(url);
    const hostname = parsed.hostname.toLowerCase();
    const blocked = ["localhost", "127.0.0.1", "0.0.0.0", "::1"];
    if (blocked.includes(hostname)) return false;
    if (/^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|169\.254\.)/.test(hostname)) return false;
    return true;
  } catch {
    return false;
  }
}
