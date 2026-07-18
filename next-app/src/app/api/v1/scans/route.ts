import { NextRequest } from "next/server";
import { prisma } from "@/lib/db";
import { apiSuccess, apiError } from "@/lib/api-utils";
import crypto from "crypto";
import { spawn } from "child_process";
import path from "path";

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

  const fullId = crypto.randomUUID();
  const scanId = fullId.slice(0, 8);

  await prisma.scan.create({
    data: {
      id: fullId,
      userId,
      targetUrl: normalizedTarget,
      status: "running",
    },
  });

  spawnPythonScan(fullId, normalizedTarget, userId);

  return apiSuccess({ scan_id: scanId, target_url: normalizedTarget });
}

function spawnPythonScan(scanId: string, targetUrl: string, userId: string) {
  const backendDir = path.resolve(process.cwd(), "..", "backend");

  const pythonProcess = spawn("python", [
    "-m", "app.api.headless_runner",
    "--scan-id", scanId,
    "--target-url", targetUrl,
    "--user-id", userId,
  ], {
    cwd: backendDir,
    env: {
      ...process.env,
      DATABASE_URL: process.env.DATABASE_URL!,
      NVIDIA_API_KEY: process.env.NVIDIA_API_KEY!,
      AETHER_JWT_SECRET: process.env.AETHER_JWT_SECRET!,
      AETHER_USE_NVIDIA_ORCHESTRATOR: "true",
      AETHER_VALIDATION_HOSTS: process.env.AETHER_VALIDATION_HOSTS || "",
    },
    stdio: ["ignore", "pipe", "pipe"],
  });

  pythonProcess.stdout?.on("data", (data) => {
    console.log(`[scan:${scanId}] ${data.toString().trim()}`);
  });

  pythonProcess.stderr?.on("data", (data) => {
    console.error(`[scan:${scanId}:err] ${data.toString().trim()}`);
  });

  pythonProcess.on("close", async (code) => {
    console.log(`[scan:${scanId}] Process exited with code ${code}`);
    try {
      const status = code === 0 ? "completed" : "failed";
      await prisma.scan.update({
        where: { id: scanId },
        data: { status, completedAt: new Date() },
      });
    } catch (err) {
      console.error(`[scan:${scanId}] Failed to update status:`, err);
    }
  });

  pythonProcess.on("error", async (err) => {
    console.error(`[scan:${scanId}] Spawn error:`, err);
    try {
      await prisma.scan.update({
        where: { id: scanId },
        data: { status: "failed", completedAt: new Date() },
      });
    } catch { /* ignore */ }
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
