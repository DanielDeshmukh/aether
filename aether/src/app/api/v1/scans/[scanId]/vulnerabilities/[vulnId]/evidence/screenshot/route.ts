import { NextRequest } from "next/server";
import { prisma } from "@/lib/db";

export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ scanId: string; vulnId: string }> }
) {
  const userId = request.headers.get("x-user-id");
  if (!userId) return new Response("Not authenticated", { status: 401 });

  const { scanId, vulnId } = await params;

  const scan = await prisma.scan.findFirst({
    where: { id: scanId, userId },
  });

  if (!scan) return new Response("Scan not found", { status: 404 });

  const vuln = await prisma.vulnerability.findFirst({
    where: { id: vulnId, scanId },
  });

  if (!vuln) return new Response("Vulnerability not found", { status: 404 });

  const evidence = (vuln.evidence ?? {}) as Record<string, unknown>;
  const artifact = evidence.artifact as Record<string, unknown> | undefined;
  const b64 = artifact?.screenshot_base64 as string | undefined;

  if (!b64) return new Response("Screenshot not available", { status: 404 });

  const buffer = Buffer.from(b64, "base64");
  return new Response(buffer, {
    status: 200,
    headers: { "Content-Type": "image/png", "Cache-Control": "private, max-age=3600" },
  });
}
