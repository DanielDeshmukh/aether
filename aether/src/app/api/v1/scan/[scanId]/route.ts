import { NextRequest } from "next/server";
import { prisma } from "@/lib/db";
import { apiSuccess, apiError } from "@/lib/api-utils";

async function validateScanOwnership(scanId: string, userId: string) {
  const scan = await prisma.scan.findUnique({
    where: { id: scanId },
    select: { id: true, userId: true, status: true },
  });
  if (!scan) return { error: apiError("Scan not found", 404) };
  if (scan.userId !== userId) return { error: apiError("Forbidden", 403) };
  return { scan };
}

export async function POST(
  request: NextRequest,
  { params }: { params: Promise<{ scanId: string }> }
) {
  const userId = request.headers.get("x-user-id");
  if (!userId) return apiError("Not authenticated", 401);

  const { scanId } = await params;
  const { scan, error } = await validateScanOwnership(scanId, userId);
  if (error) return error;

  const url = new URL(request.url);
  const action = url.pathname.split("/").pop();

  const allowedTransitions: Record<string, string[]> = {
    pause: ["running", "pending"],
    resume: ["paused"],
    terminate: ["running", "pending", "paused"],
  };

  if (action && !allowedTransitions[action]?.includes(scan!.status)) {
    return apiError(`Cannot ${action} scan in status: ${scan!.status}`, 400);
  }

  const statusMap: Record<string, string> = {
    pause: "paused",
    resume: "running",
    terminate: "terminated",
  };

  const newStatus = statusMap[action!] ?? scan!.status;

  const updated = await prisma.scan.update({
    where: { id: scanId },
    data: {
      status: newStatus,
      ...(newStatus === "terminated" ? { completedAt: new Date() } : {}),
    },
    select: { id: true, status: true, completedAt: true },
  });

  return apiSuccess(updated);
}
