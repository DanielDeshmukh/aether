import { NextRequest } from "next/server";
import { prisma } from "@/lib/db";
import { apiSuccess, apiError } from "@/lib/api-utils";

export async function POST(
  request: NextRequest,
  { params }: { params: Promise<{ scanId: string }> }
) {
  const userId = request.headers.get("x-user-id");
  if (!userId) return apiError("Not authenticated", 401);

  const { scanId } = await params;

  const scan = await prisma.scan.findUnique({
    where: { id: scanId },
    select: { id: true, userId: true, status: true },
  });

  if (!scan) return apiError("Scan not found", 404);
  if (scan.userId !== userId) return apiError("Forbidden", 403);

  const activeStatuses = ["running", "pending", "paused"];
  if (!activeStatuses.includes(scan.status)) {
    return apiError(`Cannot kill scan in status: ${scan.status}`, 400);
  }

  const updated = await prisma.scan.update({
    where: { id: scanId },
    data: { status: "terminated", completedAt: new Date() },
    select: { id: true, status: true, completedAt: true },
  });

  return apiSuccess(updated);
}
