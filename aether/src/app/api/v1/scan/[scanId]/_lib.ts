import { prisma } from "@/lib/db";
import { apiError } from "@/lib/api-utils";

export async function validateAndUpdateStatus(
  scanId: string,
  userId: string,
  allowedStatuses: string[],
  newStatus: string
) {
  const scan = await prisma.scan.findUnique({
    where: { id: scanId },
    select: { id: true, userId: true, status: true },
  });

  if (!scan) return apiError("Scan not found", 404);
  if (scan.userId !== userId) return apiError("Forbidden", 403);
  if (!allowedStatuses.includes(scan.status)) {
    return apiError(`Cannot transition from "${scan.status}" to "${newStatus}"`, 400);
  }

  const updated = await prisma.scan.update({
    where: { id: scanId },
    data: {
      status: newStatus,
      ...(newStatus === "terminated" || newStatus === "failed" ? { completedAt: new Date() } : {}),
    },
    select: { id: true, status: true, completedAt: true },
  });

  return { data: updated };
}
