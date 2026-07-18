import { NextRequest } from "next/server";
import { prisma } from "@/lib/db";
import { apiSuccess, apiError } from "@/lib/api-utils";

export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ scanId: string }> }
) {
  const userId = request.headers.get("x-user-id");
  if (!userId) return apiError("Not authenticated", 401);

  const { scanId } = await params;

  const scan = await prisma.scan.findFirst({
    where: { id: scanId, userId },
    include: {
      vulnerabilities: true,
      profiles: true,
    },
  });

  if (!scan) return apiError("Scan not found", 404);

  return apiSuccess(scan);
}

export async function DELETE(
  request: NextRequest,
  { params }: { params: Promise<{ scanId: string }> }
) {
  const userId = request.headers.get("x-user-id");
  if (!userId) return apiError("Not authenticated", 401);

  const { scanId } = await params;

  const scan = await prisma.scan.findFirst({
    where: { id: scanId, userId },
  });

  if (!scan) return apiError("Scan not found", 404);

  await prisma.scan.delete({ where: { id: scan.id } });

  return apiSuccess({ message: "Scan deleted" });
}
