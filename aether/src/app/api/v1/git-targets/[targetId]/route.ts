import { NextRequest } from "next/server";
import { prisma } from "@/lib/db";
import { apiSuccess, apiError } from "@/lib/api-utils";

export async function DELETE(
  request: NextRequest,
  { params }: { params: Promise<{ targetId: string }> }
) {
  const userId = request.headers.get("x-user-id");
  if (!userId) return apiError("Not authenticated", 401);

  const { targetId } = await params;

  const target = await prisma.target.findFirst({
    where: { id: targetId, userId },
  });

  if (!target) return apiError("Target not found", 404);

  await prisma.target.delete({
    where: { id: targetId },
  });

  return apiSuccess({ status: "deleted" });
}
