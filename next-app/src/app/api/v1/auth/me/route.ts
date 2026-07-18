import { NextRequest } from "next/server";
import { prisma } from "@/lib/db";
import { apiSuccess, apiError } from "@/lib/api-utils";

export async function GET(request: NextRequest) {
  const userId = request.headers.get("x-user-id");
  if (!userId) {
    return apiError("Not authenticated", 401);
  }

  const user = await prisma.user.findUnique({
    where: { id: userId },
    select: { id: true, email: true, name: true, provider: true, createdAt: true, lastLoginAt: true },
  });

  if (!user) {
    return apiError("User not found", 404);
  }

  return apiSuccess(user);
}
