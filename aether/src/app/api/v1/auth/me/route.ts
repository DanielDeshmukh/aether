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

export async function PATCH(request: NextRequest) {
  const userId = request.headers.get("x-user-id");
  if (!userId) {
    return apiError("Not authenticated", 401);
  }

  const body = await request.json();
  const { name, email } = body;

  const updateData: Record<string, string> = {};
  if (name !== undefined) updateData.name = name;
  if (email !== undefined) updateData.email = email;

  if (Object.keys(updateData).length === 0) {
    return apiError("No fields to update", 400);
  }

  try {
    const user = await prisma.user.update({
      where: { id: userId },
      data: updateData,
      select: { id: true, email: true, name: true, provider: true, createdAt: true, lastLoginAt: true },
    });
    return apiSuccess(user);
  } catch {
    return apiError("Failed to update profile", 500);
  }
}
