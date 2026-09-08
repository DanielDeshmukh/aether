import { NextRequest } from "next/server";
import { prisma } from "@/lib/db";
import { hashToken, createAccessToken, createRefreshToken } from "@/lib/auth";
import { apiError } from "@/lib/api-utils";
import { NextResponse } from "next/server";

export async function GET(request: NextRequest) {
  const token = request.nextUrl.searchParams.get("token");

  if (!token) {
    return apiError("Token is required");
  }

  const hashedToken = hashToken(token);

  const magicLink = await prisma.magicLink.findUnique({
    where: { token: hashedToken },
  });

  if (!magicLink) {
    return apiError("Invalid token", 404);
  }

  if (magicLink.used) {
    return apiError("Token already used", 410);
  }

  if (new Date() > magicLink.expiresAt) {
    return apiError("Token expired", 410);
  }

  if (!magicLink.userId) {
    return apiError("Invalid token", 400);
  }

  await prisma.magicLink.update({
    where: { id: magicLink.id },
    data: { used: true },
  });

  await prisma.user.update({
    where: { id: magicLink.userId },
    data: { lastLoginAt: new Date() },
  });

  const accessToken = createAccessToken(magicLink.userId, magicLink.email);
  const refreshToken = createRefreshToken(magicLink.userId);

  const frontendUrl = process.env.FRONTEND_URL || "http://localhost:3000";
  const callbackUrl = new URL("/auth/callback", frontendUrl);
  callbackUrl.searchParams.set("access_token", accessToken);
  callbackUrl.searchParams.set("refresh_token", refreshToken);

  return NextResponse.redirect(callbackUrl);
}
