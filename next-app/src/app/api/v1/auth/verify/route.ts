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

  await prisma.magicLink.update({
    where: { id: magicLink.id },
    data: { used: true },
  });

  await prisma.user.update({
    where: { id: magicLink.userId! },
    data: { lastLoginAt: new Date() },
  });

  const accessToken = createAccessToken(magicLink.userId!, magicLink.email);
  const refreshToken = createRefreshToken(magicLink.userId!);

  const frontendUrl = process.env.FRONTEND_URL || "http://localhost:3000";
  const redirectUrl = new URL("/home", frontendUrl);
  redirectUrl.searchParams.set("access_token", accessToken);
  redirectUrl.searchParams.set("refresh_token", refreshToken);

  const response = NextResponse.redirect(redirectUrl);
  response.cookies.set("access_token", accessToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    maxAge: 60 * 60,
    path: "/",
  });
  response.cookies.set("refresh_token", refreshToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    maxAge: 7 * 24 * 60 * 60,
    path: "/",
  });

  return response;
}
