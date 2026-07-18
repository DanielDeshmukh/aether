import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/db";
import { decodeToken, createAccessToken, createRefreshToken } from "@/lib/auth";
import { apiError } from "@/lib/api-utils";

export async function POST(request: NextRequest) {
  const refreshToken = request.cookies.get("refresh_token")?.value;
  if (!refreshToken) {
    return apiError("Refresh token required", 401);
  }

  const decoded = decodeToken(refreshToken);
  if (!decoded || decoded.type !== "refresh") {
    return apiError("Invalid refresh token", 401);
  }

  const isRevoked = await prisma.revokedToken.findUnique({
    where: { tokenJti: decoded.jti },
  });
  if (isRevoked) {
    return apiError("Token revoked", 401);
  }

  await prisma.revokedToken.create({
    data: {
      tokenJti: decoded.jti,
      userId: decoded.sub,
      expiresAt: new Date(decoded.exp * 1000),
    },
  });

  const user = await prisma.user.findUnique({ where: { id: decoded.sub } });
  if (!user) {
    return apiError("User not found", 404);
  }

  const newAccessToken = createAccessToken(user.id, user.email);
  const newRefreshToken = createRefreshToken(user.id);

  const response = NextResponse.json({ data: { access_token: newAccessToken } });
  response.cookies.set("access_token", newAccessToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    maxAge: 60 * 60,
    path: "/",
  });
  response.cookies.set("refresh_token", newRefreshToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    maxAge: 7 * 24 * 60 * 60,
    path: "/",
  });

  return response;
}
