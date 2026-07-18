import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/db";
import { decodeToken } from "@/lib/auth";
import { apiSuccess, apiError } from "@/lib/api-utils";

export async function DELETE(request: NextRequest) {
  const userId = request.headers.get("x-user-id");
  if (!userId) {
    return apiError("Not authenticated", 401);
  }

  const accessToken = request.cookies.get("access_token")?.value;
  if (accessToken) {
    const decoded = decodeToken(accessToken);
    if (decoded?.jti) {
      await prisma.revokedToken.create({
        data: {
          tokenJti: decoded.jti,
          userId: decoded.sub,
          expiresAt: new Date(decoded.exp * 1000),
        },
      }).catch(() => {});
    }
  }

  await prisma.user.delete({ where: { id: userId } });

  const response = NextResponse.json(apiSuccess({ message: "Account deleted" }));
  response.cookies.delete("access_token");
  response.cookies.delete("refresh_token");
  return response;
}
