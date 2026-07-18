import { NextRequest, NextResponse } from "next/server";
import { decodeToken } from "@/lib/auth";
import { prisma } from "@/lib/db";
import { apiSuccess } from "@/lib/api-utils";

export async function POST(request: NextRequest) {
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

  const response = NextResponse.json(apiSuccess({ message: "Logged out" }));
  response.cookies.delete("access_token");
  response.cookies.delete("refresh_token");
  return response;
}
