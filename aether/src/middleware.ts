import { NextRequest, NextResponse } from "next/server";
import { decodeToken } from "@/lib/auth";

const PUBLIC_PATHS = [
  "/",
  "/join-us",
  "/security",
  "/legal",
  "/auth/callback",
  "/api/v1/health",
  "/api/v1/auth/magic-link",
  "/api/v1/auth/verify",
  "/api/v1/auth/refresh",
];

export function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl;

  if (PUBLIC_PATHS.some((p) => pathname === p || pathname.startsWith(p + "/"))) {
    return NextResponse.next();
  }

  const token = request.cookies.get("access_token")?.value;
  if (!token) {
    if (pathname.startsWith("/api/")) {
      return NextResponse.json({ detail: "Not authenticated" }, { status: 401 });
    }
    return NextResponse.redirect(new URL("/", request.url));
  }

  const decoded = decodeToken(token);
  if (!decoded || decoded.type !== "access") {
    if (pathname.startsWith("/api/")) {
      return NextResponse.json({ detail: "Invalid token" }, { status: 401 });
    }
    return NextResponse.redirect(new URL("/", request.url));
  }

  const requestHeaders = new Headers(request.headers);
  requestHeaders.set("x-user-id", decoded.sub);
  requestHeaders.set("x-user-email", decoded.email);

  return NextResponse.next({ request: { headers: requestHeaders } });
}

export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon.ico|images/).*)"],
};
