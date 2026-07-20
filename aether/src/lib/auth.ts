import jwt from "jsonwebtoken";
import crypto from "crypto";

const JWT_SECRET = (() => {
  const secret = process.env.AETHER_JWT_SECRET;
  if (!secret) {
    if (process.env.NODE_ENV === "production") {
      throw new Error("AETHER_JWT_SECRET is required in production");
    }
    console.warn("WARNING: AETHER_JWT_SECRET not set, using dev_secret");
    return "dev_secret";
  }
  return secret;
})();

export interface TokenPayload {
  sub: string;
  email: string;
  aud: string;
  iat: number;
  exp: number;
  type: "access" | "refresh";
  jti: string;
}

export function createAccessToken(userId: string, email: string): string {
  return jwt.sign(
    {
      sub: userId,
      email,
      aud: "authenticated",
      type: "access",
      jti: crypto.randomBytes(16).toString("base64url"),
    } as Record<string, unknown>,
    JWT_SECRET,
    { algorithm: "HS256", expiresIn: "60m" }
  );
}

export function createRefreshToken(userId: string): string {
  return jwt.sign(
    {
      sub: userId,
      aud: "authenticated",
      type: "refresh",
      jti: crypto.randomBytes(16).toString("base64url"),
    } as Record<string, unknown>,
    JWT_SECRET,
    { algorithm: "HS256", expiresIn: "7d" }
  );
}

export function decodeToken(token: string): TokenPayload | null {
  try {
    return jwt.verify(token, JWT_SECRET, {
      algorithms: ["HS256"],
      audience: "authenticated",
    }) as TokenPayload;
  } catch {
    return null;
  }
}

export function generateMagicLinkToken(): string {
  return crypto.randomBytes(32).toString("hex");
}

export function hashToken(token: string): string {
  return crypto.createHash("sha256").update(token).digest("hex");
}
