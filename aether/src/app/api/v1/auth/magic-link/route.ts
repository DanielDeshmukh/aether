import { NextRequest } from "next/server";
import { prisma } from "@/lib/db";
import { generateMagicLinkToken, hashToken } from "@/lib/auth";
import { apiSuccess, apiError } from "@/lib/api-utils";

export async function POST(request: NextRequest) {
  const body = await request.json();
  const { email } = body;

  if (!email || typeof email !== "string") {
    return apiError("Email is required");
  }

  const normalizedEmail = email.toLowerCase().trim();

  const user = await prisma.user.upsert({
    where: { email: normalizedEmail },
    update: {},
    create: { email: normalizedEmail, provider: "email" },
  });

  const rawToken = generateMagicLinkToken();
  const hashedToken = hashToken(rawToken);
  const expiresAt = new Date(Date.now() + 15 * 60 * 1000);

  await prisma.magicLink.create({
    data: {
      token: hashedToken,
      email: normalizedEmail,
      userId: user.id,
      expiresAt,
    },
  });

  const frontendUrl = process.env.FRONTEND_URL || "http://localhost:3000";
  const verifyUrl = `${frontendUrl}/auth/callback?token=${rawToken}`;

  try {
    const { sendMagicLinkEmail } = await import("@/lib/email");
    await sendMagicLinkEmail({ to: normalizedEmail, magicLink: verifyUrl });
  } catch {
    console.log("Magic link URL (email not sent):", verifyUrl);
  }

  return apiSuccess({ message: "Magic link sent" });
}
