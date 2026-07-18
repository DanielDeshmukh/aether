import { Resend } from "resend";

const resend = new Resend(process.env.RESEND_API_KEY);

interface SendMagicLinkEmailParams {
  to: string;
  magicLink: string;
}

interface SendReportEmailParams {
  to: string;
  targetUrl: string;
  threatLevel: string;
  vulnerabilityCount: number;
  reportUrl: string;
}

export async function sendMagicLinkEmail({ to, magicLink }: SendMagicLinkEmailParams) {
  if (!process.env.RESEND_API_KEY) {
    console.warn("RESEND_API_KEY not set, skipping email");
    return;
  }

  await resend.emails.send({
    from: process.env.EMAIL_FROM || "AETHER <noreply@aether.dev>",
    to,
    subject: "Sign in to AETHER",
    html: `
      <div style="font-family: sans-serif; max-width: 480px; margin: 0 auto; padding: 32px;">
        <h1 style="font-size: 20px; font-weight: 600; margin-bottom: 16px;">Sign in to AETHER</h1>
        <p style="color: #666; font-size: 14px; margin-bottom: 24px;">
          Click the button below to sign in. This link expires in 10 minutes.
        </p>
        <a href="${magicLink}"
           style="display: inline-block; padding: 12px 24px; background: #FFC107; color: #000; font-weight: 600; text-decoration: none; border-radius: 4px;">
          Sign In
        </a>
        <p style="color: #999; font-size: 12px; margin-top: 24px;">
          If you didn't request this, you can safely ignore this email.
        </p>
      </div>
    `,
  });
}

export async function sendReportEmail({ to, targetUrl, threatLevel, vulnerabilityCount, reportUrl }: SendReportEmailParams) {
  if (!process.env.RESEND_API_KEY) {
    console.warn("RESEND_API_KEY not set, skipping email");
    return;
  }

  await resend.emails.send({
    from: process.env.EMAIL_FROM || "AETHER <noreply@aether.dev>",
    to,
    subject: `Scan Complete: ${targetUrl} [${threatLevel.toUpperCase()}]`,
    html: `
      <div style="font-family: sans-serif; max-width: 480px; margin: 0 auto; padding: 32px;">
        <h1 style="font-size: 20px; font-weight: 600; margin-bottom: 16px;">Scan Complete</h1>
        <p style="color: #666; font-size: 14px; margin-bottom: 8px;">
          Target: <strong>${targetUrl}</strong>
        </p>
        <p style="color: #666; font-size: 14px; margin-bottom: 8px;">
          Threat Level: <strong style="color: ${threatLevel === "critical" ? "#ef4444" : threatLevel === "high" ? "#f97316" : "#FFC107"};">${threatLevel.toUpperCase()}</strong>
        </p>
        <p style="color: #666; font-size: 14px; margin-bottom: 24px;">
          Vulnerabilities Found: <strong>${vulnerabilityCount}</strong>
        </p>
        <a href="${reportUrl}"
           style="display: inline-block; padding: 12px 24px; background: #FFC107; color: #000; font-weight: 600; text-decoration: none; border-radius: 4px;">
          View Report
        </a>
      </div>
    `,
  });
}
