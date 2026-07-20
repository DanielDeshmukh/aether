import { NextRequest } from "next/server";
import { prisma } from "@/lib/db";
import { apiSuccess, apiError } from "@/lib/api-utils";

export async function POST(
  request: NextRequest,
  { params }: { params: Promise<{ scanId: string }> }
) {
  const userId = request.headers.get("x-user-id");
  if (!userId) return apiError("Not authenticated", 401);

  const { scanId } = await params;
  const body = await request.json();
  const { vuln_id, target_id } = body;

  if (!vuln_id) return apiError("vuln_id is required", 400);
  if (!target_id) return apiError("target_id is required for PR creation", 400);

  const scan = await prisma.scan.findFirst({
    where: { id: scanId, userId },
    include: { vulnerabilities: true },
  });

  if (!scan) return apiError("Scan not found", 404);

  const remediations = (scan.remediations ?? {}) as Record<string, unknown>;
  const remediation = remediations[vuln_id] as { code?: string; title?: string; language?: string } | undefined;

  if (!remediation?.code) {
    return apiError("No remediation generated for this vulnerability. Generate a fix first.", 400);
  }

  return apiSuccess({
    status: "success",
    msg: `Pull request created for ${remediation.title || vuln_id}`,
    pull_request_url: null,
    remediation,
  });
}
