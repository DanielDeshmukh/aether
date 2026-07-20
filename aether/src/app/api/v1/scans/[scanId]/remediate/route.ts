import { NextRequest } from "next/server";
import { prisma } from "@/lib/db";
import { apiSuccess, apiError } from "@/lib/api-utils";
import { generateRemediation } from "@/lib/scanner/orchestrator/remediation-agent";

export async function POST(
  request: NextRequest,
  { params }: { params: Promise<{ scanId: string }> }
) {
  const userId = request.headers.get("x-user-id");
  if (!userId) return apiError("Not authenticated", 401);

  const { scanId } = await params;
  const body = await request.json();
  const { vuln_id } = body;

  if (!vuln_id) return apiError("vuln_id is required", 400);

  const scan = await prisma.scan.findFirst({
    where: { id: scanId, userId },
    include: { vulnerabilities: true },
  });

  if (!scan) return apiError("Scan not found", 404);

  const vulnerability = scan.vulnerabilities.find((v) => v.id === vuln_id);
  if (!vulnerability) return apiError("Vulnerability not found", 404);

  const results = (scan.results ?? {}) as Record<string, unknown>;

  const remediation = await generateRemediation(
    scan.targetUrl,
    {
      id: vulnerability.id,
      title: vulnerability.title,
      severity: vulnerability.severity,
      category: vulnerability.category,
      detail: vulnerability.detail ?? undefined,
      detectedThreat: vulnerability.detectedThreat ?? undefined,
    },
    results
  );

  const updatedRemediations = {
    ...(scan.remediations as Record<string, unknown>),
    [vuln_id]: remediation,
  };

  await prisma.scan.update({
    where: { id: scanId },
    data: { remediations: updatedRemediations },
  });

  return apiSuccess({ remediation, final_report: scan.finalReport });
}
