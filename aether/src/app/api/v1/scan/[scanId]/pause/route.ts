import { NextRequest } from "next/server";
import { apiSuccess, apiError } from "@/lib/api-utils";
import { validateAndUpdateStatus } from "../_lib";

export async function POST(
  request: NextRequest,
  { params }: { params: Promise<{ scanId: string }> }
) {
  const userId = request.headers.get("x-user-id");
  if (!userId) return apiError("Not authenticated", 401);

  const { scanId } = await params;
  const result = await validateAndUpdateStatus(scanId, userId, ["running", "pending"], "paused");
  if (result instanceof Response) return result;

  return apiSuccess(result.data);
}
