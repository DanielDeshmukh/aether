import { NextRequest } from "next/server";
import { prisma } from "@/lib/db";
import { apiSuccess, apiError } from "@/lib/api-utils";

export async function GET(request: NextRequest) {
  const userId = request.headers.get("x-user-id");
  if (!userId) return apiError("Not authenticated", 401);

  const targets = await prisma.target.findMany({
    where: { userId },
    orderBy: { createdAt: "desc" },
  });

  return apiSuccess({
    targets: targets.map((t) => ({
      id: t.id,
      domain: t.domain,
      git_provider: t.gitProvider,
      repository: t.repository,
      project_id: t.projectId,
      default_branch: t.defaultBranch,
      base_branch: t.baseBranch,
      api_base_url: t.apiBaseUrl,
      repo_web_url: t.repoWebUrl,
      is_verified: t.isVerified,
    })),
  });
}

export async function POST(request: NextRequest) {
  const userId = request.headers.get("x-user-id");
  if (!userId) return apiError("Not authenticated", 401);

  const body = await request.json();
  const { target_id, git_provider, access_token, repository, project_id, default_branch, base_branch, api_base_url, repo_web_url } = body;

  if (!target_id) return apiError("target_id is required", 400);
  if (!repository) return apiError("repository is required", 400);

  const target = await prisma.target.findFirst({
    where: { id: target_id, userId },
  });

  if (!target) return apiError("Target not found", 404);

  await prisma.target.update({
    where: { id: target_id },
    data: {
      gitProvider: git_provider ?? target.gitProvider,
      accessToken: access_token || target.accessToken,
      repository: repository ?? target.repository,
      projectId: project_id ?? target.projectId,
      defaultBranch: default_branch ?? target.defaultBranch,
      baseBranch: base_branch ?? target.baseBranch,
      apiBaseUrl: api_base_url ?? target.apiBaseUrl,
      repoWebUrl: repo_web_url ?? target.repoWebUrl,
    },
  });

  return apiSuccess({ status: "saved" });
}
