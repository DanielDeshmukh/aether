import { NextRequest } from "next/server";
import { prisma } from "@/lib/db";
import { decodeToken } from "@/lib/auth";

export async function GET(request: NextRequest) {
  const authHeader = request.headers.get("authorization");
  const token = authHeader?.startsWith("Bearer ") ? authHeader.slice(7) : request.nextUrl.searchParams.get("token");
  if (!token) {
    return Response.json({ detail: "Missing token" }, { status: 401 });
  }

  const payload = decodeToken(token);
  if (!payload) {
    return Response.json({ detail: "Invalid token" }, { status: 401 });
  }

  const encoder = new TextEncoder();
  const stream = new ReadableStream({
    start(controller) {
      const send = (event: string, data: unknown) => {
        controller.enqueue(encoder.encode(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`));
      };

      let lastScanIds = new Set<string>();

      const poll = async () => {
        try {
          const scans = await prisma.scan.findMany({
            where: { userId: payload.sub },
            orderBy: { createdAt: "desc" },
            take: 50,
            select: { id: true, status: true, targetUrl: true, threatLevel: true, createdAt: true, completedAt: true },
          });

          const currentIds = new Set(scans.map((s) => s.id));

          for (const scan of scans) {
            const isNew = !lastScanIds.has(scan.id);
            send("scan_update", { scan, isNew });
          }

          lastScanIds = currentIds;
        } catch {
          clearInterval(interval);
          controller.close();
        }
      };

      poll();
      const interval = setInterval(poll, 5000);

      request.signal.addEventListener("abort", () => {
        clearInterval(interval);
        controller.close();
      });
    },
  });

  return new Response(stream, {
    headers: {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache",
      Connection: "keep-alive",
    },
  });
}
