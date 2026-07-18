import { NextRequest } from "next/server";
import { prisma } from "@/lib/db";
import { decodeToken } from "@/lib/auth";

export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ scanId: string }> }
) {
  const authHeader = request.headers.get("authorization");
  const token = authHeader?.startsWith("Bearer ") ? authHeader.slice(7) : null;
  if (!token) {
    return Response.json({ detail: "Missing token" }, { status: 401 });
  }

  const payload = decodeToken(token);
  if (!payload) {
    return Response.json({ detail: "Invalid token" }, { status: 401 });
  }

  const { scanId } = await params;

  const scan = await prisma.scan.findFirst({
    where: { id: scanId, userId: payload.sub },
  });

  if (!scan) {
    return Response.json({ detail: "Scan not found" }, { status: 404 });
  }

  const encoder = new TextEncoder();
  const stream = new ReadableStream({
    start(controller) {
      const send = (event: string, data: unknown) => {
        controller.enqueue(encoder.encode(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`));
      };

      send("progress", {
        scanId: scan.id,
        status: scan.status,
        targetUrl: scan.targetUrl,
        threatLevel: scan.threatLevel,
      });

      if (scan.status === "completed" || scan.status === "failed") {
        send("complete", {
          scanId: scan.id,
          status: scan.status,
          threatLevel: scan.threatLevel,
        });
        controller.close();
        return;
      }

      const interval = setInterval(async () => {
        try {
          const current = await prisma.scan.findUnique({
            where: { id: scanId },
          });

          if (!current) {
            clearInterval(interval);
            controller.close();
            return;
          }

          send("progress", {
            scanId: current.id,
            status: current.status,
            targetUrl: current.targetUrl,
            threatLevel: current.threatLevel,
          });

          if (current.status === "completed" || current.status === "failed") {
            clearInterval(interval);
            send("complete", {
              scanId: current.id,
              status: current.status,
              threatLevel: current.threatLevel,
            });
            controller.close();
          }
        } catch {
          clearInterval(interval);
          controller.close();
        }
      }, 3000);

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
