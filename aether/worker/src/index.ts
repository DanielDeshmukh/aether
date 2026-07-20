import http from "http";
import { URL } from "url";

const PORT = parseInt(process.env.WORKER_PORT || "4000", 10);

async function handleScan(scanId: string, targetUrl: string, userId: string) {
  const { executeScan } = await import("../../src/lib/scanner/index.js");

  console.log(`[worker] Starting scan ${scanId} for ${targetUrl}`);

  try {
    await executeScan({
      scanId,
      targetUrl,
      userId,
      onEvent: async (event) => {
        console.log(`[worker:${scanId}] ${event.type}: ${event.msg}`);
      },
    });
    console.log(`[worker] Scan ${scanId} completed`);
  } catch (err) {
    console.error(`[worker] Scan ${scanId} failed:`, err);
    const { prisma } = await import("../../src/lib/db.js");
    await prisma.scan.update({
      where: { id: scanId },
      data: {
        status: "failed",
        completedAt: new Date(),
        threatLevel: "critical",
        finalReport: {
          threat_level: "critical",
          risk_impact: `Scan failed: ${err instanceof Error ? err.message : "Unknown error"}`,
          remediation_steps: ["Retry the scan.", "Check worker logs."],
        },
      },
    });
  }
}

const server = http.createServer(async (req, res) => {
  res.setHeader("Content-Type", "application/json");

  if (req.method === "GET" && req.url === "/health") {
    res.writeHead(200);
    res.end(JSON.stringify({ status: "ok", timestamp: new Date().toISOString() }));
    return;
  }

  if (req.method === "POST" && req.url === "/scan") {
    let body = "";
    for await (const chunk of req) body += chunk;

    try {
      const { scanId, targetUrl, userId } = JSON.parse(body);

      if (!scanId || !targetUrl || !userId) {
        res.writeHead(400);
        res.end(JSON.stringify({ error: "scanId, targetUrl, and userId are required" }));
        return;
      }

      res.writeHead(202);
      res.end(JSON.stringify({ status: "accepted", scanId }));

      handleScan(scanId, targetUrl, userId).catch((err) => {
        console.error(`[worker] Unhandled error for scan ${scanId}:`, err);
      });
    } catch {
      res.writeHead(400);
      res.end(JSON.stringify({ error: "Invalid JSON" }));
    }
    return;
  }

  res.writeHead(404);
  res.end(JSON.stringify({ error: "Not found" }));
});

server.listen(PORT, "0.0.0.0", () => {
  console.log(`[worker] Scan worker listening on port ${PORT}`);
});
