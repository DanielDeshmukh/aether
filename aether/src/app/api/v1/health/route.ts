import { NextResponse } from "next/server";
import { prisma } from "@/lib/db";

export async function GET() {
  let dbStatus = "ok";
  try {
    await prisma.$queryRaw`SELECT 1`;
  } catch {
    dbStatus = "error";
  }

  return NextResponse.json({
    status: dbStatus === "ok" ? "online" : "degraded",
    version: "2.0.0",
    framework: "nextjs",
    database: dbStatus,
    timestamp: new Date().toISOString(),
  });
}
