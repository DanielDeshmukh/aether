"use client";

import { useEffect, useState } from "react";
import Link from "next/link";

interface Scan {
  id: string;
  targetUrl: string;
  status: string;
  threatLevel: string;
  createdAt: string;
  completedAt: string | null;
}

const severityColors: Record<string, string> = {
  critical: "text-red-400 bg-red-500/10",
  high: "text-orange-400 bg-orange-500/10",
  medium: "text-yellow-400 bg-yellow-500/10",
  low: "text-green-400 bg-green-500/10",
  unknown: "text-white/30 bg-white/5",
};

export default function DashboardPage() {
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch("/api/v1/scans")
      .then((res) => res.json())
      .then((data) => setScans(data.data || []))
      .finally(() => setLoading(false));
  }, []);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-full">
        <div className="text-white/30 text-sm">Loading scans...</div>
      </div>
    );
  }

  return (
    <div className="max-w-4xl mx-auto px-8 py-16">
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-2xl font-bold">Dashboard</h1>
          <p className="text-white/40 text-sm mt-1">{scans.length} scan{scans.length !== 1 ? "s" : ""} total</p>
        </div>
        <Link
          href="/home"
          className="px-4 py-2 bg-aether-gold text-black font-semibold rounded chamfer-button text-xs hover:bg-aether-gold-deep transition-colors"
        >
          New Scan
        </Link>
      </div>

      {scans.length === 0 ? (
        <div className="text-center py-24 text-white/30">
          <p className="text-sm">No scans yet.</p>
          <Link href="/home" className="text-aether-gold text-sm mt-2 inline-block hover:underline">
            Start your first scan
          </Link>
        </div>
      ) : (
        <div className="space-y-2">
          {scans.map((scan) => (
            <Link
              key={scan.id}
              href={`/dashboard/${scan.id}`}
              className="block px-5 py-4 bg-white/[0.02] border border-white/5 rounded hover:border-white/10 transition-colors"
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-4">
                  <span
                    className={`px-2 py-0.5 rounded text-[10px] font-medium uppercase ${severityColors[scan.threatLevel] || severityColors.unknown}`}
                  >
                    {scan.threatLevel}
                  </span>
                  <div>
                    <div className="text-sm font-medium">{scan.targetUrl}</div>
                    <div className="text-xs text-white/30 mt-0.5">
                      {scan.status} &middot; {new Date(scan.createdAt).toLocaleDateString()}
                    </div>
                  </div>
                </div>
                <div className="text-white/20 text-xs">
                  {scan.completedAt
                    ? `${Math.round((new Date(scan.completedAt).getTime() - new Date(scan.createdAt).getTime()) / 1000)}s`
                    : "Running..."}
                </div>
              </div>
            </Link>
          ))}
        </div>
      )}
    </div>
  );
}
