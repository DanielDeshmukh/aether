"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";

interface Vulnerability {
  id: string;
  title: string;
  severity: string;
  category: string;
  detail: string;
  evidence: Record<string, unknown>;
}

interface Scan {
  id: string;
  targetUrl: string;
  status: string;
  threatLevel: string;
  results: Record<string, unknown>;
  finalReport: Record<string, unknown>;
  remediations: Record<string, unknown>;
  vulnerabilities: Vulnerability[];
  createdAt: string;
  completedAt: string | null;
}

export default function ScanDetailPage() {
  const params = useParams();
  const scanId = params.scanId as string;
  const [scan, setScan] = useState<Scan | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch(`/api/v1/scans/${scanId}`)
      .then((res) => res.json())
      .then((data) => setScan(data.data))
      .finally(() => setLoading(false));
  }, [scanId]);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-full">
        <div className="text-white/30 text-sm">Loading scan...</div>
      </div>
    );
  }

  if (!scan) {
    return (
      <div className="flex items-center justify-center h-full">
        <div className="text-white/30 text-sm">Scan not found.</div>
      </div>
    );
  }

  const report = scan.finalReport as Record<string, unknown>;
  const steps = (Array.isArray(report.remediation_steps) ? report.remediation_steps : []) as string[];

  return (
    <div className="max-w-4xl mx-auto px-8 py-16 space-y-8">
      <div>
        <div className="flex items-center gap-3 mb-2">
          <h1 className="text-xl font-bold">{scan.targetUrl}</h1>
          <span className="px-2 py-0.5 rounded text-[10px] font-medium uppercase bg-white/5 text-white/50">
            {scan.status}
          </span>
        </div>
        <p className="text-xs text-white/30">
          Created {new Date(scan.createdAt).toLocaleString()}
          {scan.completedAt && ` \u00B7 Completed ${new Date(scan.completedAt).toLocaleString()}`}
        </p>
      </div>

      <div className="grid grid-cols-3 gap-4">
        <div className="px-4 py-3 bg-white/[0.02] border border-white/5 rounded">
          <div className="text-xs text-white/40 mb-1">Threat Level</div>
          <div className="text-lg font-bold text-aether-gold">{String(report.threat_level || scan.threatLevel)}</div>
        </div>
        <div className="px-4 py-3 bg-white/[0.02] border border-white/5 rounded">
          <div className="text-xs text-white/40 mb-1">Vulnerabilities</div>
          <div className="text-lg font-bold">{scan.vulnerabilities.length}</div>
        </div>
        <div className="px-4 py-3 bg-white/[0.02] border border-white/5 rounded">
          <div className="text-xs text-white/40 mb-1">Risk Impact</div>
          <div className="text-sm font-medium mt-1 leading-snug">{String(report.risk_impact || "N/A")}</div>
        </div>
      </div>

      {scan.vulnerabilities.length > 0 && (
        <div>
          <h2 className="text-sm font-semibold uppercase tracking-wider text-white/50 mb-4">Findings</h2>
          <div className="space-y-2">
            {scan.vulnerabilities.map((v) => (
              <div key={v.id} className="px-4 py-3 bg-white/[0.02] border border-white/5 rounded">
                <div className="flex items-center gap-3">
                  <span className={`px-2 py-0.5 rounded text-[10px] font-medium uppercase ${
                    v.severity === "high" ? "text-orange-400 bg-orange-500/10" :
                    v.severity === "medium" ? "text-yellow-400 bg-yellow-500/10" :
                    "text-white/30 bg-white/5"
                  }`}>
                    {v.severity}
                  </span>
                  <span className="text-sm font-medium">{v.title}</span>
                  <span className="text-xs text-white/30">{v.category}</span>
                </div>
                <p className="text-xs text-white/40 mt-2">{v.detail}</p>
              </div>
            ))}
          </div>
        </div>
      )}

      {steps.length > 0 && (
        <div>
          <h2 className="text-sm font-semibold uppercase tracking-wider text-white/50 mb-4">Remediation Steps</h2>
          <div className="space-y-2">
            {steps.map((step, i) => (
              <div key={i} className="flex gap-3 px-4 py-3 bg-white/[0.02] border border-white/5 rounded">
                <span className="text-aether-gold text-xs font-bold mt-0.5">{i + 1}</span>
                <span className="text-sm text-white/70">{step}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
