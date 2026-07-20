"use client";

import { useEffect, useState, useCallback } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import { buildWsUrl, apiRequest } from "@/lib/api-client";

function normalizePlan(initialPlan: unknown): Array<Record<string, unknown>> {
  if (typeof initialPlan === "string") { try { return normalizePlan(JSON.parse(initialPlan)); } catch { return []; } }
  if (Array.isArray(initialPlan)) return initialPlan as Array<Record<string, unknown>>;
  if (initialPlan && Array.isArray((initialPlan as Record<string, unknown>).steps)) return (initialPlan as Record<string, unknown>).steps as Array<Record<string, unknown>>;
  return [];
}

function normalizeReport(finalReport: unknown): Record<string, unknown> {
  if (typeof finalReport === "string") { try { return normalizeReport(JSON.parse(finalReport)); } catch { return {}; } }
  return (finalReport || {}) as Record<string, unknown>;
}

function statusTone(status: unknown) {
  const normalized = typeof status === "string" ? status.trim().toLowerCase() : "";
  if (normalized === "failed") return "border-red-500/30 bg-red-500/10 text-red-500";
  if (normalized === "completed") return "border-green-500/30 bg-green-500/10 text-green-500";
  return "border-lambo-gold/30 bg-lambo-gold/10 text-lambo-gold";
}

export default function ScanDetailPage() {
  const params = useParams();
  const scanId = params.scanId as string;
  const [scan, setScan] = useState<Record<string, unknown> | null>(null);
  const [error, setError] = useState("");
  const [isLoading, setIsLoading] = useState(true);
  const [loadingFixId, setLoadingFixId] = useState("");
  const [remediationError, setRemediationError] = useState("");
  const [copiedFixId, setCopiedFixId] = useState("");
  const [loadingAction, setLoadingAction] = useState("");
  const [gitPushStatus, setGitPushStatus] = useState("");
  const [loadingPrId, setLoadingPrId] = useState("");
  const [screenshots, setScreenshots] = useState<Record<string, string>>({});

  const refetchScan = useCallback(async () => {
    try {
      const response = await apiRequest(`/api/v1/scans/${scanId}`);
      const data = await response.json();
      setScan(data ?? null);
    } catch { console.error("Failed to refetch scan"); }
  }, [scanId]);

  useEffect(() => {
    let isMounted = true;
    const loadScan = async () => {
      setIsLoading(true);
      setError("");
      try {
        const response = await apiRequest(`/api/v1/scans/${scanId}`);
        const data = await response.json();
        if (!isMounted) return;
        setScan(data ?? null);
      } catch (err) {
        if (!isMounted) return;
        setError(err instanceof Error ? err.message.toUpperCase() : "FAILED TO LOAD SCAN");
        setScan(null);
      }
      setIsLoading(false);
    };
    loadScan();
    return () => { isMounted = false; };
  }, [scanId]);

  const finalReport = normalizeReport(scan?.final_report);
  const planSteps = normalizePlan(scan?.initial_plan);
  const results = (scan?.results ?? {}) as Record<string, unknown>;
  const portScan = results.port_scan as Record<string, unknown> | undefined;
  const headerAudit = results.header_audit as Record<string, unknown> | undefined;
  const auditEngine = results.audit_engine as Record<string, unknown> | undefined;
  const remediations = (scan?.remediations ?? {}) as Record<string, unknown>;
  const auditFindings = (auditEngine?.findings ?? []) as Array<Record<string, unknown>>;
  const headerFindings = (headerAudit?.findings ?? []) as Array<Record<string, unknown>>;
  const findings = auditFindings.length ? auditFindings : headerFindings;
  const scanStatus = typeof scan?.status === "string" ? (scan.status as string).toUpperCase() : "PENDING";
  const autoRemediation = (finalReport.auto_remediation ?? {}) as Record<string, unknown>;
  const lastPullRequest = (autoRemediation.last_pull_request ?? null) as Record<string, unknown> | null;

  const handleDownloadPdf = async () => {
    try {
      const response = await apiRequest(`/api/v1/scans/${scanId}/report`);
      const blob = await response.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `aether-report-${scanId.slice(0, 8)}.pdf`;
      a.click();
      URL.revokeObjectURL(url);
    } catch { console.error("Failed to download PDF"); }
  };

  const handlePause = async () => { setLoadingAction("pause"); try { await apiRequest(`/api/v1/scan/${scanId}/pause`, { method: "POST" }); await refetchScan(); } catch { /* ignore */ } setLoadingAction(""); };
  const handleResume = async () => { setLoadingAction("resume"); try { await apiRequest(`/api/v1/scan/${scanId}/resume`, { method: "POST" }); await refetchScan(); } catch { /* ignore */ } setLoadingAction(""); };
  const handleTerminate = async () => { setLoadingAction("terminate"); try { await apiRequest(`/api/v1/scan/${scanId}/terminate`, { method: "POST" }); await refetchScan(); } catch { /* ignore */ } setLoadingAction(""); };

  const handleRemediate = async (vulnId: string) => {
    setLoadingFixId(vulnId);
    setRemediationError("");
    const token = document.cookie.match(/(?:^|;\s*)access_token=([^;]*)/)?.[1] ?? "";
    const socket = new WebSocket(buildWsUrl(`/ws/remediation/${scanId}?user_id=placeholder`));
    socket.onopen = () => socket.send(JSON.stringify({ action: "generate_fix", vuln_id: vulnId }));
    socket.onmessage = (event) => {
      const payload = JSON.parse(event.data);
      if (payload.type === "error") { setRemediationError(payload.msg ?? "REMEDIATION REQUEST FAILED."); setLoadingFixId(""); socket.close(); return; }
      if (payload.remediation) {
        setScan((current) => ({
          ...current,
          final_report: payload.final_report ?? current?.final_report,
          remediations: { ...(current?.remediations as Record<string, unknown> ?? {}), [vulnId]: payload.remediation },
        }));
      }
      setLoadingFixId("");
      setTimeout(refetchScan, 1500);
      socket.close();
    };
    socket.onerror = () => { setRemediationError("REMEDIATION SOCKET FAILED."); setLoadingFixId(""); socket.close(); };
  };

  const handleCreatePullRequest = async (vulnId: string) => {
    if (!autoRemediation?.target_id) { setRemediationError("NO GIT REMEDIATION TARGET IS CONFIGURED."); return; }
    setLoadingPrId(vulnId);
    setGitPushStatus("");
    setRemediationError("");
    const socket = new WebSocket(buildWsUrl(`/ws/remediation/${scanId}?user_id=placeholder`));
    socket.onopen = () => socket.send(JSON.stringify({ action: "create_pull_request", vuln_id: vulnId, target_id: autoRemediation.target_id }));
    socket.onmessage = (event) => {
      const payload = JSON.parse(event.data);
      if (payload.type === "error") { setRemediationError(payload.msg ?? "PULL REQUEST CREATION FAILED."); setLoadingPrId(""); socket.close(); return; }
      if (payload.type === "git_push_status") {
        setGitPushStatus(payload.msg ?? "");
        if (payload.status === "success") { setScan((current) => ({ ...current, final_report: payload.final_report ?? current?.final_report })); setLoadingPrId(""); socket.close(); return; }
        if (payload.status === "error") { setRemediationError(payload.msg ?? "PR CREATION FAILED."); setLoadingPrId(""); socket.close(); }
      }
    };
    socket.onerror = () => { setRemediationError("GIT SOCKET FAILED."); setLoadingPrId(""); socket.close(); };
  };

  const handleCopy = async (vulnId: string, code: string) => {
    try { await navigator.clipboard.writeText(code); setCopiedFixId(vulnId); window.setTimeout(() => setCopiedFixId((c) => c === vulnId ? "" : c), 1800); } catch { setRemediationError("COPY TO CLIPBOARD FAILED."); }
  };

  const handleAction = async (action: string) => {
    try { await apiRequest(`/api/v1/scan/${scanId}/${action}`, { method: "POST" }); await refetchScan(); } catch { console.error(`Failed to ${action} scan`); }
  };

  return (
    <div className="min-h-screen bg-[#050505] font-lambo text-lambo-white">
      <main className="relative overflow-hidden px-5 pb-16 pt-24 md:px-10 md:pt-28">
        <div className="absolute inset-0 bg-[radial-gradient(circle_at_top_right,rgba(255,192,0,0.05),transparent_28%),linear-gradient(180deg,rgba(255,255,255,0.02),transparent_22%)]" />

        <section className="relative mx-auto max-w-7xl space-y-6">
          <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
            <div className="min-w-0">
              <p className="text-[10px] font-bold tracking-[0.4em] text-lambo-gold sm:text-xs">// Mission Debrief</p>
              <h1 className="mt-3 break-all text-xl font-black tracking-[-0.03em] text-lambo-white sm:text-3xl md:text-5xl">{(scan?.target_url as string) ?? "Loading Scan"}</h1>
            </div>
            <div className="flex items-center gap-3 flex-wrap justify-start md:justify-end">
              <button type="button" onClick={handleDownloadPdf} className="chamfer-button border border-lambo-gold/30 bg-lambo-gold/10 px-4 py-3 text-[10px] font-bold tracking-[0.2em] text-lambo-gold transition-colors hover:bg-lambo-gold/20">Download PDF</button>
              {(scan?.status as string)?.toLowerCase() === "running" && (
                <>
                  <button type="button" onClick={handlePause} disabled={!!loadingAction} className="chamfer-button border border-yellow-500/30 bg-yellow-500/10 px-4 py-3 text-[10px] font-bold tracking-[0.2em] text-yellow-400 transition-colors hover:bg-yellow-500/20 disabled:opacity-50">{loadingAction === "pause" ? "Pausing..." : "Pause"}</button>
                  <button type="button" onClick={handleTerminate} disabled={!!loadingAction} className="chamfer-button border border-red-500/30 bg-red-500/10 px-4 py-3 text-[10px] font-bold tracking-[0.2em] text-red-400 transition-colors hover:bg-red-500/20 disabled:opacity-50">{loadingAction === "terminate" ? "Terminating..." : "Terminate"}</button>
                </>
              )}
              {(scan?.status as string)?.toLowerCase() === "paused" && (
                <button type="button" onClick={handleResume} disabled={!!loadingAction} className="chamfer-button border border-green-500/30 bg-green-500/10 px-4 py-3 text-[10px] font-bold tracking-[0.2em] text-green-400 transition-colors hover:bg-green-500/20 disabled:opacity-50">{loadingAction === "resume" ? "Resuming..." : "Resume"}</button>
              )}
              <Link href="/dashboard" className="chamfer-button border border-white/10 bg-white/5 px-4 py-3 text-[10px] font-bold tracking-[0.2em] text-lambo-ash transition-colors hover:border-lambo-gold/40 hover:text-lambo-gold">Back to Dashboard</Link>
            </div>
          </div>

          {error && <div className="chamfer-panel border border-red-500/30 bg-red-500/10 px-5 py-4 text-[10px] font-bold tracking-[0.28em] text-red-500">{error}</div>}

          {isLoading ? (
            <div className="chamfer-panel border border-white/10 bg-white/[0.02] p-4 sm:p-6 md:p-8 text-[10px] tracking-[0.3em] text-lambo-ash">Loading debrief...</div>
          ) : scan ? (
            <>
              <section className="grid gap-6 md:grid-cols-2 xl:grid-cols-[1.2fr_0.8fr]">
                <div className="chamfer-panel border border-lambo-gold/20 bg-[#0d0d0d] p-4 sm:p-6 md:p-8">
                  <p className="text-[10px] font-bold tracking-[0.42em] text-lambo-gold">// Risk Impact</p>
                  <p className="mt-5 text-lg font-bold tracking-tight text-lambo-white md:text-xl">{(finalReport.risk_impact as string) ?? "Final synthesis pending."}</p>
                  <div className="mt-8 flex flex-wrap items-center gap-3">
                    <div className="inline-flex items-center border border-lambo-gold/30 bg-lambo-gold/10 px-4 py-3 text-[10px] font-bold tracking-[0.2em] text-lambo-gold">Threat Level: {(finalReport.threat_level as string) ?? (scan.threat_level as string) ?? "unknown"}</div>
                    <div className={`inline-flex items-center border px-4 py-3 text-[10px] font-bold tracking-[0.2em] ${statusTone(scan?.status)}`}>Status: {scanStatus.charAt(0) + scanStatus.slice(1).toLowerCase()}</div>
                  </div>
                  {(finalReport.error_message as string) && (
                    <div className="mt-5 chamfer-panel border border-red-500/30 bg-red-500/10 p-4 text-[10px] font-bold tracking-[0.22em] text-red-500">{finalReport.error_message as string}</div>
                  )}
                </div>

                <div className="chamfer-panel border border-white/10 bg-white/5 p-4 sm:p-6 md:p-8">
                  <p className="text-[10px] font-bold tracking-[0.42em] text-lambo-gold">// Remediation Steps</p>
                  <div className="mt-5 space-y-4">
                    {(finalReport.remediation_steps as string[] ?? []).map((step, index) => (
                      <div key={index} className="chamfer-panel border border-white/5 bg-black/40 p-4">
                        <p className="text-[10px] font-bold tracking-[0.28em] text-lambo-gold">Action {index + 1}</p>
                        <p className="mt-3 text-sm leading-7 tracking-[0.14em] text-lambo-white">{step}</p>
                      </div>
                    ))}
                  </div>
                </div>
              </section>

              <section className="grid gap-6 md:grid-cols-2">
                <div className="chamfer-panel border border-white/10 bg-white/5 p-4 sm:p-6 md:p-8">
                  <p className="text-[10px] font-bold tracking-[0.42em] text-lambo-gold mb-5">// Vulnerabilities &amp; Remediations</p>
                  {remediationError && <div className="mb-4 chamfer-panel border border-red-500/30 bg-red-500/10 px-4 py-3 text-[10px] font-bold tracking-[0.22em] text-red-500">{remediationError}</div>}
                  {gitPushStatus && <div className="mb-4 chamfer-panel border border-lambo-cyan/30 bg-lambo-cyan/10 px-4 py-3 text-[10px] font-bold tracking-[0.22em] text-lambo-cyan">{gitPushStatus}</div>}
                  <div className="space-y-4 text-[10px] tracking-[0.22em] text-lambo-ash">
                    <div className="chamfer-panel border border-white/5 bg-black/40 p-4">
                      <p className="font-bold text-lambo-gold">Port Scan</p>
                      <p className="mt-3 text-lambo-white">Open Ports: {((portScan?.open_ports as string[]) ?? []).length ? (portScan?.open_ports as string[]).join(", ") : "None"}</p>
                    </div>
                    <div className="chamfer-panel border border-white/5 bg-black/40 p-4">
                      <p className="font-bold text-lambo-gold">Header Audit</p>
                      <p className="mt-3 text-lambo-white">Findings: {(headerAudit?.findings as unknown[] ?? []).length}</p>
                    </div>
                    {findings.map((finding) => {
                      const remediation = remediations[finding.id as string] as Record<string, unknown> | undefined;
                      return (
                        <div key={finding.id as string} className="chamfer-panel border border-white/5 bg-black/40 p-4">
                          <div className="flex items-start justify-between gap-4">
                            <div>
                              <p className="font-bold text-lambo-gold">{(finding.title as string) ?? (finding.header as string) ?? "Finding"}</p>
                              <p className="mt-2 text-[10px] uppercase leading-6 tracking-[0.16em] text-lambo-white">{(finding.detail as string) ?? (finding.detected_threat as string) ?? "No detail available."}</p>
                            </div>
                            <div className="flex flex-col items-end gap-3">
                              <button type="button" onClick={() => handleRemediate(finding.id as string)} disabled={loadingFixId === finding.id} className="chamfer-button border border-lambo-gold/30 bg-lambo-gold/10 px-4 py-3 text-[10px] font-bold tracking-[0.2em] text-lambo-gold disabled:opacity-50 hover:bg-lambo-gold/20 transition-colors">
                                {loadingFixId === finding.id ? "Generating..." : "Remediate"}
                              </button>
                              {remediation && Boolean(autoRemediation?.pr_ready) && (
                                <button type="button" onClick={() => handleCreatePullRequest(finding.id as string)} disabled={loadingPrId === finding.id} className="chamfer-button border border-lambo-cyan/30 bg-lambo-cyan/10 px-4 py-3 text-[10px] font-bold tracking-[0.2em] text-lambo-cyan disabled:opacity-50 hover:bg-lambo-cyan/20 transition-colors">
                                  {loadingPrId === finding.id ? "Opening PR..." : "Create Pull Request"}
                                </button>
                              )}
                            </div>
                          </div>
                          {loadingFixId === finding.id && !remediation && (
                            <div className="mt-4 chamfer-panel border border-lambo-gold/20 bg-lambo-gold/5 p-4">
                              <div className="flex items-center justify-between gap-3">
                                <p className="text-[10px] font-bold uppercase tracking-[0.28em] text-lambo-gold">Calculating Remediation</p>
                                <div className="flex gap-1">
                                  <span className="h-2 w-2 rounded-full bg-lambo-gold animate-bounce [animation-delay:-0.3s]" />
                                  <span className="h-2 w-2 rounded-full bg-lambo-gold animate-bounce [animation-delay:-0.15s]" />
                                  <span className="h-2 w-2 rounded-full bg-lambo-gold animate-bounce" />
                                </div>
                              </div>
                            </div>
                          )}
                          {screenshots[finding.id as string] && (
                            <div className="mt-4">
                              <p className="text-[10px] font-bold uppercase tracking-[0.28em] text-lambo-gold mb-2">Screenshot Evidence</p>
                              <img src={screenshots[finding.id as string]} alt={`Evidence for ${finding.title}`} className="border border-white/10 max-w-full rounded" />
                            </div>
                          )}
                          {!screenshots[finding.id as string] && (
                            <button type="button" onClick={async () => {
                              const vulnId = finding.id as string;
                              if (screenshots[vulnId]) return;
                              try {
                                const response = await apiRequest(`/api/v1/scans/${scanId}/vulnerabilities/${vulnId}/evidence/screenshot`);
                                if (response.ok) { const blob = await response.blob(); const url = URL.createObjectURL(blob); setScreenshots((prev) => ({ ...prev, [vulnId]: url })); }
                              } catch { /* ignore */ }
                            }} className="mt-3 text-[10px] font-bold tracking-[0.15em] text-lambo-ash hover:text-lambo-gold transition-colors">Load Screenshot Evidence</button>
                          )}
                          {remediation && (
                            <div className="mt-4 space-y-3">
                              <div className="flex flex-wrap items-center justify-between gap-3">
                                <p className="text-[10px] font-bold uppercase tracking-[0.28em] text-lambo-cyan">{remediation.title as string}</p>
                                <button type="button" onClick={() => handleCopy(finding.id as string, remediation.code as string)} className="chamfer-button border border-lambo-gold/30 bg-lambo-gold/10 px-3 py-2 text-[10px] font-bold tracking-[0.15em] text-lambo-gold hover:bg-lambo-gold/20 transition-colors">
                                  {copiedFixId === finding.id ? "Copied" : "Copy to Clipboard"}
                                </button>
                              </div>
                              <p className="text-[10px] uppercase leading-6 tracking-[0.16em] text-lambo-white">{remediation.summary as string}</p>
                              {lastPullRequest?.pull_request_url ? (
                                <a href={String(lastPullRequest.pull_request_url)} target="_blank" rel="noreferrer" className="inline-flex items-center text-[10px] font-bold uppercase tracking-[0.22em] text-lambo-cyan hover:text-lambo-gold transition-colors">View Pull Request</a>
                              ) : null}
                              <div className="chamfer-panel border border-lambo-gold/30 bg-lambo-gold/10 p-[1px]">
                                <div className="bg-lambo-charcoal p-4">
                                  <div className="mb-3 text-[10px] font-bold uppercase tracking-[0.28em] text-lambo-gold">{remediation.language as string}</div>
                                  <pre className="overflow-x-auto whitespace-pre-wrap break-words font-mono text-sm leading-7 text-lambo-gold"><code>{remediation.code as string}</code></pre>
                                </div>
                              </div>
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>
                </div>

                <div className="chamfer-panel border border-white/10 bg-white/5 p-4 sm:p-6 md:p-8">
                  <p className="text-[10px] font-bold tracking-[0.42em] text-lambo-gold">// Strategy Trace</p>
                  <div className="mt-5 space-y-4">
                    {planSteps.map((step, index) => (
                      <div key={index} className="chamfer-panel border border-white/5 bg-black/40 p-4">
                        <p className="text-[10px] font-bold tracking-[0.28em] text-lambo-gold">{(step.label as string) ?? `Step ${index + 1}`}</p>
                        <p className="mt-3 text-sm leading-7 tracking-[0.14em] text-lambo-white">{(step.message as string) ?? "Unavailable"}</p>
                      </div>
                    ))}
                  </div>
                </div>
              </section>
            </>
          ) : (
            <div className="chamfer-panel border border-white/10 bg-white/[0.02] p-4 sm:p-6 md:p-8 text-[10px] uppercase tracking-[0.3em] text-lambo-ash">Scan not found.</div>
          )}
        </section>
      </main>
    </div>
  );
}
