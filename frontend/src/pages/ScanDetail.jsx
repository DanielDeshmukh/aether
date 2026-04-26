import React, { useEffect, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import Header from '../components/Header';
import { buildWsUrl } from '../lib/api';
import { supabase } from '../lib/supabaseClient';
import { useDocumentTitle } from '../lib/useDocumentTitle';

const normalizePlan = (initialPlan) => {
  if (typeof initialPlan === 'string') {
    try {
      return normalizePlan(JSON.parse(initialPlan));
    } catch {
      return [];
    }
  }
  if (Array.isArray(initialPlan)) {
    return initialPlan;
  }
  if (initialPlan && Array.isArray(initialPlan.steps)) {
    return initialPlan.steps;
  }
  return [];
};

const normalizeReport = (finalReport) => {
  if (typeof finalReport === 'string') {
    try {
      return normalizeReport(JSON.parse(finalReport));
    } catch {
      return {};
    }
  }
  return finalReport || {};
};

const statusTone = (status) => {
  const normalized = typeof status === 'string' ? status.trim().toLowerCase() : '';
  if (normalized === 'failed') {
    return 'border-[rgba(255,92,92,0.3)] bg-[rgba(255,92,92,0.08)] text-[#ff7b72]';
  }
  if (normalized === 'completed') {
    return 'border-[rgba(0,255,65,0.3)] bg-[rgba(0,255,65,0.08)] text-[#00ff41]';
  }
  return 'border-[rgba(212,175,55,0.3)] bg-[rgba(212,175,55,0.08)] text-[#d4af37]';
};

const ScanDetail = () => {
  const { scanId } = useParams();
  const [scan, setScan] = useState(null);
  const [error, setError] = useState('');
  const [isLoading, setIsLoading] = useState(true);
  const [loadingFixId, setLoadingFixId] = useState('');
  const [remediationError, setRemediationError] = useState('');
  const [copiedFixId, setCopiedFixId] = useState('');

  useDocumentTitle(scan?.target_url ? `Scan Debrief ${scan.target_url}` : 'Scan Debrief');

  useEffect(() => {
    let isMounted = true;

    const loadScan = async () => {
      setIsLoading(true);
      setError('');

      const { data, error: fetchError } = await supabase
        .from('scans')
        .select('*')
        .eq('id', scanId)
        .limit(1)
        .maybeSingle();

      if (!isMounted) {
        return;
      }

      if (fetchError) {
        setError(fetchError.message.toUpperCase());
        setScan(null);
      } else {
        setScan(data ?? null);
      }

      setIsLoading(false);
    };

    loadScan();
    return () => {
      isMounted = false;
    };
  }, [scanId]);

  const finalReport = normalizeReport(scan?.final_report);
  const planSteps = normalizePlan(scan?.initial_plan);
  const portScan = scan?.results?.port_scan;
  const headerAudit = scan?.results?.header_audit;
  const remediations = scan?.remediations ?? {};
  const scanStatus = typeof scan?.status === 'string' ? scan.status.toUpperCase() : 'PENDING';
  const reportError = finalReport.error_message;

  const handleRemediate = (vulnId) => {
    setLoadingFixId(vulnId);
    setRemediationError('');
    const socket = new WebSocket(buildWsUrl(`/ws/remediation/${scan.id}`));

    socket.onopen = () => {
      socket.send(JSON.stringify({ action: 'generate_fix', vuln_id: vulnId }));
    };

    socket.onmessage = (event) => {
      const payload = JSON.parse(event.data);
      if (payload.type === 'error') {
        setRemediationError(payload.msg ?? 'REMEDIATION REQUEST FAILED.');
        setLoadingFixId('');
        socket.close();
        return;
      }
      if (payload.remediation) {
        setScan((current) => ({
          ...current,
          remediations: {
            ...(current?.remediations ?? {}),
            [vulnId]: payload.remediation,
          },
        }));
      }
      setLoadingFixId('');
      socket.close();
    };

    socket.onerror = () => {
      setRemediationError('REMEDIATION SOCKET FAILED BEFORE A FIX COULD BE RETURNED.');
      setLoadingFixId('');
      socket.close();
    };
  };

  const handleCopy = async (vulnId, code) => {
    try {
      await navigator.clipboard.writeText(code);
      setCopiedFixId(vulnId);
      window.setTimeout(() => {
        setCopiedFixId((current) => (current === vulnId ? '' : current));
      }, 1800);
    } catch {
      setRemediationError('COPY TO CLIPBOARD FAILED IN THIS BROWSER SESSION.');
    }
  };

  return (
    <div className="min-h-screen bg-[#050505] font-mono text-white">
      <Header />
      <main className="relative overflow-hidden px-5 pb-16 pt-28 md:px-10">
        <div className="absolute inset-0 bg-[radial-gradient(circle_at_top_right,rgba(212,175,55,0.12),transparent_28%),linear-gradient(180deg,rgba(255,255,255,0.02),transparent_22%)]" />

        <section className="relative mx-auto max-w-7xl space-y-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-[10px] font-bold uppercase tracking-[0.42em] text-[#d4af37]">Mission Debrief</p>
              <h1 className="mt-3 break-all text-3xl font-black uppercase tracking-[-0.06em] text-[#f5f1df] md:text-5xl">
                {scan?.target_url ?? 'Loading Scan'}
              </h1>
            </div>
            <Link
              to="/dashboard"
              className="chamfer-button border border-[rgba(212,175,55,0.34)] bg-[rgba(212,175,55,0.08)] px-4 py-3 text-[10px] font-black uppercase tracking-[0.28em] text-[#d4af37]"
            >
              Back
            </Link>
          </div>

          {error && (
            <div className="chamfer-panel border border-[rgba(255,0,0,0.32)] bg-[rgba(255,0,0,0.08)] px-5 py-4 text-[10px] font-bold uppercase tracking-[0.28em] text-[#ff5c5c]">
              {error}
            </div>
          )}

          {isLoading ? (
            <div className="chamfer-panel border border-white/10 bg-white/[0.02] p-8 text-[10px] uppercase tracking-[0.3em] text-[#8f8a78]">
              Loading debrief...
            </div>
          ) : scan ? (
            <>
              <section className="grid gap-6 xl:grid-cols-[1.2fr_0.8fr]">
                <div className="chamfer-panel border border-[rgba(212,175,55,0.24)] bg-[linear-gradient(180deg,rgba(17,17,17,0.98),rgba(9,9,9,0.98))] p-8">
                  <p className="text-[10px] font-bold uppercase tracking-[0.42em] text-[#d4af37]">Risk Impact</p>
                  <p className="mt-5 text-xl font-black uppercase leading-10 tracking-[-0.04em] text-[#f5f1df] md:text-2xl">
                    {finalReport.risk_impact ?? 'Final synthesis pending.'}
                  </p>
                  <div className="mt-8 flex flex-wrap items-center gap-3">
                    <div className="inline-flex items-center border border-[rgba(212,175,55,0.3)] bg-[rgba(212,175,55,0.08)] px-4 py-3 text-[10px] font-black uppercase tracking-[0.3em] text-[#d4af37]">
                      Threat Level: {(finalReport.threat_level ?? scan.threat_level ?? 'unknown').toUpperCase()}
                    </div>
                    <div className={`inline-flex items-center border px-4 py-3 text-[10px] font-black uppercase tracking-[0.3em] ${statusTone(scan?.status)}`}>
                      Status: {scanStatus}
                    </div>
                  </div>
                  {reportError && (
                    <div className="mt-5 chamfer-panel border border-[rgba(255,92,92,0.3)] bg-[rgba(255,92,92,0.08)] p-4 text-[10px] font-bold uppercase tracking-[0.22em] text-[#ff7b72]">
                      {reportError}
                    </div>
                  )}
                </div>

                <div className="chamfer-panel border border-white/10 bg-[rgba(255,255,255,0.02)] p-8">
                  <p className="text-[10px] font-bold uppercase tracking-[0.42em] text-[#d4af37]">Remediation Steps</p>
                  <div className="mt-5 space-y-4">
                    {(finalReport.remediation_steps ?? []).map((step, index) => (
                      <div key={index} className="chamfer-panel border border-white/8 bg-black/30 p-4">
                        <p className="text-[10px] font-bold uppercase tracking-[0.28em] text-[#d4af37]">Action {index + 1}</p>
                        <p className="mt-3 text-sm uppercase leading-7 tracking-[0.14em] text-[#f5f1df]">{step}</p>
                      </div>
                    ))}
                  </div>
                </div>
              </section>

              <section className="grid gap-6 xl:grid-cols-2">
                <div className="chamfer-panel border border-white/10 bg-[rgba(255,255,255,0.02)] p-8">
                  <p className="text-[10px] font-bold uppercase tracking-[0.42em] text-[#d4af37]">Tool Results</p>
                  {remediationError && (
                    <div className="mt-4 chamfer-panel border border-[rgba(255,92,92,0.3)] bg-[rgba(255,92,92,0.08)] px-4 py-3 text-[10px] font-bold uppercase tracking-[0.22em] text-[#ff7b72]">
                      {remediationError}
                    </div>
                  )}
                  <div className="mt-5 space-y-4 text-[10px] uppercase tracking-[0.22em] text-[#8f8a78]">
                    <div className="chamfer-panel border border-white/8 bg-black/30 p-4">
                      <p className="font-bold text-[#d4af37]">Port Scan</p>
                      <p className="mt-3 text-[#f5f1df]">
                        Open Ports: {(portScan?.open_ports ?? []).length ? portScan.open_ports.join(', ') : 'None'}
                      </p>
                    </div>
                    <div className="chamfer-panel border border-white/8 bg-black/30 p-4">
                      <p className="font-bold text-[#d4af37]">Header Audit</p>
                      <p className="mt-3 text-[#f5f1df]">
                        Findings: {(headerAudit?.findings ?? []).length}
                      </p>
                    </div>
                    {(headerAudit?.findings ?? []).map((finding) => {
                      const remediation = remediations[finding.id];
                      return (
                        <div key={finding.id} className="chamfer-panel border border-white/8 bg-black/30 p-4">
                          <div className="flex items-start justify-between gap-4">
                            <div>
                              <p className="font-bold text-[#d4af37]">{finding.header}</p>
                              <p className="mt-2 text-[10px] uppercase leading-6 tracking-[0.16em] text-[#f5f1df]">
                                {finding.detail}
                              </p>
                            </div>
                            <button
                              type="button"
                              onClick={() => handleRemediate(finding.id)}
                              disabled={loadingFixId === finding.id}
                              className="chamfer-button border border-[rgba(212,175,55,0.34)] bg-[rgba(212,175,55,0.08)] px-4 py-3 text-[10px] font-black uppercase tracking-[0.24em] text-[#d4af37] disabled:opacity-50"
                            >
                              {loadingFixId === finding.id ? 'Generating...' : 'Remediate'}
                            </button>
                          </div>
                          {loadingFixId === finding.id && !remediation && (
                            <div className="mt-4 chamfer-panel border border-[rgba(212,175,55,0.22)] bg-[rgba(212,175,55,0.05)] p-4">
                              <div className="flex items-center justify-between gap-3">
                                <p className="text-[10px] font-bold uppercase tracking-[0.28em] text-[#d4af37]">
                                  Calculating Remediation
                                </p>
                                <div className="flex gap-1">
                                  <span className="h-2 w-2 rounded-full bg-[#d4af37] animate-bounce [animation-delay:-0.3s]" />
                                  <span className="h-2 w-2 rounded-full bg-[#d4af37] animate-bounce [animation-delay:-0.15s]" />
                                  <span className="h-2 w-2 rounded-full bg-[#d4af37] animate-bounce" />
                                </div>
                              </div>
                              <div className="mt-4 space-y-3">
                                <div className="h-3 w-1/3 bg-[rgba(212,175,55,0.18)]" />
                                <div className="h-3 w-full bg-[rgba(255,255,255,0.06)]" />
                                <div className="h-3 w-5/6 bg-[rgba(255,255,255,0.06)]" />
                                <div className="h-28 w-full bg-[rgba(255,255,255,0.04)]" />
                              </div>
                            </div>
                          )}
                          {remediation && (
                            <div className="mt-4 space-y-3">
                              <div className="flex flex-wrap items-center justify-between gap-3">
                                <p className="text-[10px] font-bold uppercase tracking-[0.28em] text-[#d4af37]">
                                  {remediation.title}
                                </p>
                                <button
                                  type="button"
                                  onClick={() => handleCopy(finding.id, remediation.code)}
                                  className="chamfer-button border border-[rgba(212,175,55,0.34)] bg-[rgba(212,175,55,0.08)] px-3 py-2 text-[10px] font-black uppercase tracking-[0.22em] text-[#d4af37]"
                                >
                                  {copiedFixId === finding.id ? 'Copied' : 'Copy to Clipboard'}
                                </button>
                              </div>
                              <p className="text-[10px] uppercase leading-6 tracking-[0.16em] text-[#f5f1df]">
                                {remediation.summary}
                              </p>
                              <div className="chamfer-panel border border-[rgba(212,175,55,0.3)] bg-[rgba(212,175,55,0.08)] p-[1px]">
                                <div className="bg-[#0a0a0a] p-4">
                                  <div className="mb-3 text-[10px] font-bold uppercase tracking-[0.28em] text-[#d4af37]">
                                    {remediation.language}
                                  </div>
                                  <pre className="overflow-x-auto whitespace-pre-wrap break-words text-sm leading-7 text-[#f0d77c]">
                                    <code>{remediation.code}</code>
                                  </pre>
                                </div>
                              </div>
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>
                </div>

                <div className="chamfer-panel border border-white/10 bg-[rgba(255,255,255,0.02)] p-8">
                  <p className="text-[10px] font-bold uppercase tracking-[0.42em] text-[#d4af37]">Gemini Strategy Trace</p>
                  <div className="mt-5 space-y-4">
                    {planSteps.map((step, index) => (
                      <div key={index} className="chamfer-panel border border-white/8 bg-black/30 p-4">
                        <p className="text-[10px] font-bold uppercase tracking-[0.28em] text-[#d4af37]">{step.label ?? `STEP ${index + 1}`}</p>
                        <p className="mt-3 text-sm uppercase leading-7 tracking-[0.14em] text-[#f5f1df]">{step.message ?? 'Unavailable'}</p>
                      </div>
                    ))}
                  </div>
                </div>
              </section>
            </>
          ) : (
            <div className="chamfer-panel border border-white/10 bg-white/[0.02] p-8 text-[10px] uppercase tracking-[0.3em] text-[#8f8a78]">
              Scan not found.
            </div>
          )}
        </section>
      </main>
    </div>
  );
};

export default ScanDetail;
