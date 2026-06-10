import React, { useEffect, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import Header from '../components/Header';
import { buildWsUrl } from '../lib/api';
import { auth } from '../lib/auth';
import { useDocumentTitle } from '../lib/useDocumentTitle';
import { apiRequest } from '../lib/apiClient';

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
    return 'border-red-500/30 bg-red-500/10 text-red-500';
  }
  if (normalized === 'completed') {
    return 'border-green-500/30 bg-green-500/10 text-green-500';
  }
  return 'border-lambo-gold/30 bg-lambo-gold/10 text-lambo-gold';
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

      try {
        const response = await apiRequest(`/api/v1/scans/${scanId}`);
        const data = await response.json();
        if (!isMounted) return;
        setScan(data ?? null);
      } catch (err) {
        if (!isMounted) return;
        setError(err.message?.toUpperCase() || 'FAILED TO LOAD SCAN');
        setScan(null);
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
  const auditEngine = scan?.results?.audit_engine;
  const remediations = scan?.remediations ?? {};
  const findings = (auditEngine?.findings ?? []).length ? (auditEngine?.findings ?? []) : (headerAudit?.findings ?? []);
  const scanStatus = typeof scan?.status === 'string' ? scan.status.toUpperCase() : 'PENDING';
  const reportError = finalReport.error_message;
  const autoRemediation = finalReport.auto_remediation ?? {};
  const lastPullRequest = autoRemediation.last_pull_request;
  const [loadingPrId, setLoadingPrId] = useState('');
  const [gitPushStatus, setGitPushStatus] = useState('');

  const handleRemediate = async (vulnId) => {
    setLoadingFixId(vulnId);
    setRemediationError('');

    const userId = auth.getUserId();

    const socket = new WebSocket(buildWsUrl(`/ws/remediation/${scan.id}?user_id=${userId}`));

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
          final_report: payload.final_report ?? current?.final_report,
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

  const handleCreatePullRequest = async (vulnId) => {
    if (!autoRemediation?.target_id) {
      setRemediationError('NO GIT REMEDIATION TARGET IS CONFIGURED FOR THIS ASSET.');
      return;
    }

    setLoadingPrId(vulnId);
    setGitPushStatus('');
    setRemediationError('');

    const userId = auth.getUserId();

    const socket = new WebSocket(buildWsUrl(`/ws/remediation/${scan.id}?user_id=${userId}`));

    socket.onopen = () => {
      socket.send(JSON.stringify({ action: 'create_pull_request', vuln_id: vulnId, target_id: autoRemediation.target_id }));
    };

    socket.onmessage = (event) => {
      const payload = JSON.parse(event.data);
      if (payload.type === 'error') {
        setRemediationError(payload.msg ?? 'PULL REQUEST CREATION FAILED.');
        setLoadingPrId('');
        socket.close();
        return;
      }
      if (payload.type === 'git_push_status') {
        setGitPushStatus(payload.msg ?? '');
        if (payload.status === 'success') {
          setScan((current) => ({
            ...current,
            final_report: payload.final_report ?? current?.final_report,
          }));
          setLoadingPrId('');
          socket.close();
          return;
        }
        if (payload.status === 'error') {
          setRemediationError(payload.msg ?? 'PULL REQUEST CREATION FAILED.');
          setLoadingPrId('');
          socket.close();
        }
      }
    };

    socket.onerror = () => {
      setRemediationError('GIT REMEDIATION SOCKET FAILED BEFORE THE PULL REQUEST COULD BE OPENED.');
      setLoadingPrId('');
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
    <div className="min-h-screen bg-[#050505] font-lambo text-lambo-white">
      <Header />
      <main className="relative overflow-hidden px-5 pb-16 pt-28 md:px-10">
        <div className="absolute inset-0 bg-[radial-gradient(circle_at_top_right,rgba(255,192,0,0.05),transparent_28%),linear-gradient(180deg,rgba(255,255,255,0.02),transparent_22%)]" />

        <section className="relative mx-auto max-w-7xl space-y-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-[10px] font-bold tracking-[0.4em] text-lambo-gold">// Mission Debrief</p>
              <h1 className="mt-3 break-all text-3xl font-black tracking-[-0.03em] text-lambo-white md:text-5xl">
                {scan?.target_url ?? 'Loading Scan'}
              </h1>
            </div>
            <div className="flex items-center gap-6">
              <Link
                to="/dashboard"
                className="chamfer-button border border-white/10 bg-white/5 px-4 py-3 text-[10px] font-bold tracking-[0.2em] text-lambo-ash transition-colors hover:border-lambo-gold/40 hover:text-lambo-gold"
              >
                Back to Dashboard
              </Link>
            </div>
          </div>

          {error && (
            <div className="chamfer-panel border border-red-500/30 bg-red-500/10 px-5 py-4 text-[10px] font-bold tracking-[0.28em] text-red-500">
              {error}
            </div>
          )}

          {isLoading ? (
            <div className="chamfer-panel border border-white/10 bg-white/[0.02] p-8 text-[10px] tracking-[0.3em] text-lambo-ash">
              Loading debrief...
            </div>
          ) : scan ? (
            <>
              <section className="grid gap-6 xl:grid-cols-[1.2fr_0.8fr]">
                <div className="chamfer-panel border border-lambo-gold/20 bg-[#0d0d0d] p-8">
                  <p className="text-[10px] font-bold tracking-[0.42em] text-lambo-gold">// Risk Impact</p>
                  <p className="mt-5 text-lg font-bold tracking-tight text-lambo-white md:text-xl">
                    {finalReport.risk_impact ?? 'Final synthesis pending.'}
                  </p>
                  <div className="mt-8 flex flex-wrap items-center gap-3">
                    <div className="inline-flex items-center border border-lambo-gold/30 bg-lambo-gold/10 px-4 py-3 text-[10px] font-bold tracking-[0.2em] text-lambo-gold">
                      Threat Level: {finalReport.threat_level ?? scan.threat_level ?? 'unknown'}
                    </div>
                    <div className={`inline-flex items-center border px-4 py-3 text-[10px] font-bold tracking-[0.2em] ${statusTone(scan?.status)}`}>
                      Status: {scanStatus.charAt(0) + scanStatus.slice(1).toLowerCase()}
                    </div>
                  </div>
                  {reportError && (
                    <div className="mt-5 chamfer-panel border border-red-500/30 bg-red-500/10 p-4 text-[10px] font-bold tracking-[0.22em] text-red-500">
                      {reportError}
                    </div>
                  )}
                </div>

                <div className="chamfer-panel border border-white/10 bg-white/5 p-8">
                  <p className="text-[10px] font-bold tracking-[0.42em] text-lambo-gold">// Remediation Steps</p>
                  <div className="mt-5 space-y-4">
                    {(finalReport.remediation_steps ?? []).map((step, index) => (
                      <div key={index} className="chamfer-panel border border-white/5 bg-black/40 p-4">
                        <p className="text-[10px] font-bold tracking-[0.28em] text-lambo-gold">Action {index + 1}</p>
                        <p className="mt-3 text-sm leading-7 tracking-[0.14em] text-lambo-white">{step}</p>
                      </div>
                    ))}
                  </div>
                </div>
              </section>

              <section className="grid gap-6 xl:grid-cols-2">
                <div className="chamfer-panel border border-white/10 bg-white/5 p-8">
                  <div className="flex items-center justify-between mb-5">
                    <p className="text-[10px] font-bold tracking-[0.42em] text-lambo-gold">// Vulnerabilities & Remediations</p>
                  </div>
                  {remediationError && (
                    <div className="mt-4 chamfer-panel border border-red-500/30 bg-red-500/10 px-4 py-3 text-[10px] font-bold tracking-[0.22em] text-red-500">
                      {remediationError}
                    </div>
                  )}
                  {gitPushStatus && (
                    <div className="mt-4 chamfer-panel border border-lambo-cyan/30 bg-lambo-cyan/10 px-4 py-3 text-[10px] font-bold tracking-[0.22em] text-lambo-cyan">
                      {gitPushStatus}
                    </div>
                  )}
                  <div className="mt-5 space-y-4 text-[10px] tracking-[0.22em] text-lambo-ash">
                    <div className="chamfer-panel border border-white/5 bg-black/40 p-4">
                      <p className="font-bold text-lambo-gold">Port Scan</p>
                      <p className="mt-3 text-lambo-white">
                        Open Ports: {(portScan?.open_ports ?? []).length ? portScan.open_ports.join(', ') : 'None'}
                      </p>
                    </div>
                    <div className="chamfer-panel border border-white/5 bg-black/40 p-4">
                      <p className="font-bold text-lambo-gold">Header Audit</p>
                      <p className="mt-3 text-lambo-white">
                        Findings: {(headerAudit?.findings ?? []).length}
                      </p>
                    </div>
                    {findings.map((finding) => {
                      const remediation = remediations[finding.id];
                      return (
                        <div key={finding.id} className="chamfer-panel border border-white/5 bg-black/40 p-4">
                          <div className="flex items-start justify-between gap-4">
                            <div>
                              <p className="font-bold text-lambo-gold">{finding.title ?? finding.header ?? 'Finding'}</p>
                              <p className="mt-2 text-[10px] uppercase leading-6 tracking-[0.16em] text-lambo-white">
                                {finding.detail ?? finding.detected_threat ?? 'No detail available.'}
                              </p>
                            </div>
                            <div className="flex flex-col items-end gap-3">
                              <button
                                type="button"
                                onClick={() => handleRemediate(finding.id)}
                                disabled={loadingFixId === finding.id}
                                className="chamfer-button border border-lambo-gold/30 bg-lambo-gold/10 px-4 py-3 text-[10px] font-bold tracking-[0.2em] text-lambo-gold disabled:opacity-50 hover:bg-lambo-gold/20 transition-colors"
                              >
                                {loadingFixId === finding.id ? 'Generating...' : 'Gemini Remediate'}
                              </button>
                              {remediation && autoRemediation?.pr_ready && (
                                <button
                                  type="button"
                                  onClick={() => handleCreatePullRequest(finding.id)}
                                  disabled={loadingPrId === finding.id}
                                  className="chamfer-button border border-lambo-cyan/30 bg-lambo-cyan/10 px-4 py-3 text-[10px] font-bold tracking-[0.2em] text-lambo-cyan disabled:opacity-50 hover:bg-lambo-cyan/20 transition-colors"
                                >
                                  {loadingPrId === finding.id ? 'Opening PR...' : 'Create Pull Request'}
                                </button>
                              )}
                            </div>
                          </div>
                          {loadingFixId === finding.id && !remediation && (
                            <div className="mt-4 chamfer-panel border border-lambo-gold/20 bg-lambo-gold/5 p-4">
                              <div className="flex items-center justify-between gap-3">
                                <p className="text-[10px] font-bold uppercase tracking-[0.28em] text-lambo-gold">
                                  Calculating Remediation
                                </p>
                                <div className="flex gap-1">
                                  <span className="h-2 w-2 rounded-full bg-lambo-gold animate-bounce [animation-delay:-0.3s]" />
                                  <span className="h-2 w-2 rounded-full bg-lambo-gold animate-bounce [animation-delay:-0.15s]" />
                                  <span className="h-2 w-2 rounded-full bg-lambo-gold animate-bounce" />
                                </div>
                              </div>
                              <div className="mt-4 space-y-3">
                                <div className="h-3 w-1/3 bg-lambo-gold/20" />
                                <div className="h-3 w-full bg-white/10" />
                                <div className="h-3 w-5/6 bg-white/10" />
                                <div className="h-28 w-full bg-white/5" />
                              </div>
                            </div>
                          )}
                          {remediation && (
                            <div className="mt-4 space-y-3">
                              <div className="flex flex-wrap items-center justify-between gap-3">
                                <p className="text-[10px] font-bold uppercase tracking-[0.28em] text-lambo-cyan">
                                  {remediation.title}
                                </p>
                                <button
                                  type="button"
                                  onClick={() => handleCopy(finding.id, remediation.code)}
                                  className="chamfer-button border border-lambo-gold/30 bg-lambo-gold/10 px-3 py-2 text-[10px] font-bold tracking-[0.15em] text-lambo-gold hover:bg-lambo-gold/20 transition-colors"
                                >
                                  {copiedFixId === finding.id ? 'Copied' : 'Copy to Clipboard'}
                                </button>
                              </div>
                              <p className="text-[10px] uppercase leading-6 tracking-[0.16em] text-lambo-white">
                                {remediation.summary}
                              </p>
                              {lastPullRequest?.pull_request_url && (
                                <a
                                  href={lastPullRequest.pull_request_url}
                                  target="_blank"
                                  rel="noreferrer"
                                  className="inline-flex items-center text-[10px] font-bold uppercase tracking-[0.22em] text-lambo-cyan hover:text-lambo-gold transition-colors"
                                >
                                  View Pull Request
                                </a>
                              )}
                              <div className="chamfer-panel border border-lambo-gold/30 bg-lambo-gold/10 p-[1px]">
                                <div className="bg-lambo-charcoal p-4">
                                  <div className="mb-3 text-[10px] font-bold uppercase tracking-[0.28em] text-lambo-gold">
                                    {remediation.language}
                                  </div>
                                  <pre className="overflow-x-auto whitespace-pre-wrap break-words font-mono text-sm leading-7 text-lambo-gold">
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

                <div className="chamfer-panel border border-white/10 bg-white/5 p-8">
                  <p className="text-[10px] font-bold tracking-[0.42em] text-lambo-gold">// Gemini Strategy Trace</p>
                  <div className="mt-5 space-y-4">
                    {planSteps.map((step, index) => (
                      <div key={index} className="chamfer-panel border border-white/5 bg-black/40 p-4">
                        <p className="text-[10px] font-bold tracking-[0.28em] text-lambo-gold">{step.label ?? `Step ${index + 1}`}</p>
                        <p className="mt-3 text-sm leading-7 tracking-[0.14em] text-lambo-white">{step.message ?? 'Unavailable'}</p>
                      </div>
                    ))}
                  </div>
                </div>
              </section>
            </>
          ) : (
            <div className="chamfer-panel border border-white/10 bg-white/[0.02] p-8 text-[10px] uppercase tracking-[0.3em] text-lambo-ash">
              Scan not found.
            </div>
          )}
        </section>
      </main>
    </div>
  );
};

export default ScanDetail;
