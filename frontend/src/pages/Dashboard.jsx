import React, { useEffect, useState, useRef, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import Header from '../components/Header';
import { auth } from '../lib/auth';
import { useDocumentTitle } from '../lib/useDocumentTitle';
import { apiRequest } from '../lib/apiClient';
import { buildWsUrl } from '../lib/api';

const PAGE_SIZE = 9;

const STATUS_STYLES = {
  plan_hold: 'bg-lambo-gold/10 text-lambo-gold border-lambo-gold/30',
  running: 'bg-blue-500/10 text-blue-400 border-blue-500/30',
  pending: 'bg-lambo-gold/10 text-lambo-gold border-lambo-gold/30',
  completed: 'bg-green-500/10 text-green-500 border-green-500/30',
  failed: 'bg-red-500/10 text-red-500 border-red-500/30',
};

const statusLabelMap = {
  plan_hold: 'Plan Hold',
  running: 'Running',
  pending: 'Pending',
  completed: 'Completed',
  failed: 'Failed',
};

const normalizePlan = (initialPlan) => {
  if (typeof initialPlan === 'string') {
    try {
      const parsed = JSON.parse(initialPlan);
      return normalizePlan(parsed);
    } catch {
      return [];
    }
  }
  if (Array.isArray(initialPlan)) return initialPlan;
  if (initialPlan && Array.isArray(initialPlan.steps)) return initialPlan.steps;
  return [];
};

const normalizeStatus = (status) => {
  const normalized = typeof status === 'string' ? status.trim().toLowerCase() : '';
  if (normalized === 'plan_hold') return 'plan_hold';
  if (normalized === 'running' || normalized === 'active' || normalized === 'in_progress') return 'running';
  if (normalized === 'completed') return 'completed';
  if (normalized === 'failed') return 'failed';
  return 'pending';
};

const formatTime = (value) => {
  if (!value) return 'Awaiting timestamp';
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return 'Timestamp unavailable';
  return parsed.toLocaleString(undefined, { month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit' });
};

const Dashboard = () => {
  const [scans, setScans] = useState([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState('');
  const [page, setPage] = useState(1);
  const [sortBy, setSortBy] = useState('date');
  const [filterStatus, setFilterStatus] = useState('all');
  const [deleteConfirmId, setDeleteConfirmId] = useState('');
  const navigate = useNavigate();
  const wsRef = useRef(null);
  useDocumentTitle('Dashboard');

  useEffect(() => {
    let isMounted = true;
    const loadScans = async () => {
      setIsLoading(true);
      setError('');
      try {
        const response = await apiRequest('/api/v1/scans');
        const data = await response.json();
        if (!isMounted) return;
        setScans(data ?? []);
      } catch (err) {
        if (!isMounted) return;
        setError(err.message === 'AUTHENTICATION_REQUIRED' ? 'Session expired. Please log in.' : err.message);
        setScans([]);
      }
      setIsLoading(false);
    };
    loadScans();

    const connectDashboardWs = () => {
      const token = auth.getAccessToken();
      if (!token) return;
      const ws = new WebSocket(buildWsUrl(`/ws/dashboard?token=${token}`));
      wsRef.current = ws;
      ws.onmessage = (event) => {
        if (!isMounted) return;
        try {
          const payload = JSON.parse(event.data);
          if (payload.type === 'scan_update' && payload.scan) {
            const nextRecord = payload.scan;
            setScans((current) => {
              const filtered = current.filter((scan) => scan.id !== nextRecord.id);
              return [nextRecord, ...filtered];
            });
          }
        } catch {}
      };
      ws.onclose = () => { if (isMounted) setTimeout(connectDashboardWs, 3000); };
      ws.onerror = () => { ws.close(); };
    };
    connectDashboardWs();
    return () => {
      isMounted = false;
      if (wsRef.current) { wsRef.current.onclose = null; wsRef.current.close(); }
    };
  }, []);

  const handleDelete = async (scanId) => {
    try {
      await apiRequest(`/api/v1/scans/${scanId}`, { method: 'DELETE' });
      setScans((current) => current.filter((s) => s.id !== scanId));
      setDeleteConfirmId('');
    } catch {
      setDeleteConfirmId('');
    }
  };

  const filteredScans = useMemo(() => {
    let result = [...scans];
    if (filterStatus !== 'all') {
      result = result.filter((s) => normalizeStatus(s.status) === filterStatus);
    }
    if (sortBy === 'date') {
      result.sort((a, b) => new Date(b.created_at ?? 0).getTime() - new Date(a.created_at ?? 0).getTime());
    } else if (sortBy === 'threat') {
      const order = { critical: 0, high: 1, medium: 2, low: 3, unknown: 4 };
      result.sort((a, b) => (order[a.threat_level?.toLowerCase()] ?? 4) - (order[b.threat_level?.toLowerCase()] ?? 4));
    } else if (sortBy === 'status') {
      result.sort((a, b) => normalizeStatus(a.status).localeCompare(normalizeStatus(b.status)));
    }
    return result;
  }, [scans, sortBy, filterStatus]);

  const totalPages = Math.max(1, Math.ceil(filteredScans.length / PAGE_SIZE));
  const paginatedScans = filteredScans.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);

  useEffect(() => { setPage(1); }, [sortBy, filterStatus]);

  return (
    <div className="min-h-screen bg-[#050505] font-lambo text-white">
      <Header />
      <main className="relative overflow-hidden px-5 pb-16 pt-28 md:px-10">
        <div className="absolute inset-0 bg-[radial-gradient(circle_at_top_right,rgba(255,193,7,0.05),transparent_28%),linear-gradient(180deg,rgba(255,255,255,0.02),transparent_22%)]" />
        <div className="absolute left-0 top-0 h-full w-full bg-[linear-gradient(135deg,transparent_0%,transparent_48%,rgba(255,193,7,0.02)_48%,rgba(255,193,7,0.02)_49%,transparent_49%,transparent_100%)] opacity-30" />

        <section className="relative mx-auto max-w-7xl">
          <div className="chamfer-panel border border-lambo-gold/20 bg-[#0d0d0d] p-8 shadow-[0_0_0_1px_rgba(255,255,255,0.02)] md:p-10">
            <div className="flex flex-col gap-6 lg:flex-row lg:items-end lg:justify-between">
              <div className="max-w-2xl">
                <p className="text-[10px] font-bold tracking-[0.45em] text-lambo-gold">// Phase 5 Dashboard</p>
                <h1 className="mt-4 text-2xl font-bold tracking-tight text-lambo-white md:text-3xl">Recent Scans</h1>
                <p className="mt-4 max-w-xl text-sm tracking-[0.2em] text-lambo-ash">
                  Review persisted scan targets, inspect AI reasoning, and keep the operator loop anchored to the latest engine state.
                </p>
              </div>
              <div className="grid gap-3 text-right text-[10px] tracking-[0.3em] text-lambo-ash sm:grid-cols-2">
                <div className="chamfer-badge border border-white/10 bg-white/5 px-4 py-3">
                  <div className="text-[9px] uppercase tracking-widest text-lambo-ash/60">Records</div>
                  <div className="mt-2 text-xl font-bold tracking-tight text-lambo-white">{scans.length}</div>
                </div>
                <div className="chamfer-badge border border-lambo-gold/30 bg-lambo-gold/5 px-4 py-3">
                  <div className="text-[9px] uppercase tracking-widest text-lambo-gold/60">Sync</div>
                  <div className="mt-2 text-xl font-bold tracking-tight text-lambo-gold">{isLoading ? 'Live' : 'Ready'}</div>
                </div>
              </div>
            </div>
          </div>

          {error && (
            <div className="chamfer-panel mt-6 border border-[rgba(255,123,114,0.28)] bg-[rgba(255,59,48,0.08)] px-5 py-4 text-[10px] font-bold tracking-[0.28em] text-[#ff7b72]">{error}</div>
          )}

          <div className="mt-6 flex flex-wrap items-center gap-4 text-[10px] tracking-[0.2em]">
            <select value={filterStatus} onChange={(e) => setFilterStatus(e.target.value)}
              className="chamfer-badge border border-white/10 bg-[#0d0d0d] px-4 py-3 text-lambo-ash focus:border-lambo-gold/40 focus:outline-none">
              <option value="all">All Status</option>
              <option value="pending">Pending</option>
              <option value="running">Running</option>
              <option value="plan_hold">Plan Hold</option>
              <option value="completed">Completed</option>
              <option value="failed">Failed</option>
            </select>
            <select value={sortBy} onChange={(e) => setSortBy(e.target.value)}
              className="chamfer-badge border border-white/10 bg-[#0d0d0d] px-4 py-3 text-lambo-ash focus:border-lambo-gold/40 focus:outline-none">
              <option value="date">Sort by Date</option>
              <option value="threat">Sort by Threat Level</option>
              <option value="status">Sort by Status</option>
            </select>
          </div>

          {isLoading ? (
            <div className="mt-8 grid gap-5 md:grid-cols-2 xl:grid-cols-3">
              {Array.from({ length: 6 }).map((_, index) => (
                <div key={index} className="chamfer-panel border border-[rgba(255,255,255,0.06)] bg-[linear-gradient(180deg,rgba(14,14,14,1),rgba(8,8,8,1))] p-6">
                  <div className="h-3 w-24 bg-[rgba(212,175,55,0.18)]" />
                  <div className="mt-6 h-12 bg-[rgba(255,255,255,0.05)]" />
                  <div className="mt-8 flex justify-between gap-3">
                    <div className="h-8 w-24 bg-[rgba(255,255,255,0.05)]" />
                    <div className="h-8 w-28 bg-[rgba(212,175,55,0.12)]" />
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="mt-8 grid gap-5 md:grid-cols-2 xl:grid-cols-3">
              {paginatedScans.map((scan) => {
                const normalizedStatus = normalizeStatus(scan.status);
                const statusClasses = STATUS_STYLES[normalizedStatus] ?? STATUS_STYLES.pending;
                const planSteps = normalizePlan(scan.initial_plan);
                const vulnCount = scan.results?.audit_engine?.findings?.length ?? scan.results?.header_audit?.findings?.length ?? 0;

                return (
                  <article key={scan.id} className="chamfer-panel border border-white/5 bg-[#0d0d0d] p-6 transition-colors duration-300 hover:border-lambo-gold/30">
                    <div className="flex items-start justify-between gap-4">
                      <div>
                        <p className="text-[10px] font-bold tracking-[0.35em] text-lambo-gold">// Scan {(scan.id ?? 'unknown').slice(0, 8)}</p>
                        <p className="mt-4 break-all text-lg font-bold uppercase leading-tight tracking-[-0.05em] text-lambo-white">{scan.target_url ?? 'Target unavailable'}</p>
                      </div>
                      <div className="flex flex-col items-end gap-2">
                        <span className={`chamfer-badge border px-3 py-2 text-[10px] font-bold tracking-[0.28em] ${statusClasses}`}>
                          {statusLabelMap[normalizedStatus]}
                        </span>
                        {scan.is_verified ? (
                          <span className="chamfer-badge border border-green-500/30 bg-green-500/10 px-2 py-1 text-[9px] font-bold tracking-[0.2em] text-green-400">
                            Verified
                          </span>
                        ) : (
                          <span className="chamfer-badge border border-yellow-500/30 bg-yellow-500/10 px-2 py-1 text-[9px] font-bold tracking-[0.2em] text-yellow-400">
                            Unverified
                          </span>
                        )}
                      </div>
                    </div>

                    <div className="mt-4 flex items-center gap-4 text-[10px] tracking-[0.22em] text-lambo-ash">
                      {vulnCount > 0 && (
                        <span className="border border-red-500/30 bg-red-500/10 px-2 py-1 text-red-400">{vulnCount} finding{vulnCount !== 1 ? 's' : ''}</span>
                      )}
                      <span>{scan.threat_level ?? 'unknown'}</span>
                    </div>

                    <div className="mt-4 flex items-center justify-between border-t border-white/5 pt-5 text-[10px] tracking-[0.24em] text-lambo-ash">
                      <span>{formatTime(scan.created_at)}</span>
                      <span>{planSteps.length ? `${planSteps.length} steps` : 'No plan'}</span>
                    </div>

                    <div className="mt-4 flex gap-3">
                      <button type="button" onClick={() => navigate(`/dashboard/${scan.id}`)}
                        className="chamfer-button flex-1 border border-lambo-gold/30 bg-lambo-gold/10 px-4 py-3 text-[10px] font-bold tracking-[0.2em] text-lambo-gold transition-colors duration-300 hover:bg-lambo-gold/20">
                        View Debrief
                      </button>
                      {deleteConfirmId === scan.id ? (
                        <div className="flex gap-2">
                          <button type="button" onClick={() => handleDelete(scan.id)}
                            className="chamfer-button border border-red-500/50 bg-red-500/20 px-3 py-3 text-[10px] font-bold tracking-[0.15em] text-red-400 hover:bg-red-500/30 transition-colors">Yes</button>
                          <button type="button" onClick={() => setDeleteConfirmId('')}
                            className="chamfer-button border border-white/10 bg-white/5 px-3 py-3 text-[10px] font-bold tracking-[0.15em] text-lambo-ash hover:bg-white/10 transition-colors">No</button>
                        </div>
                      ) : (
                        <button type="button" onClick={() => setDeleteConfirmId(scan.id)}
                          className="chamfer-button border border-white/10 bg-white/5 px-3 py-3 text-[10px] font-bold tracking-[0.15em] text-lambo-ash hover:border-red-500/30 hover:text-red-400 transition-colors">
                          Delete
                        </button>
                      )}
                    </div>
                  </article>
                );
              })}
            </div>
          )}

          {!isLoading && filteredScans.length > PAGE_SIZE && (
            <div className="mt-8 flex items-center justify-center gap-4">
              <button type="button" onClick={() => setPage((p) => Math.max(1, p - 1))} disabled={page === 1}
                className="chamfer-button border border-white/10 bg-white/5 px-4 py-3 text-[10px] font-bold tracking-[0.2em] text-lambo-ash disabled:opacity-30 hover:border-lambo-gold/40 hover:text-lambo-gold transition-colors">
                Prev
              </button>
              <span className="text-[10px] tracking-[0.3em] text-lambo-ash">Page {page} of {totalPages}</span>
              <button type="button" onClick={() => setPage((p) => Math.min(totalPages, p + 1))} disabled={page >= totalPages}
                className="chamfer-button border border-white/10 bg-white/5 px-4 py-3 text-[10px] font-bold tracking-[0.2em] text-lambo-ash disabled:opacity-30 hover:border-lambo-gold/40 hover:text-lambo-gold transition-colors">
                Next
              </button>
            </div>
          )}

          {!isLoading && scans.length === 0 && !error && (
            <div className="chamfer-panel mt-8 border border-[rgba(255,255,255,0.07)] bg-[rgba(255,255,255,0.02)] px-6 py-10 text-center">
              <p className="text-[10px] font-bold tracking-[0.45em] text-lambo-gold">// No Recent Scans</p>
              <p className="mt-4 text-sm tracking-[0.22em] text-lambo-ash">Launch a scan to populate the dashboard.</p>
            </div>
          )}
        </section>
      </main>
    </div>
  );
};

export default Dashboard;
