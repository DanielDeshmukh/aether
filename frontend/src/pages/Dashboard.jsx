import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import Header from '../components/Header';
import { supabase } from '../lib/supabaseClient';
import { useDocumentTitle } from '../lib/useDocumentTitle';

const STATUS_STYLES = {
  plan_hold: 'bg-[rgba(212,175,55,0.12)] text-[#d4af37] border-[rgba(212,175,55,0.34)]',
  pending: 'bg-[rgba(212,175,55,0.12)] text-[#d4af37] border-[rgba(212,175,55,0.34)]',
  completed: 'bg-[rgba(0,255,65,0.12)] text-[#00ff41] border-[rgba(0,255,65,0.34)]',
  failed: 'bg-[rgba(255,0,0,0.12)] text-[#ff0000] border-[rgba(255,0,0,0.34)]',
};

const statusLabelMap = {
  plan_hold: 'PLAN_HOLD',
  pending: 'PENDING',
  completed: 'COMPLETED',
  failed: 'FAILED',
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

  if (Array.isArray(initialPlan)) {
    return initialPlan;
  }

  if (initialPlan && Array.isArray(initialPlan.steps)) {
    return initialPlan.steps;
  }

  return [];
};

const normalizeStatus = (status) => {
  const normalized = typeof status === 'string' ? status.trim().toLowerCase() : '';
  if (normalized === 'plan_hold') {
    return 'plan_hold';
  }
  if (normalized === 'completed') {
    return 'completed';
  }
  if (normalized === 'failed') {
    return 'failed';
  }
  return 'pending';
};

const formatTime = (value) => {
  if (!value) {
    return 'Awaiting timestamp';
  }

  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    return 'Timestamp unavailable';
  }

  return parsed.toLocaleString(undefined, {
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
  });
};

const Dashboard = () => {
  const [scans, setScans] = useState([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState('');
  const navigate = useNavigate();
  useDocumentTitle('Dashboard');

  useEffect(() => {
    let isMounted = true;

    const loadScans = async () => {
      setIsLoading(true);
      setError('');

      const { data, error: fetchError } = await supabase
        .from('scans')
        .select('*')
        .order('created_at', { ascending: false })
        .limit(12);

      if (!isMounted) {
        return;
      }

      if (fetchError) {
        setError(fetchError.message.toUpperCase());
        setScans([]);
      } else {
        setScans(data ?? []);
      }

      setIsLoading(false);
    };

    loadScans();

    const channel = supabase
      .channel('dashboard-scans')
      .on(
        'postgres_changes',
        { event: '*', schema: 'public', table: 'scans' },
        (payload) => {
          if (!isMounted) {
            return;
          }

          if (payload.eventType === 'DELETE') {
            setScans((current) => current.filter((scan) => scan.id !== payload.old.id));
            return;
          }

          const nextRecord = payload.new;
          setScans((current) => {
            const filtered = current.filter((scan) => scan.id !== nextRecord.id);
            return [nextRecord, ...filtered].sort(
              (left, right) => new Date(right.created_at ?? 0).getTime() - new Date(left.created_at ?? 0).getTime()
            ).slice(0, 12);
          });
        }
      )
      .subscribe();

    return () => {
      isMounted = false;
      supabase.removeChannel(channel);
    };
  }, []);

  return (
    <div className="min-h-screen bg-[#050505] font-mono text-white">
      <Header />
      <main className="relative overflow-hidden px-5 pb-16 pt-28 md:px-10">
        <div className="absolute inset-0 bg-[radial-gradient(circle_at_top_right,rgba(212,175,55,0.12),transparent_28%),linear-gradient(180deg,rgba(255,255,255,0.02),transparent_22%)]" />
        <div className="absolute left-0 top-0 h-full w-full bg-[linear-gradient(135deg,transparent_0%,transparent_48%,rgba(212,175,55,0.05)_48%,rgba(212,175,55,0.05)_49%,transparent_49%,transparent_100%)] opacity-30" />

        <section className="relative mx-auto max-w-7xl">
          <div className="chamfer-panel border border-[rgba(212,175,55,0.22)] bg-[linear-gradient(180deg,rgba(17,17,17,0.98),rgba(9,9,9,0.98))] p-8 shadow-[0_0_0_1px_rgba(255,255,255,0.02)] md:p-10">
            <div className="flex flex-col gap-6 lg:flex-row lg:items-end lg:justify-between">
              <div className="max-w-2xl">
                <p className="text-[10px] font-bold uppercase tracking-[0.45em] text-[#d4af37]">
                  Phase 5 Dashboard
                </p>
                <h1 className="mt-4 text-4xl font-black uppercase tracking-[-0.08em] text-[#f5f1df] md:text-6xl">
                  Recent Scans
                </h1>
                <p className="mt-4 max-w-xl text-sm uppercase tracking-[0.2em] text-[#8f8a78]">
                  Review persisted scan targets, inspect AI reasoning, and keep the operator loop anchored to the latest engine state.
                </p>
              </div>

              <div className="grid gap-3 text-right text-[10px] uppercase tracking-[0.3em] text-[#8f8a78] sm:grid-cols-2">
                <div className="chamfer-badge border border-[rgba(255,255,255,0.08)] bg-[rgba(255,255,255,0.02)] px-4 py-3">
                  <div>Records</div>
                  <div className="mt-2 text-2xl font-black tracking-[-0.06em] text-[#f5f1df]">{scans.length}</div>
                </div>
                <div className="chamfer-badge border border-[rgba(212,175,55,0.22)] bg-[rgba(212,175,55,0.05)] px-4 py-3">
                  <div>Sync</div>
                  <div className="mt-2 text-2xl font-black tracking-[-0.06em] text-[#d4af37]">
                    {isLoading ? 'LIVE' : 'READY'}
                  </div>
                </div>
              </div>
            </div>
          </div>

          {error && (
            <div className="chamfer-panel mt-6 border border-[rgba(255,123,114,0.28)] bg-[rgba(255,59,48,0.08)] px-5 py-4 text-[10px] font-bold uppercase tracking-[0.28em] text-[#ff7b72]">
              {error}
            </div>
          )}

          {isLoading ? (
            <div className="mt-8 grid gap-5 md:grid-cols-2 xl:grid-cols-3">
              {Array.from({ length: 6 }).map((_, index) => (
                <div
                  key={index}
                  className="chamfer-panel border border-[rgba(255,255,255,0.06)] bg-[linear-gradient(180deg,rgba(14,14,14,1),rgba(8,8,8,1))] p-6"
                >
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
              {scans.map((scan) => {
                const normalizedStatus = normalizeStatus(scan.status);
                const statusClasses = STATUS_STYLES[normalizedStatus] ?? STATUS_STYLES.pending;
                const planSteps = normalizePlan(scan.initial_plan);

                return (
                  <article
                    key={scan.id}
                    className="chamfer-panel border border-[rgba(255,255,255,0.07)] bg-[linear-gradient(180deg,rgba(15,15,15,1),rgba(9,9,9,1))] p-6 transition-colors duration-300 hover:border-[rgba(212,175,55,0.32)]"
                  >
                    <div className="flex items-start justify-between gap-4">
                      <div>
                        <p className="text-[10px] font-bold uppercase tracking-[0.35em] text-[#d4af37]">
                          Scan {(scan.id ?? 'unknown').slice(0, 8)}
                        </p>
                        <p className="mt-4 break-all text-lg font-bold uppercase leading-tight tracking-[-0.05em] text-[#f5f1df]">
                          {scan.target_url ?? 'Target unavailable'}
                        </p>
                      </div>
                      <span className={`chamfer-badge border px-3 py-2 text-[10px] font-bold uppercase tracking-[0.28em] ${statusClasses}`}>
                        {statusLabelMap[normalizedStatus]}
                      </span>
                    </div>

                    <div className="mt-8 flex items-center justify-between border-t border-[rgba(255,255,255,0.06)] pt-5 text-[10px] uppercase tracking-[0.24em] text-[#8f8a78]">
                      <span>{formatTime(scan.created_at)}</span>
                      <span>{scan.threat_level ?? 'unknown'}</span>
                    </div>

                    <button
                      type="button"
                      onClick={() => navigate(`/dashboard/${scan.id}`)}
                      className="chamfer-button mt-6 w-full border border-[rgba(212,175,55,0.34)] bg-[rgba(212,175,55,0.08)] px-4 py-4 text-[10px] font-bold uppercase tracking-[0.32em] text-[#d4af37] transition-colors duration-300 hover:bg-[rgba(212,175,55,0.16)]"
                    >
                      View Debrief
                    </button>

                    <p className="mt-4 text-[10px] uppercase tracking-[0.22em] text-[#8f8a78]">
                      {planSteps.length ? `${planSteps.length} reasoning steps ready` : 'No reasoning persisted yet'}
                    </p>
                  </article>
                );
              })}
            </div>
          )}

          {!isLoading && scans.length === 0 && !error && (
            <div className="chamfer-panel mt-8 border border-[rgba(255,255,255,0.07)] bg-[rgba(255,255,255,0.02)] px-6 py-10 text-center">
              <p className="text-[10px] font-bold uppercase tracking-[0.45em] text-[#d4af37]">No Recent Scans</p>
              <p className="mt-4 text-sm uppercase tracking-[0.22em] text-[#8f8a78]">
                Launch a scan to populate the dashboard.
              </p>
            </div>
          )}
        </section>
      </main>

    </div>
  );
};

export default Dashboard;
