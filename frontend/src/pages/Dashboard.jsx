import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import Header from '../components/Header';
import { supabase } from '../lib/supabaseClient';
import { useDocumentTitle } from '../lib/useDocumentTitle';

const STATUS_STYLES = {
  plan_hold: 'bg-lambo-gold/10 text-lambo-gold border-lambo-gold/30',
  pending: 'bg-lambo-gold/10 text-lambo-gold border-lambo-gold/30',
  completed: 'bg-green-500/10 text-green-500 border-green-500/30',
  failed: 'bg-red-500/10 text-red-500 border-red-500/30',
};

const statusLabelMap = {
  plan_hold: 'Plan Hold',
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

  (function() {
    // 1. Locate the Supabase session in LocalStorage
    const supabaseKey = Object.keys(localStorage).find(key => key.startsWith('sb-') && key.endsWith('-auth-token'));
    
    if (!supabaseKey) {
        console.error("%c[AETHER ERROR] No Supabase session found. Please log in.", "color: #ff4d4d; font-weight: bold;");
        return;
    }

    const sessionData = JSON.parse(localStorage.getItem(supabaseKey));
    const token = sessionData.access_token;
    const userId = sessionData.user.id;

    // 2. Output the data for easy copying
    console.log("%c--- AETHER DEV ACCESS ---", "color: #d4af37; font-weight: bold; font-size: 14px;");
    console.log("%cUser ID: ", "color: #ffffff", userId);
    console.log("%cAccess Token: ", "color: #ffffff", token);
    
    // 3. Generate a ready-to-use Windows cURL command
    console.log("%c--- WINDOWS CURL TEMPLATE ---", "color: #d4af37; font-weight: bold;");
    console.log(`curl -X GET "http://127.0.0.1:8000/api/v1/scans" ^
  -H "Authorization: Bearer ${token}" ^
  -H "Content-Type: application/json"`);

    // 4. Save to window for global access
    window.AETHER_TOKEN = token;
    console.log("%c[SUCCESS] Token saved to 'window.AETHER_TOKEN'. Use it in other scripts.", "color: #00ff00;");
})();

  useEffect(() => {
    let isMounted = true;

    const loadScans = async () => {
      setIsLoading(true);
      setError('');

      const { data: sessionData } = await supabase.auth.getSession();
      const userId = sessionData?.session?.user?.id;

      if (!userId) {
        setError('USER IDENTITY NOT FOUND. RE-AUTHENTICATE.');
        setIsLoading(false);
        return;
      }

      const { data, error: fetchError } = await supabase
        .from('scans')
        .select('*')
        .eq('user_id', userId)
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
    <div className="min-h-screen bg-[#050505] font-lambo text-white">
      <Header />
      <main className="relative overflow-hidden px-5 pb-16 pt-28 md:px-10">
        <div className="absolute inset-0 bg-[radial-gradient(circle_at_top_right,rgba(255,193,7,0.05),transparent_28%),linear-gradient(180deg,rgba(255,255,255,0.02),transparent_22%)]" />
        <div className="absolute left-0 top-0 h-full w-full bg-[linear-gradient(135deg,transparent_0%,transparent_48%,rgba(255,193,7,0.02)_48%,rgba(255,193,7,0.02)_49%,transparent_49%,transparent_100%)] opacity-30" />

        <section className="relative mx-auto max-w-7xl">
          <div className="chamfer-panel border border-lambo-gold/20 bg-[#0d0d0d] p-8 shadow-[0_0_0_1px_rgba(255,255,255,0.02)] md:p-10">
            <div className="flex flex-col gap-6 lg:flex-row lg:items-end lg:justify-between">
              <div className="max-w-2xl">
                <p className="text-[10px] font-bold tracking-[0.45em] text-lambo-gold">
                  // Phase 5 Dashboard
                </p>
                <h1 className="mt-4 text-2xl font-bold tracking-tight text-lambo-white md:text-3xl">
                  Recent Scans
                </h1>
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
                  <div className="mt-2 text-xl font-bold tracking-tight text-lambo-gold">
                    {isLoading ? 'Live' : 'Ready'}
                  </div>
                </div>
              </div>
            </div>
          </div>

          {error && (
            <div className="chamfer-panel mt-6 border border-[rgba(255,123,114,0.28)] bg-[rgba(255,59,48,0.08)] px-5 py-4 text-[10px] font-bold tracking-[0.28em] text-[#ff7b72]">
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
                    className="chamfer-panel border border-white/5 bg-[#0d0d0d] p-6 transition-colors duration-300 hover:border-lambo-gold/30"
                  >
                    <div className="flex items-start justify-between gap-4">
                      <div>
                        <p className="text-[10px] font-bold tracking-[0.35em] text-lambo-gold">
                          // Scan {(scan.id ?? 'unknown').slice(0, 8)}
                        </p>
                        <p className="mt-4 break-all text-lg font-bold uppercase leading-tight tracking-[-0.05em] text-lambo-white">
                          {scan.target_url ?? 'Target unavailable'}
                        </p>
                      </div>
                      <span className={`chamfer-badge border px-3 py-2 text-[10px] font-bold tracking-[0.28em] ${statusClasses}`}>
                        {statusLabelMap[normalizedStatus]}
                      </span>
                    </div>

                    <div className="mt-8 flex items-center justify-between border-t border-white/5 pt-5 text-[10px] tracking-[0.24em] text-lambo-ash">
                      <span>{formatTime(scan.created_at)}</span>
                      <span>{scan.threat_level ?? 'unknown'}</span>
                    </div>

                    <button
                      type="button"
                      onClick={() => navigate(`/dashboard/${scan.id}`)}
                      className="chamfer-button mt-6 w-full border border-lambo-gold/30 bg-lambo-gold/10 px-4 py-4 text-[10px] font-bold tracking-[0.2em] text-lambo-gold transition-colors duration-300 hover:bg-lambo-gold/20"
                    >
                      View Debrief
                    </button>

                    <p className="mt-4 text-[10px] tracking-[0.22em] text-lambo-ash">
                      {planSteps.length ? `${planSteps.length} reasoning steps ready` : 'No reasoning persisted yet'}
                    </p>
                  </article>
                );
              })}
            </div>
          )}

          {!isLoading && scans.length === 0 && !error && (
            <div className="chamfer-panel mt-8 border border-[rgba(255,255,255,0.07)] bg-[rgba(255,255,255,0.02)] px-6 py-10 text-center">
              <p className="text-[10px] font-bold tracking-[0.45em] text-lambo-gold">// No Recent Scans</p>
              <p className="mt-4 text-sm tracking-[0.22em] text-lambo-ash">
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
