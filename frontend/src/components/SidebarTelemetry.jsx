import React, { useEffect, useState } from 'react';
import { supabase } from '../lib/supabaseClient';
import { buildApiUrl } from '../lib/api';

const statusPalette = {
    completed: 'text-[#00ff41]',
    failed: 'text-[#ff5f56]',
    plan_hold: 'text-lambo-gold',
    pending: 'text-[#7dd3fc]',
};

const normalizeStatus = (status) => {
    const normalized = typeof status === 'string' ? status.trim().toLowerCase() : '';
    if (normalized === 'completed') {
        return 'completed';
    }
    if (normalized === 'failed') {
        return 'failed';
    }
    if (normalized === 'plan_hold') {
        return 'plan_hold';
    }
    return 'pending';
};

const formatTime = (value) => {
    if (!value) {
        return 'SYNC_PENDING';
    }

    const parsed = new Date(value);
    if (Number.isNaN(parsed.getTime())) {
        return 'TIME_UNKNOWN';
    }

    return parsed.toLocaleString(undefined, {
        month: 'short',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
    }).toUpperCase();
};

const systemStats = [
    { label: 'CPU', values: ['23%', '31%', '27%', '35%'] },
    { label: 'MEM', values: ['4.8 GB', '5.1 GB', '4.9 GB', '5.3 GB'] },
    { label: 'LAT', values: ['42 MS', '38 MS', '47 MS', '40 MS'] },
];

const SidebarTelemetry = () => {
    const [scans, setScans] = useState([]);
    const [isLoading, setIsLoading] = useState(true);
    const [error, setError] = useState('');
    const [tickerIndex, setTickerIndex] = useState(0);
    const [selectedScan, setSelectedScan] = useState(null);
    const [isDownloading, setIsDownloading] = useState(false);
    const [downloadError, setDownloadError] = useState('');

    useEffect(() => {
        let isMounted = true;

        const loadScans = async () => {
            const { data, error: fetchError } = await supabase
                .from('scans')
                .select('id, target_url, status, created_at, threat_level')
                .order('created_at', { ascending: false })
                .limit(3);

            if (!isMounted) {
                return;
            }

            if (fetchError) {
                setError(fetchError.message.toUpperCase());
                setScans([]);
            } else {
                setError('');
                setScans(data ?? []);
            }

            setIsLoading(false);
        };

        loadScans();

        const channel = supabase
            .channel('homepage-sidebar-scans')
            .on(
                'postgres_changes',
                { event: '*', schema: 'public', table: 'scans' },
                (payload) => {
                    if (!isMounted) {
                        return;
                    }

                    if (payload.eventType === 'DELETE') {
                        setScans((current) => current.filter((scan) => scan.id !== payload.old.id).slice(0, 3));
                        return;
                    }

                    const nextRecord = payload.new;
                    setScans((current) => {
                        const filtered = current.filter((scan) => scan.id !== nextRecord.id);
                        return [nextRecord, ...filtered]
                            .sort(
                                (left, right) =>
                                    new Date(right.created_at ?? 0).getTime() - new Date(left.created_at ?? 0).getTime()
                            )
                            .slice(0, 3);
                    });
                }
            )
            .subscribe();

        return () => {
            isMounted = false;
            supabase.removeChannel(channel);
        };
    }, []);

    useEffect(() => {
        const ticker = window.setInterval(() => {
            setTickerIndex((current) => (current + 1) % systemStats[0].values.length);
        }, 2200);

        return () => window.clearInterval(ticker);
    }, []);

    const handleDownloadReport = async () => {
        if (!selectedScan) {
            return;
        }

        setIsDownloading(true);
        setDownloadError('');

        try {
            const response = await fetch(buildApiUrl(`/api/v1/scans/${selectedScan.id}/report`));
            if (!response.ok) {
                const payload = await response.json().catch(() => ({}));
                throw new Error(payload.detail || 'REPORT DOWNLOAD FAILED.');
            }

            const blob = await response.blob();
            const objectUrl = window.URL.createObjectURL(blob);
            const link = document.createElement('a');
            link.href = objectUrl;
            link.download = `aether-security-audit-${selectedScan.id}.pdf`;
            document.body.appendChild(link);
            link.click();
            link.remove();
            window.URL.revokeObjectURL(objectUrl);
            setSelectedScan(null);
        } catch (downloadFailure) {
            setDownloadError((downloadFailure.message || 'REPORT DOWNLOAD FAILED.').toUpperCase());
        } finally {
            setIsDownloading(false);
        }
    };

    return (
        <>
            <aside className="h-full border border-white/10 bg-[linear-gradient(180deg,rgba(12,12,13,0.98),rgba(6,6,7,0.98))]">
                <div className="border-b border-white/10 px-5 py-4">
                    <p className="text-[9px] font-black uppercase tracking-[0.42em] text-lambo-gold">
                        Sidebar Telemetry
                    </p>
                    <h2 className="mt-3 text-sm font-black uppercase tracking-[0.18em] text-lambo-white">
                        Recent Scans
                    </h2>
                </div>

                <div className="space-y-3 px-5 py-5">
                    {error && (
                        <div className="border border-white/10 bg-red-600/10 px-3 py-3 text-[9px] uppercase tracking-[0.22em] text-red-400">
                            {error}
                        </div>
                    )}

                    {isLoading && !error && Array.from({ length: 3 }).map((_, index) => (
                        <div key={index} className="border border-white/10 bg-white/[0.02] px-4 py-4">
                            <div className="h-2 w-20 bg-lambo-gold/20" />
                            <div className="mt-4 h-8 bg-white/[0.05]" />
                            <div className="mt-4 h-2 w-24 bg-white/[0.05]" />
                        </div>
                    ))}

                    {!isLoading && !error && scans.length === 0 && (
                        <div className="border border-white/10 bg-white/[0.02] px-4 py-6 text-center">
                            <p className="text-[9px] uppercase tracking-[0.35em] text-lambo-gold">No Scans Yet</p>
                            <p className="mt-3 text-[10px] uppercase tracking-[0.18em] text-lambo-ash">
                                Launch a hunt to populate this rail.
                            </p>
                        </div>
                    )}

                    {scans.map((scan) => {
                        const normalizedStatus = normalizeStatus(scan.status);

                        return (
                            <button
                                key={scan.id}
                                type="button"
                                onClick={() => {
                                    setSelectedScan(scan);
                                    setDownloadError('');
                                }}
                                className="w-full border border-white/10 bg-white/[0.02] px-4 py-4 text-left transition-colors duration-300 hover:border-lambo-gold/30"
                            >
                                <div className="flex items-center justify-between gap-4">
                                    <p className="text-[8px] font-black uppercase tracking-[0.35em] text-lambo-gold">
                                        {(scan.id ?? 'UNKNOWN').slice(0, 8)}
                                    </p>
                                    <span className={`text-[8px] font-black uppercase tracking-[0.3em] ${statusPalette[normalizedStatus]}`}>
                                        {normalizedStatus}
                                    </span>
                                </div>
                                <p className="mt-3 break-all text-[11px] font-bold uppercase leading-relaxed tracking-[0.16em] text-lambo-white">
                                    {scan.target_url ?? 'TARGET_UNAVAILABLE'}
                                </p>
                                <div className="mt-4 flex items-center justify-between text-[8px] uppercase tracking-[0.24em] text-lambo-ash">
                                    <span>{formatTime(scan.created_at)}</span>
                                    <span>{(scan.threat_level ?? 'unknown').toString().toUpperCase()}</span>
                                </div>
                            </button>
                        );
                    })}
                </div>

                <div className="border-t border-white/10 px-5 py-4">
                    <p className="text-[9px] font-black uppercase tracking-[0.42em] text-lambo-gold">
                        System Status
                    </p>
                    <div className="mt-4 space-y-3">
                        {systemStats.map((stat) => (
                            <div key={stat.label} className="border border-white/10 bg-black/40 px-4 py-3">
                                <div className="flex items-center justify-between text-[8px] uppercase tracking-[0.32em] text-lambo-ash">
                                    <span>{stat.label}</span>
                                    <span className="text-lambo-gold">LIVE</span>
                                </div>
                                <div className="mt-3 flex items-end justify-between gap-3">
                                    <span className="text-lg font-black uppercase tracking-[-0.08em] text-lambo-white">
                                        {stat.values[tickerIndex]}
                                    </span>
                                    <span className="text-[8px] uppercase tracking-[0.28em] text-lambo-ash">
                                        TICK {tickerIndex + 1}
                                    </span>
                                </div>
                            </div>
                        ))}
                    </div>
                </div>
            </aside>

            {selectedScan && (
                <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 px-5">
                    <div className="w-full max-w-lg border border-white/10 bg-[#0c0c0d] p-8">
                        <p className="text-[9px] font-black uppercase tracking-[0.42em] text-lambo-gold">
                            Diagnosis Report
                        </p>
                        <h3 className="mt-4 text-2xl font-black uppercase tracking-[-0.06em] text-lambo-white">
                            Download Diagnosis
                        </h3>
                        <p className="mt-4 text-[11px] uppercase leading-relaxed tracking-[0.18em] text-lambo-ash">
                            Do you want to download the Diagnosis Report for <span className="text-lambo-gold">{selectedScan.target_url}</span>?
                        </p>

                        {downloadError && (
                            <div className="mt-6 border border-white/10 bg-red-600/10 px-4 py-3 text-[10px] uppercase tracking-[0.18em] text-red-400">
                                {downloadError}
                            </div>
                        )}

                        <div className="mt-8 flex gap-4">
                            <button
                                type="button"
                                onClick={() => {
                                    setSelectedScan(null);
                                    setDownloadError('');
                                }}
                                className="flex-1 border border-white/10 py-4 text-[10px] uppercase tracking-[0.2em] text-lambo-ash transition-colors hover:bg-white/5"
                            >
                                Cancel
                            </button>
                            <button
                                type="button"
                                onClick={handleDownloadReport}
                                disabled={isDownloading}
                                className={`flex-1 py-4 text-[10px] font-black uppercase tracking-[0.2em] transition-colors ${
                                    isDownloading
                                        ? 'cursor-wait bg-lambo-gold/20 text-black/40'
                                        : 'bg-lambo-gold text-black hover:bg-[#917300]'
                                }`}
                            >
                                {isDownloading ? 'Generating PDF...' : 'Download Report'}
                            </button>
                        </div>
                    </div>
                </div>
            )}
        </>
    );
};

export default SidebarTelemetry;
