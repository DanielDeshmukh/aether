import React, { useEffect, useState } from 'react';
import { supabase } from '../lib/supabaseClient';
import { apiRequest } from '../lib/apiClient';

const SidebarTelemetry = () => {
    const [scans, setScans] = useState([]);
    const [isLoading, setIsLoading] = useState(true);
    const [selectedScan, setSelectedScan] = useState(null);
    const [isDownloading, setIsDownloading] = useState(false);
    const [error, setError] = useState('');

    useEffect(() => {
        const loadScans = async () => {
            const { data, error: fError } = await supabase
                .from('scans')
                .select('id, target_url, status, created_at, threat_level')
                .order('created_at', { ascending: false }).limit(3);
            if (!fError) setScans(data ?? []);
            setIsLoading(false);
        };
        loadScans();
    }, []);

    const handleDownloadReport = async () => {
        if (!selectedScan) return;
        setIsDownloading(true);
        try {
            // apiRequest returns the parsed JSON, but for a file download, we need the raw response.
            // We'll temporarily bypass apiRequest's JSON parsing for this specific endpoint.
            const { data: { session } } = await supabase.auth.getSession();
            const response = await fetch(`http://127.0.0.1:8000/api/v1/scans/${selectedScan.id}/report`, {
                headers: { 'Authorization': `Bearer ${session.access_token}` }
            });

            if (!response.ok) throw new Error('Failed to download report');
            const blob = await response.blob();
            const sanitized = selectedScan.target_url.replace(/[^a-z0-9]/gi, '-').toLowerCase();
            const link = document.createElement('a');
            link.href = URL.createObjectURL(blob);
            link.download = `aether-diagnosis-${sanitized}.pdf`;
            link.click();
            setSelectedScan(null);
        } catch (e) {
            setError('DOWNLOAD_FAILED');
        } finally {
            setIsDownloading(false);
        }
    };

    return (
        <aside className="h-full border border-white/10 bg-[#050505] font-sans">
            <div className="border-b border-white/10 px-5 py-6">
                <p className="text-[9px] font-black uppercase tracking-[0.4em] text-[#FFC107]">// Telemetry</p>
                <h2 className="mt-2 text-sm font-black uppercase text-white">Recent Hunts</h2>
            </div>

            <div className="p-5 space-y-4">
                {scans.map(scan => (
                    <button key={scan.id} onClick={() => setSelectedScan(scan)} 
                        className="w-full text-left border border-white/5 bg-[#0D0D0D] p-4 hover:border-[#FFC107]/50 transition-all">
                        <div className="flex justify-between items-center text-[8px] font-mono text-[#FFC107]">
                            <span>ID: {scan.id.slice(0,8)}</span>
                            <span className="uppercase">{scan.status}</span>
                        </div>
                        <p className="mt-2 text-[11px] font-bold text-white truncate">{scan.target_url}</p>
                    </button>
                ))}
            </div>

            {selectedScan && (
                <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/90 backdrop-blur-md">
                    <div className="w-full max-w-md border border-white/10 bg-[#0D0D0D] p-8">
                        <p className="text-[10px] font-mono text-[#FFC107] tracking-widest">// PDF_GENERATOR</p>
                        <h2 className="mt-4 text-2xl font-black text-white uppercase">Download Report</h2>
                        <div className="mt-6 border-l-2 border-[#FFC107] pl-4 py-1 text-xs text-gray-400">
                            Target: <span className="text-white">{selectedScan.target_url}</span>
                        </div>
                        <div className="mt-8 flex gap-3">
                            <button onClick={() => setSelectedScan(null)} className="flex-1 py-3 text-[10px] text-white border border-white/10 uppercase font-bold">Cancel</button>
                            <button onClick={handleDownloadReport} disabled={isDownloading}
                                className="flex-1 py-3 text-[10px] bg-[#FFC107] text-black font-black uppercase hover:bg-[#eab308]">
                                {isDownloading ? 'Processing...' : 'Confirm'}
                            </button>
                        </div>
                    </div>
                </div>
            )}
        </aside>
    );
};

export default SidebarTelemetry;