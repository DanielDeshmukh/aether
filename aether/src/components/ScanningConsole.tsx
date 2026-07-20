"use client";

import { useEffect, useRef, useState, useCallback } from "react";
import Link from "next/link";
import { buildApiUrl } from "@/lib/api-client";

const statusLabels: Record<string, string> = {
  idle: "Standby",
  connecting: "Linking",
  scanning: "Scanning",
  analyzing: "Analyzing",
  paused: "Plan Hold",
  terminated: "Halted",
  failed: "Failed",
  completed: "Completed",
};

interface LogEntry {
  type?: string;
  phase?: string;
  msg: string;
  attack_vector?: string;
  evidence_snippet?: string;
  provided_solution?: string;
}

interface ScanningConsoleProps {
  scanSession: { scan_id?: string; target_url?: string } | null;
  className?: string;
}

export default function ScanningConsole({ scanSession, className = "" }: ScanningConsoleProps) {
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [status, setStatus] = useState("idle");
  const scrollRef = useRef<HTMLDivElement>(null);
  const eventSourceRef = useRef<EventSource | null>(null);
  const prevScanIdRef = useRef<string | undefined>(undefined);

  const cleanup = useCallback(() => {
    if (eventSourceRef.current) {
      eventSourceRef.current.close();
      eventSourceRef.current = null;
    }
  }, []);

  useEffect(() => {
    if (!scanSession?.scan_id) {
      cleanup();
      return undefined;
    }

    if (prevScanIdRef.current !== scanSession.scan_id) {
      prevScanIdRef.current = scanSession.scan_id;
      setLogs([
        { type: "thought", phase: "thought", msg: `Thought: Mission file accepted for ${scanSession.target_url}. Initializing Aether reasoning stack.` },
      ]);
      setStatus("connecting");
    }

    const token = document.cookie.match(/(?:^|;\s*)access_token=([^;]*)/)?.[1] ?? "";
    const sseUrl = buildApiUrl(`/api/v1/scans/${scanSession.scan_id}/progress`);
    const url = token ? `${sseUrl}?token=${token}` : sseUrl;

    const es = new EventSource(url);
    eventSourceRef.current = es;

    es.addEventListener("progress", (event) => {
      try {
        const data = JSON.parse(event.data);
        const scanStatus = data.status?.toLowerCase() ?? "";

        if (scanStatus === "running" || scanStatus === "active" || scanStatus === "in_progress") {
          setStatus("scanning");
          setLogs((prev) => {
            const lastLog = prev[prev.length - 1];
            const progressMsg = `Engine active — scanning ${scanSession.target_url}...`;
            if (lastLog?.msg === progressMsg) return prev;
            return [...prev, { type: "system", phase: "scan", msg: progressMsg }];
          });
        } else if (scanStatus === "completed") {
          setStatus("completed");
        } else if (scanStatus === "failed") {
          setStatus("failed");
          setLogs((prev) => [...prev, { type: "error", msg: "Scan engine reported failure." }]);
        } else if (scanStatus === "paused") {
          setStatus("paused");
          setLogs((prev) => [...prev, { type: "system", phase: "plan", msg: "Scan paused by operator." }]);
        } else if (scanStatus === "terminated") {
          setStatus("terminated");
          setLogs((prev) => [...prev, { type: "error", msg: "Scan terminated." }]);
        }
      } catch { /* ignore parse errors */ }
    });

    es.addEventListener("complete", (event) => {
      try {
        const data = JSON.parse(event.data);
        if (data.status === "completed") {
          setStatus("completed");
          setLogs((prev) => [...prev, { type: "system", phase: "complete", msg: "SCAN COMPLETE — All phases finished." }]);
        } else if (data.status === "failed") {
          setStatus("failed");
        }
      } catch { /* ignore */ }
      es.close();
    });

    es.onerror = () => {
      setStatus((prev) => (prev === "terminated" || prev === "failed" ? prev : "completed"));
      es.close();
    };

    return cleanup;
  }, [scanSession, cleanup]);

  useEffect(() => {
    if (scrollRef.current) scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
  }, [logs]);

  const handleKillSwitch = async () => {
    if (!scanSession?.scan_id) return;
    setStatus("terminated");
    try { await fetch(`/api/v1/scan/kill/${scanSession.scan_id}`, { method: "POST" }); } catch { /* ignore */ }
    setLogs((prev) => [...prev, { type: "error", msg: "!!! Emergency termination executed by operator !!!" }]);
    cleanup();
  };

  return (
    <div className={`w-full font-mono animate-in fade-in duration-700 ${className}`.trim()}>
      <div className="bg-[#050505] border border-white/10 overflow-hidden">
        <div className="bg-[#0d0d0d] border-b border-white/10 p-4 flex justify-between items-center">
          <div className="flex items-center gap-3">
            <div className={`w-2 h-2 ${status === "terminated" || status === "failed" ? "bg-red-600" : "bg-lambo-gold animate-pulse"}`}></div>
            <span className="text-[10px] text-lambo-white tracking-[0.3em] font-bold">// Aether_Engine_Core</span>
          </div>
          <div className="text-[9px] sm:text-[10px] text-lambo-ash tracking-widest flex flex-wrap items-center gap-2">
            ID: <span className="text-lambo-gold">{scanSession?.scan_id || "Standby"}</span>
            <span className="text-lambo-charcoal">|</span>
            Mode: <span className="text-lambo-gold">{statusLabels[status]}</span>
          </div>
        </div>

        <div ref={scrollRef} className="h-80 overflow-y-auto p-6 space-y-2 bg-black/50 scrollbar-thin scrollbar-thumb-lambo-gold/20 scroll-smooth">
          {!scanSession && <div className="text-[11px] tracking-[0.15em] text-lambo-ash">Awaiting a target authorization to start the engine loop.</div>}

          {logs.map((log, i) => {
            if (!log) return null;
            const logType = (log.type || "thought").toLowerCase();
            const capitalizedType = logType.charAt(0).toUpperCase() + logType.slice(1);
            return (
              <div key={i} className="flex flex-wrap gap-2 sm:gap-4 text-[11px] leading-relaxed animate-in fade-in slide-in-from-left-2 duration-300">
                <span className="text-lambo-ash/40">[{new Date().toLocaleTimeString([], { hour12: false })}]</span>
                <span className={`font-bold tracking-tight w-16 sm:w-20 ${log.type === "error" ? "text-red-600" : "text-lambo-gold"}`}>
                  [{capitalizedType}]
                </span>
                <div className={`flex-1 space-y-1 border px-3 py-3 ${log.type === "error" ? "border-white/10 bg-red-600/10" : "border-white/10 bg-lambo-gold/5"}`}>
                  <span className={`block tracking-wide ${log.type === "error" ? "text-red-400" : "text-lambo-white"}`}>{log.msg}</span>
                  {log.attack_vector && (
                    <div className="border border-red-600/30 bg-red-600/10 px-3 py-2 text-[10px] text-red-300">Active Hit: {log.attack_vector}</div>
                  )}
                  {log.evidence_snippet && (
                    <pre className="overflow-x-auto whitespace-pre-wrap border border-white/10 bg-black/40 px-3 py-2 text-[10px] text-lambo-ash">{log.evidence_snippet}</pre>
                  )}
                  {log.provided_solution && (
                    <div className="border border-lambo-gold/20 bg-lambo-gold/10 px-3 py-2 text-[10px] text-lambo-white">Fix This: {log.provided_solution}</div>
                  )}
                  {log.phase && (
                    <span className={`inline-block border px-2 py-1 text-[9px] sm:text-[10px] tracking-[0.2em] ${log.type === "error" ? "border-white/10 text-red-400" : "border-white/10 text-lambo-gold"}`}>
                      {log.phase}
                    </span>
                  )}
                </div>
              </div>
            );
          })}

          {status === "scanning" && <div className="text-lambo-gold text-[11px] animate-pulse py-2">_ Engine active: Streaming telemetry...</div>}

          {status === "completed" && (
            <div className="mt-6 border border-lambo-gold/30 bg-lambo-gold/10 p-5 text-center animate-in fade-in slide-in-from-bottom-2">
              <p className="text-[12px] font-bold text-lambo-gold tracking-[0.15em] mb-2">Scan is complete</p>
              <p className="text-[10px] text-lambo-white tracking-[0.05em] mb-5">The system has finished scanning. Please head towards the dashboard to view the full audit result.</p>
              <Link href="/dashboard" className="inline-block border border-lambo-gold bg-lambo-gold px-6 py-3 text-[10px] font-bold tracking-[0.15em] text-black hover:bg-lambo-gold-dark hover:border-lambo-gold-dark transition-colors">
                Go to Dashboard
              </Link>
            </div>
          )}
        </div>

        <div className="p-4 bg-lambo-charcoal/5 border-t border-white/10 flex items-center justify-between">
          <div className="flex flex-col gap-1">
            <span className="text-[8px] text-lambo-ash uppercase">Process Authority</span>
            <span className="text-[10px] text-lambo-white font-bold tracking-widest">
              {status === "terminated" ? "STDOUT_NULL" : scanSession?.scan_id ? `pid_${scanSession.scan_id}` : "No active process"}
            </span>
          </div>
          <div className="flex items-center gap-3">
            <button
              onClick={handleKillSwitch}
              disabled={status === "terminated" || !scanSession?.scan_id}
              className={`px-6 py-3 text-[10px] sm:text-xs font-bold tracking-[0.15em] transition-colors border ${
                status === "terminated" || !scanSession?.scan_id ? "border-lambo-charcoal text-lambo-ash opacity-50 cursor-not-allowed" : "border-red-600/50 text-red-500 hover:bg-red-600 hover:text-white"
              }`}
            >
              {status === "terminated" ? "Engine Halted" : "Execute Kill Switch"}
            </button>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-4 mt-6">
        {[
          { label: "// Log Entries", val: logs.length },
          { label: "// Scan Status", val: status?.toUpperCase() || "ACTIVE" },
        ].map((stat, i) => (
          <div key={i} className="bg-[#0d0d0d] border border-white/10 p-3 text-center group hover:border-lambo-gold/30 transition-colors">
            <p className="text-[8px] text-lambo-ash uppercase mb-1 tracking-widest">{stat.label}</p>
            <p className="text-sm text-lambo-white font-bold">{String(stat.val)}</p>
          </div>
        ))}
      </div>
    </div>
  );
}
