import React, { useEffect, useRef, useState } from 'react';

const statusLabels = {
    idle: 'STANDBY',
    connecting: 'LINKING',
    scanning: 'SCANNING',
    analyzing: 'ANALYZING',
    paused: 'PLAN HOLD',
    terminated: 'HALTED',
};

const ScanningConsole = ({ scanSession }) => {
    const [logs, setLogs] = useState([]);
    const [status, setStatus] = useState('idle');
    const [brainState, setBrainState] = useState(null);
    const scrollRef = useRef(null);
    const socketRef = useRef(null);

    useEffect(() => {
        if (!scanSession?.scan_id) {
            setLogs([]);
            setStatus('idle');
            return undefined;
        }

        setLogs([
            {
                type: 'thought',
                phase: 'thought',
                msg: `THOUGHT: MISSION FILE ACCEPTED FOR ${scanSession.target_url.toUpperCase()}. INITIALIZING AETHER REASONING STACK.`,
            },
        ]);
        setBrainState(null);
        setStatus('connecting');

        socketRef.current = new WebSocket(`ws://localhost:8000/ws/scan/${scanSession.scan_id}`);

        socketRef.current.onopen = () => {
            setStatus('scanning');
        };

        socketRef.current.onmessage = (event) => {
            const data = JSON.parse(event.data);
            setLogs((prev) => [...prev, data]);
            if (data.brain) {
                setBrainState(data.brain);
            }

            if (data.phase === 'analyze' || data.msg.includes('COMPLETE')) {
                setStatus('analyzing');
            }

            if (data.phase === 'plan' && data.brain?.status === 'paused') {
                setStatus('paused');
            }

            if (data.msg.includes('TERMINATED')) {
                setStatus('terminated');
            }
        };

        socketRef.current.onerror = () => {
            setLogs((prev) => [...prev, { type: 'error', msg: 'WEBSOCKET CONNECTION FAILURE.' }]);
            setStatus('terminated');
        };

        socketRef.current.onclose = () => {
            setStatus((currentStatus) => (currentStatus === 'terminated' ? currentStatus : 'analyzing'));
        };

        return () => {
            socketRef.current?.close();
        };
    }, [scanSession]);

    useEffect(() => {
        if (scrollRef.current) {
            scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
        }
    }, [logs]);

    const handleKillSwitch = async () => {
        if (!scanSession?.scan_id) return;

        setStatus('terminated');

        try {
            await fetch(`http://localhost:8000/api/v1/scan/kill/${scanSession.scan_id}`, { method: 'POST' });
        } catch (err) {
            console.error('Failed to send kill signal to engine:', err);
        }

        setLogs((prev) => [
            ...prev,
            {
                type: 'error',
                msg: '!!! EMERGENCY TERMINATION EXECUTED BY OPERATOR !!!',
            },
        ]);

        socketRef.current?.close();
    };

    const sendPlanSignal = (action, reason) => {
        if (socketRef.current?.readyState !== WebSocket.OPEN) return;

        socketRef.current.send(
            JSON.stringify({
                action,
                reason,
            })
        );
    };

    return (
        <div className="w-full max-w-4xl mx-auto font-mono animate-in fade-in duration-700">
            <div className="bg-[#0c0c0d] border border-lambo-charcoal/30 overflow-hidden">
                <div className="bg-lambo-charcoal/10 border-b border-lambo-charcoal/30 p-4 flex justify-between items-center">
                    <div className="flex items-center gap-3">
                        <div className={`w-2 h-2 ${status === 'terminated' ? 'bg-red-600' : 'bg-lambo-gold animate-pulse'}`}></div>
                        <span className="text-[10px] text-lambo-white uppercase tracking-[0.3em] font-black">
                            AETHER_ENGINE_CORE
                        </span>
                    </div>
                    <div className="text-[9px] text-lambo-ash uppercase tracking-widest flex items-center gap-2">
                        ID: <span className="text-lambo-gold">{scanSession?.scan_id || 'STANDBY'}</span>
                        <span className="text-lambo-charcoal">|</span>
                        Mode: <span className="text-lambo-gold">{statusLabels[status]}</span>
                    </div>
                </div>

                {brainState?.requires_operator && (
                    <div className="border-b border-lambo-gold/30 bg-lambo-gold/10 px-4 py-3 flex items-center justify-between gap-4">
                        <div>
                            <p className="text-[9px] text-lambo-gold uppercase tracking-[0.35em]">Plan Hold</p>
                            <p className="text-[10px] text-lambo-white uppercase tracking-[0.18em]">
                                {brainState.resume_reason || 'OPERATOR REVIEW REQUIRED'}
                            </p>
                        </div>
                        <button
                            onClick={() => sendPlanSignal('resume', 'OPERATOR CLEARED THE PLAN WINDOW.')}
                            className="border border-lambo-gold bg-lambo-gold px-4 py-2 text-[10px] font-black uppercase tracking-[0.2em] text-black transition-colors hover:bg-[#917300]"
                        >
                            Resume Reasoning
                        </button>
                    </div>
                )}

                <div
                    ref={scrollRef}
                    className="h-80 overflow-y-auto p-6 space-y-2 bg-black/50 scrollbar-thin scrollbar-thumb-lambo-gold/20 scroll-smooth"
                >
                    {!scanSession && (
                        <div className="text-[11px] uppercase tracking-[0.2em] text-lambo-ash">
                            Awaiting a target authorization to start the O-PE-A engine loop.
                        </div>
                    )}

                    {logs.map((log, i) => {
                        if (!log) return null;
                        return (
                            <div key={i} className="flex gap-4 text-[11px] leading-relaxed animate-in fade-in slide-in-from-left-2 duration-300">
                                <span className="text-lambo-ash/40">[{new Date().toLocaleTimeString([], { hour12: false })}]</span>
                                <span className={`uppercase font-bold tracking-tight w-20 ${
                                    log.type === 'error'
                                        ? 'text-red-600'
                                        : 'text-lambo-gold'
                                }`}>
                                    [{(log.type || 'thought').toUpperCase()}]
                                </span>
                                <div className={`flex-1 space-y-1 border px-3 py-3 ${
                                    log.type === 'error'
                                        ? 'border-red-600/30 bg-red-600/10'
                                        : 'border-lambo-gold/30 bg-lambo-gold/5'
                                }`}>
                                    <span className={`block tracking-wide uppercase ${
                                        log.type === 'error' ? 'text-red-400' : 'text-lambo-white'
                                    }`}>{log.msg}</span>
                                    {log.phase && (
                                        <span className={`inline-block border px-2 py-1 text-[8px] uppercase tracking-[0.28em] ${
                                            log.type === 'error'
                                                ? 'border-red-600/40 text-red-400'
                                                : 'border-lambo-gold/50 text-lambo-gold'
                                        }`}>
                                            {log.phase}
                                        </span>
                                    )}
                                </div>
                            </div>
                        );
                    })}

                    {status === 'scanning' && (
                        <div className="text-lambo-gold text-[11px] animate-pulse py-2">
                            _ ENGINE_ACTIVE: STREAMING_TELEMETRY...
                        </div>
                    )}
                </div>

                <div className="p-4 bg-lambo-charcoal/5 border-t border-lambo-charcoal/30 flex items-center justify-between">
                    <div className="flex flex-col gap-1">
                        <span className="text-[8px] text-lambo-ash uppercase">Process Authority</span>
                        <span className="text-[10px] text-lambo-white font-bold tracking-widest">
                            {status === 'terminated'
                                ? 'STDOUT_NULL'
                                : scanSession?.scan_id
                                    ? `PID_${scanSession.scan_id.toUpperCase()}`
                                    : 'NO_ACTIVE_PROCESS'}
                        </span>
                    </div>

                    <div className="flex items-center gap-3">
                        <button
                            onClick={handleKillSwitch}
                            disabled={status === 'terminated' || !scanSession?.scan_id}
                            className={`px-6 py-2 text-[10px] font-black uppercase tracking-[0.2em] transition-colors border ${
                                status === 'terminated' || !scanSession?.scan_id
                                    ? 'border-lambo-charcoal text-lambo-ash opacity-50 cursor-not-allowed'
                                    : 'border-red-600/50 text-red-500 hover:bg-red-600 hover:text-white'
                            }`}
                        >
                            {status === 'terminated' ? 'Engine Halted' : 'Execute Kill Switch'}
                        </button>
                    </div>
                </div>
            </div>

            <div className="grid grid-cols-3 gap-4 mt-6">
                {[
                    { label: 'Neural_Depth', val: '88%' },
                    { label: 'Active_Nodes', val: logs.length },
                    { label: 'Risk_Score', val: status === 'terminated' ? '0' : 'LVL_3' },
                ].map((stat, i) => (
                    <div key={i} className="bg-[#0c0c0d] border border-lambo-charcoal/20 p-3 text-center group hover:border-lambo-gold/30 transition-colors">
                        <p className="text-[8px] text-lambo-ash uppercase mb-1 tracking-widest">{stat.label}</p>
                        <p className="text-sm text-lambo-white font-bold">{stat.val}</p>
                    </div>
                ))}
            </div>
        </div>
    );
};

export default ScanningConsole;
