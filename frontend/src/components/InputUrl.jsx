import React, { useState } from 'react';
import { supabase } from '../lib/supabaseClient';

const InputUrl = ({ onTerminalStart }) => {
    const [url, setUrl] = useState('');
    const [hasAuthority, setHasAuthority] = useState(false);
    const [isProcessing, setIsProcessing] = useState(false);
    const [isSubmitting, setIsSubmitting] = useState(false);
    const [error, setError] = useState('');
    const [step, setStep] = useState('input');

    const handleInitialSubmit = (e) => {
        e.preventDefault();
        if (url) {
            setError('');
            setStep('confirm');
        }
    };

    const handleFinalExecution = async () => {
        setIsProcessing(true);
        setIsSubmitting(true);
        setError('');

        try {
            const {
                data: { user },
            } = await supabase.auth.getUser();
            const response = await fetch(
                `http://localhost:8000/api/v1/scans?target_url=${encodeURIComponent(url)}${user?.id ? `&user_id=${encodeURIComponent(user.id)}` : ''}`,
                { method: 'POST' }
            );
            const payload = await response.json();

            if (!response.ok) {
                throw new Error(payload.detail || 'ENGINE HANDSHAKE FAILED.');
            }

            setStep('success');

            if (onTerminalStart) {
                setTimeout(() => onTerminalStart(payload), 800);
            }
        } catch (submitError) {
            setError(submitError.message.toUpperCase());
            setStep('confirm');
        } finally {
            setIsProcessing(false);
            setIsSubmitting(false);
        }
    };

    const resetState = () => {
        setStep('input');
        setHasAuthority(false);
        setIsProcessing(false);
        setIsSubmitting(false);
        setError('');
    };

    return (
        <div className="max-w-2xl mx-auto mt-12 font-mono">
            {step === 'input' && (
                <div className="bg-[#0c0c0d] border border-lambo-charcoal/30 p-8 relative overflow-hidden group transition-colors duration-300 hover:border-lambo-gold/20">
                    <div className="absolute top-0 left-0 w-[2px] h-full bg-lambo-gold opacity-0 group-hover:opacity-100 transition-opacity"></div>

                    <div className="flex items-center gap-3 mb-6">
                        <div className="w-2 h-2 bg-lambo-gold animate-pulse"></div>
                        <h2 className="text-lambo-gold text-[10px] font-black tracking-[0.4em] uppercase">
                            Target Acquisition
                        </h2>
                    </div>

                    <form onSubmit={handleInitialSubmit} className="space-y-6">
                        <div className="relative">
                            <input
                                type="url"
                                required
                                value={url}
                                onChange={(e) => setUrl(e.target.value)}
                                placeholder="HTTPS://TARGET-SYSTEM.IO"
                                className="w-full bg-neutral-900/50 border border-lambo-charcoal/50 text-lambo-white py-5 px-6 outline-none focus:border-lambo-gold/50 transition-colors placeholder:text-lambo-ash/20 tracking-widest text-sm"
                            />
                            <div className="absolute right-4 top-1/2 -translate-y-1/2 text-[9px] text-lambo-gold/20 tracking-tighter">
                                [AWAITING_COORDINATES]
                            </div>
                        </div>

                        <button
                            type="submit"
                            className="w-full bg-lambo-gold hover:bg-[#917300] text-black font-black py-4 uppercase tracking-[0.2em] transition-colors text-xs"
                        >
                            Initialize Neural Scan
                        </button>
                    </form>
                </div>
            )}

            {step === 'confirm' && (
                <div className="bg-[#0c0c0d] border border-lambo-gold/30 p-8 relative animate-in fade-in slide-in-from-bottom-4 duration-500">
                    <div className="text-center mb-8">
                        <div className="inline-block px-3 py-1 bg-red-600/10 border border-red-600/20 text-red-500 text-[9px] font-black tracking-widest uppercase mb-4">
                            Legal Protocol Required
                        </div>
                        <h2 className="text-lambo-white text-xl uppercase tracking-tighter">Authority Verification</h2>
                    </div>

                    <div className="bg-neutral-950/80 border border-lambo-charcoal/30 p-5 mb-8">
                        <p className="text-[11px] text-lambo-ash leading-relaxed uppercase tracking-wider">
                            By proceeding, you explicitly declare full administrative authority over <span className="text-lambo-gold underline underline-offset-4">{url}</span>.
                            Aether&apos;s orchestration loops operate under the assumption of legal ownership.
                            Unauthorized testing is strictly prohibited by our <span className="text-lambo-gold underline cursor-pointer">Privacy Framework</span>.
                        </p>
                    </div>

                    {error && (
                        <div className="mb-6 border border-red-600/30 bg-red-600/10 px-4 py-3 text-[10px] text-red-500 uppercase tracking-[0.18em]">
                            {error}
                        </div>
                    )}

                    <label className="flex items-start gap-4 cursor-pointer group mb-8">
                        <div className="relative mt-1">
                            <input
                                type="checkbox"
                                checked={hasAuthority}
                                onChange={() => setHasAuthority(!hasAuthority)}
                                className="peer sr-only"
                            />
                            <div className="w-5 h-5 border border-lambo-gold/30 peer-checked:bg-lambo-gold transition-colors duration-300"></div>
                            <div className="absolute inset-0 flex items-center justify-center opacity-0 peer-checked:opacity-100 text-black text-[10px] font-bold">
                                ✓
                            </div>
                        </div>
                        <span className="text-[10px] text-lambo-white uppercase tracking-widest leading-tight select-none opacity-70 group-hover:opacity-100 transition-opacity">
                            I confirm legal jurisdiction and administrative ownership of this domain.
                        </span>
                    </label>

                    <div className="flex gap-4">
                        <button
                            onClick={resetState}
                            className="flex-1 border border-lambo-charcoal/50 text-lambo-ash py-4 uppercase tracking-widest text-[10px] hover:bg-white/5 transition-colors"
                        >
                            Abort
                        </button>
                        <button
                            disabled={!hasAuthority || isProcessing || isSubmitting}
                            onClick={handleFinalExecution}
                            className={`flex-1 py-4 uppercase tracking-widest text-[10px] font-black transition-colors ${
                                hasAuthority
                                    ? 'bg-lambo-gold text-black hover:bg-[#917300]'
                                    : 'bg-lambo-gold/20 text-black/40 cursor-not-allowed'
                            }`}
                        >
                            {isProcessing ? 'Verifying Protocol...' : 'Authorize & Execute'}
                        </button>
                    </div>
                </div>
            )}

            {step === 'success' && (
                <div className="bg-lambo-gold p-[1px] animate-in fade-in zoom-in duration-700">
                    <div className="bg-neutral-950 p-10 text-center">
                        <div className="w-16 h-16 bg-lambo-gold/10 border border-lambo-gold flex items-center justify-center mx-auto mb-6">
                            <span className="text-lambo-gold text-2xl">✓</span>
                        </div>
                        <h2 className="text-lambo-white text-2xl uppercase tracking-tighter mb-2">Protocol Established</h2>
                        <p className="text-lambo-ash text-[10px] uppercase tracking-[0.2em] max-w-xs mx-auto leading-loose">
                            Target <span className="text-lambo-gold">{url}</span> successfully integrated into Aether Neural Hub.
                        </p>

                        <div className="mt-8 pt-8 border-t border-lambo-charcoal/30 flex flex-col gap-4">
                            <div className="text-[9px] text-lambo-gold/40 uppercase tracking-[0.3em] animate-pulse">
                                Handing over to logic engine...
                            </div>
                            <button
                                onClick={resetState}
                                className="text-lambo-ash text-[9px] uppercase tracking-widest hover:text-lambo-gold transition-colors"
                            >
                                [ Initialize Alternative Perimeter ]
                            </button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
};

export default InputUrl;
