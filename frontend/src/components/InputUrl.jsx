import React, { useState } from 'react';
import { supabase } from '../lib/supabaseClient';
import { buildApiUrl } from '../lib/api';

const InputUrl = ({ onTerminalStart, className = '', consentConfirmed = false, onConsentChange }) => {
    const [url, setUrl] = useState('');
    const [isProcessing, setIsProcessing] = useState(false);
    const [isSubmitting, setIsSubmitting] = useState(false);
    const [error, setError] = useState('');
    const [step, setStep] = useState('input');

    const handleInitialSubmit = (e) => {
        e.preventDefault();
        if (url && consentConfirmed) {
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

            const response = await fetch(buildApiUrl('/api/v1/scans'), {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    target_url: url,
                    user_id: user?.id ?? null,
                    consent_confirmed: consentConfirmed,
                }),
            });
            const payload = await response.json();

            if (!response.ok) {
                throw new Error(payload.detail || 'ENGINE HANDSHAKE FAILED.');
            }

            setStep('success');

            if (onTerminalStart) {
                setTimeout(() => onTerminalStart(payload), 800);
            }
        } catch (submitError) {
            setError((submitError.message || 'ENGINE HANDSHAKE FAILED.').toUpperCase());
            setStep('confirm');
        } finally {
            setIsProcessing(false);
            setIsSubmitting(false);
        }
    };

    const resetState = () => {
        setStep('input');
        setIsProcessing(false);
        setIsSubmitting(false);
        setError('');
    };

    return (
        <div className={`w-full font-mono ${className}`.trim()}>
            {step === 'input' && (
                <div className="group relative overflow-hidden border border-white/10 bg-[#0c0c0d] p-8 transition-colors duration-300 hover:border-lambo-gold/30">
                    <div className="absolute left-0 top-0 h-full w-[2px] bg-lambo-gold opacity-0 transition-opacity group-hover:opacity-100"></div>

                    <div className="mb-6 flex items-center gap-3">
                        <div className="h-2 w-2 animate-pulse bg-lambo-gold"></div>
                        <h2 className="text-[10px] font-black uppercase tracking-[0.4em] text-lambo-gold">
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
                                className="w-full border border-white/10 bg-neutral-900/50 px-6 py-5 text-sm tracking-widest text-lambo-white outline-none transition-colors placeholder:text-lambo-ash/20 focus:border-lambo-gold/50"
                            />
                            <div className="absolute right-4 top-1/2 -translate-y-1/2 text-[9px] tracking-tighter text-lambo-gold/20">
                                [AWAITING_COORDINATES]
                            </div>
                        </div>

                        <label className="group flex cursor-pointer items-start gap-4">
                            <div className="relative mt-1">
                                <input
                                    type="checkbox"
                                    checked={consentConfirmed}
                                    onChange={(event) => onConsentChange?.(event.target.checked)}
                                    className="peer sr-only"
                                />
                                <div className="h-5 w-5 border border-white/10 transition-colors duration-300 peer-checked:bg-lambo-gold"></div>
                                <div className="absolute inset-0 flex items-center justify-center text-[9px] font-black text-black opacity-0 peer-checked:opacity-100">
                                    OK
                                </div>
                            </div>
                            <span className="text-[10px] uppercase leading-tight tracking-[0.18em] text-lambo-white/80 transition-opacity group-hover:text-lambo-white">
                                I certify that I own this target or have explicit written authorization to perform security testing.
                            </span>
                        </label>

                        <button
                            type="submit"
                            disabled={!consentConfirmed}
                            className={`w-full py-4 text-xs font-black uppercase tracking-[0.2em] transition-[background-color,box-shadow] duration-300 ${
                                consentConfirmed
                                    ? 'bg-lambo-gold text-black hover:bg-[#917300] hover:shadow-[0_0_15px_rgba(255,191,0,0.4)]'
                                    : 'cursor-not-allowed bg-lambo-gold/20 text-black/40'
                            }`}
                        >
                            Initialize Neural Scan
                        </button>
                    </form>
                </div>
            )}

            {step === 'confirm' && (
                <div className="relative border border-white/10 bg-[#0c0c0d] p-8 animate-in fade-in slide-in-from-bottom-4 duration-500">
                    <div className="mb-8 text-center">
                        <div className="mb-4 inline-block border border-white/10 bg-red-600/10 px-3 py-1 text-[9px] font-black uppercase tracking-widest text-red-500">
                            Legal Protocol Required
                        </div>
                        <h2 className="text-xl uppercase tracking-tighter text-lambo-white">Authority Verification</h2>
                    </div>

                    <div className="mb-8 border border-white/10 bg-neutral-950/80 p-5">
                        <p className="text-[11px] uppercase tracking-wider text-lambo-ash">
                            By proceeding, AETHER will write a consent log before the hunt starts for <span className="text-lambo-gold underline underline-offset-4">{url}</span>.
                            The target, authenticated user identity when available, and source IP will be persisted as part of the legal shield.
                        </p>
                    </div>

                    {error && (
                        <div className="mb-6 border border-white/10 bg-red-600/10 px-4 py-3 text-[10px] uppercase tracking-[0.18em] text-red-500">
                            {error}
                        </div>
                    )}

                    <div className="mb-8 border border-white/10 bg-white/[0.02] px-4 py-4 text-[10px] uppercase tracking-[0.18em] text-lambo-white">
                        Consent Status: <span className="text-lambo-gold">{consentConfirmed ? 'ARMED FOR LOGGING' : 'MISSING'}</span>
                    </div>

                    <div className="flex gap-4">
                        <button
                            onClick={resetState}
                            className="flex-1 border border-white/10 py-4 text-[10px] uppercase tracking-widest text-lambo-ash transition-colors hover:bg-white/5"
                        >
                            Abort
                        </button>
                        <button
                            disabled={!consentConfirmed || isProcessing || isSubmitting}
                            onClick={handleFinalExecution}
                            className={`flex-1 py-4 text-[10px] font-black uppercase tracking-widest transition-colors ${
                                consentConfirmed
                                    ? 'bg-lambo-gold text-black hover:bg-[#917300]'
                                    : 'cursor-not-allowed bg-lambo-gold/20 text-black/40'
                            }`}
                        >
                            {isProcessing ? 'Logging Consent...' : 'Authorize & Execute Hunt'}
                        </button>
                    </div>
                </div>
            )}

            {step === 'success' && (
                <div className="animate-in zoom-in duration-700 bg-lambo-gold p-[1px] fade-in">
                    <div className="bg-neutral-950 p-10 text-center">
                        <div className="mx-auto mb-6 flex h-16 w-16 items-center justify-center border border-white/10 bg-lambo-gold/10">
                            <span className="text-xs font-black uppercase tracking-[0.3em] text-lambo-gold">Armed</span>
                        </div>
                        <h2 className="mb-2 text-2xl uppercase tracking-tighter text-lambo-white">Protocol Established</h2>
                        <p className="mx-auto max-w-xs text-[10px] uppercase leading-loose tracking-[0.2em] text-lambo-ash">
                            Target <span className="text-lambo-gold">{url}</span> successfully integrated into the AETHER hunt pipeline.
                        </p>

                        <div className="mt-8 flex flex-col gap-4 border-t border-white/10 pt-8">
                            <div className="animate-pulse text-[9px] uppercase tracking-[0.3em] text-lambo-gold/40">
                                Handing over to vulnerability hunter...
                            </div>
                            <button
                                onClick={resetState}
                                className="text-[9px] uppercase tracking-widest text-lambo-ash transition-colors hover:text-lambo-gold"
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
