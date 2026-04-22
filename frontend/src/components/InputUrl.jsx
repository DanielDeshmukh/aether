import React, { useState } from 'react';

const InputUrl = () => {
    const [url, setUrl] = useState('');
    const [hasAuthority, setHasAuthority] = useState(false);
    const [isProcessing, setIsProcessing] = useState(false);
    const [step, setStep] = useState('input'); // input | confirm | success

    const handleInitialSubmit = (e) => {
        e.preventDefault();
        if (url) setStep('confirm');
    };

    const handleFinalExecution = () => {
        setIsProcessing(true);
        // Simulate Aether engine "verifying" the perimeter
        setTimeout(() => {
            setIsProcessing(false);
            setStep('success');
        }, 2000);
    };

    return (
        <div className="max-w-2xl mx-auto mt-12 font-mono">
            {/* 1. URL INPUT STAGE */}
            {step === 'input' && (
                <div className="bg-[#0c0c0d] border border-lambo-charcoal/30 p-8 rounded-2xl relative overflow-hidden group">
                    <div className="absolute top-0 left-0 w-[2px] h-full bg-lambo-gold opacity-0 group-hover:opacity-100 transition-opacity"></div>
                    
                    <h2 className="text-lambo-gold text-[10px] font-black tracking-[0.4em] uppercase mb-6 flex items-center gap-2">
                        Target Acquisition
                    </h2>
                    
                    <form onSubmit={handleInitialSubmit} className="space-y-6">
                        <div className="relative">
                            <input 
                                type="url"
                                required
                                value={url}
                                onChange={(e) => setUrl(e.target.value)}
                                placeholder="HTTPS://TARGET-DOMAIN.COM"
                                className="w-full bg-neutral-900/50 border border-lambo-charcoal/50 text-lambo-white py-5 px-6 rounded-xl outline-none focus:border-lambo-gold/50 transition-all placeholder:text-lambo-ash/20 tracking-widest text-sm"
                            />
                            
                        </div>
                        
                        <button className="w-full bg-lambo-gold hover:bg-[#c2a032] text-black font-black py-4 rounded-xl uppercase tracking-[0.2em] transition-all text-xs">
                            Initialize Neural Scan
                        </button>
                    </form>
                </div>
            )}

            {/* 2. AUTHORITY CONFIRMATION DIALOG */}
            {step === 'confirm' && (
                <div className="bg-[#0c0c0d] border border-lambo-gold/30 p-8 rounded-2xl relative">
                    <div className="text-center mb-8">
                        <div className="inline-block px-3 py-1 bg-red-600/10 border border-red-600/20 text-red-500 text-[9px] font-black tracking-widest uppercase mb-4">
                            Legal Protocol Required
                        </div>
                        <h2 className="text-lambo-white text-xl uppercase tracking-tighter">Authority Verification</h2>
                    </div>

                    <div className="bg-neutral-950/80 border border-lambo-charcoal/30 p-5 rounded-xl mb-8">
                        <p className="text-[11px] text-lambo-ash leading-relaxed uppercase tracking-wider">
                            By proceeding, you explicitly declare full administrative authority over <span className="text-lambo-gold">{url}</span>. 
                            Aether's orchestration loops operate under the assumption of legal ownership. 
                            Unauthorized testing is strictly prohibited by our <span className="text-lambo-gold underline cursor-pointer">Privacy Framework</span>.
                        </p>
                    </div>

                    <label className="flex items-start gap-4 cursor-pointer group mb-8">
                        <div className="relative mt-1">
                            <input 
                                type="checkbox" 
                                checked={hasAuthority}
                                onChange={() => setHasAuthority(!hasAuthority)}
                                className="peer sr-only"
                            />
                            <div className="w-5 h-5 border border-lambo-gold/30 rounded peer-checked:bg-lambo-gold transition-all"></div>
                            <div className="absolute inset-0 flex items-center justify-center opacity-0 peer-checked:opacity-100 text-black text-[10px] font-bold">
                                ✓
                            </div>
                        </div>
                        <span className="text-[10px] text-lambo-white uppercase tracking-widest leading-tight select-none">
                            I confirm legal jurisdiction and administrative ownership of this domain.
                        </span>
                    </label>

                    <div className="flex gap-4">
                        <button 
                            onClick={() => setStep('input')}
                            className="flex-1 border border-lambo-charcoal/50 text-lambo-ash py-4 rounded-xl uppercase tracking-widest text-[10px] hover:bg-white/5 transition-all"
                        >
                            Abort
                        </button>
                        <button 
                            disabled={!hasAuthority || isProcessing}
                            onClick={handleFinalExecution}
                            className={`flex-1 py-4 rounded-xl uppercase tracking-widest text-[10px] font-black transition-all ${
                                hasAuthority ? 'bg-lambo-gold text-black' : 'bg-lambo-gold/20 text-black/40 cursor-not-allowed'
                            }`}
                        >
                            {isProcessing ? 'Verifying...' : 'Authorize & Execute'}
                        </button>
                    </div>
                </div>
            )}

            {/* 3. SUCCESS MESSAGE */}
            {step === 'success' && (
                <div className="bg-lambo-gold p-1 rounded-2xl animate-in fade-in zoom-in duration-500">
                    <div className="bg-neutral-950 p-10 rounded-[calc(1rem-4px)] text-center">
                        <div className="w-16 h-16 bg-lambo-gold/10 border border-lambo-gold rounded-full flex items-center justify-center mx-auto mb-6">
                            <span className="text-lambo-gold text-2xl">✓</span>
                        </div>
                        <h2 className="text-lambo-white text-2xl uppercase tracking-tighter mb-2">Protocol Established</h2>
                        <p className="text-lambo-ash text-[10px] uppercase tracking-[0.2em]">
                            Target <span className="text-lambo-gold">{url}</span> successfully integrated into Aether Neural Hub.
                        </p>
                        <button 
                            onClick={() => setStep('input')}
                            className="mt-8 text-lambo-gold text-[9px] uppercase tracking-widest hover:underline"
                        >
                            Scan New Perimeter
                        </button>
                    </div>
                </div>
            )}
        </div>
    );
};

export default InputUrl;