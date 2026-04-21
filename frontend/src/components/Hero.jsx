import React from 'react';

const Hero = () => {
  return (
    <section className="relative min-h-screen flex items-center bg-lambo-black pt-24 pb-20 md:pt-32 md:pb-24 overflow-hidden">
      {/* Background glow – simplified */}
      <div className="absolute top-1/2 left-3/4 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[600px] md:w-[900px] md:h-[900px] bg-lambo-gold/5 blur-[120px] md:blur-[160px] rounded-full pointer-events-none"></div>
      <div className="absolute top-0 right-0 w-1/2 h-full bg-gradient-to-l from-lambo-gold/5 to-transparent pointer-events-none"></div>

      <div className="container mx-auto px-5 md:px-10 relative z-10 max-w-screen-lg">
        <div className="flex flex-col lg:flex-row items-center justify-between gap-8 md:gap-12 lg:gap-20">
          <div className="w-full lg:w-[55%] text-left">
            <div className="inline-block px-2 py-1 bg-lambo-gold/10 border-l border-lambo-gold mb-4 md:mb-6">
              <span className="text-[9px] md:text-[10px] font-bold text-lambo-gold tracking-[0.3em] uppercase">Protocol: AETHER_ALPHA</span>
            </div>
            <h1 className="text-[clamp(2.5rem,10vw,7rem)] mb-4 md:mb-6 text-lambo-white font-normal uppercase leading-[0.85] tracking-tighter">
              DOMINATE <br /> <span className="text-lambo-white/20">THE ATTACK</span> <br /> SURFACE.
            </h1>
            <p className="text-lg md:text-2xl text-lambo-ash max-w-xl mb-6 md:mb-8 uppercase tracking-[0.1em] md:tracking-[0.15em] font-light leading-relaxed">
              Agentic Reasoning Loop Engineering. <br />
              <span className="text-lambo-white/60">Autonomous penetration testing at machine scale.</span>
            </p>
            <div className="flex flex-col sm:flex-row gap-3 md:gap-5">
              <button className="w-full sm:w-auto border-2 bg-lambo-gold text-lambo-gold px-6 md:px-12 py-3 md:py-4 text-xs font-black tracking-[0.2em] transition-colors hover:bg-lambo-gold-dark shadow-[0_5px_10px_-5px_rgba(255,192,0,0.2)]">
                JOIN THE VANGUARD
              </button>
              <button className="w-full sm:w-auto border border-lambo-white/20 text-lambo-white/60 px-6 md:px-12 py-3 md:py-4 text-xs font-black tracking-[0.2em] transition-colors hover:bg-lambo-white/5 hover:text-lambo-white hover:border-lambo-white/40 uppercase">
                Explore Feed
              </button>
            </div>
          </div>
          <div className="w-full lg:w-[45%] relative group p-4 bg-lambo-charcoal/5">
            <img src="/images/fingerprint.png" alt="Cybersecurity Fingerprint" className="w-full h-auto object-contain filter drop-shadow-[0_0_30px_rgba(255,192,0,0.1)] transition-transform duration-300 group-hover:scale-105" />
            {/* Simple corner accents */}
          </div>
        </div>
      </div>

      {/* Microtext – mobile friendly */}
      <div className="absolute bottom-4 md:bottom-6 left-4 md:left-6 flex flex-col sm:flex-row items-start sm:items-center gap-2 md:gap-4 text-[8px] md:text-[9px] text-lambo-ash tracking-[0.2em]">
        <div className="flex items-center gap-2">
          <div className="w-2 h-2 bg-lambo-gold"></div>
          <span>Status: Operational</span>
        </div>
        <span className="opacity-70">Location: Secure Edge // 142.12.0.1</span>
      </div>
    </section>
  );
};

export default Hero;
