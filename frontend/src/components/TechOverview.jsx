import React from 'react';

const TechOverview = () => {
  return (
    <section id="tech" className="py-40 bg-lambo-black border-t border-lambo-charcoal/30 relative overflow-hidden">
      {/* Structural accent line */}
      <div className="absolute top-0 left-0 w-full h-[1px] bg-gradient-to-r from-transparent via-lambo-gold/20 to-transparent"></div>

      <div className="container mx-auto px-5 md:px-10 relative z-10 max-w-screen-lg">
        <div className="flex flex-col lg:flex-row gap-12 md:gap-24 items-start">
          {/* Text column */}
          <div className="lg:w-1/2">
            <div className="flex items-center gap-4 mb-6">
              <div className="w-8 h-[1px] bg-lambo-gold"></div>
              <span className="text-[9px] md:text-[10px] font-black text-lambo-gold tracking-[0.3em] uppercase">THE ARCHITECTURE</span>
            </div>
            <h2 className="text-[48px] md:text-[64px] mb-6 md:mb-8 uppercase text-lambo-white tracking-tighter leading-[0.9]">
              AUTONOMOUS <br /> <span className="text-lambo-white/40 italic">NEURAL</span> <br /> ORCHESTRATION.
            </h2>
            <p className="text-base md:text-lg text-lambo-ash max-w-lg uppercase tracking-wider mb-6 md:mb-8">
              AETHER is a stateful decision engine. By fusing agentic reasoning loops with a high‑performance interaction layer, we achieve human‑grade penetration testing with mathematical consistency.
            </p>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-8 gap-y-6">
              {[{ label: "State Management", value: "LangGraph / Python", detail: "Stateful Reasoning" },
                { label: "Inference Layer", value: "Gemini 1.5 Pro", detail: "Payload Logic" },
                { label: "Interaction Engine", value: "FastAPI / Playwright", detail: "DOM Simulation" },
                { label: "Storage Fabric", value: "Supabase", detail: "Encryption" }].map((item, i) => (
                <div key={i} className="group border-l border-lambo-gold/20 pl-4 hover:border-lambo-gold transition-colors duration-300">
                  <h4 className="text-lambo-white text-xs mb-1 font-bold uppercase tracking-widest group-hover:text-lambo-gold">{item.label}</h4>
                  <p className="text-sm text-lambo-ash font-bold uppercase tracking-tight mb-0">{item.value}</p>
                  <p className="text-[9px] text-lambo-ash/50 uppercase tracking-wider">{item.detail}</p>
                </div>
              ))}
            </div>
          </div>

          {/* Visual column */}
          <div className="lg:w-1/2 w-full">
            <div className="aspect-[4/3] bg-lambo-charcoal/10 border border-lambo-charcoal/30 flex items-center justify-center">
              {/* Simplified blueprint visual */}
              <svg className="w-3/4 h-3/4 opacity-20" viewBox="0 0 400 300">
                <path d="M50 50 L350 50 L350 250 L50 250 Z" fill="none" stroke="currentColor" strokeWidth="0.5" className="text-lambo-gold" />
                <path d="M50 150 L350 150 M200 50 L200 250" fill="none" stroke="currentColor" strokeWidth="0.5" className="text-lambo-gold/40" />
                <circle cx="200" cy="150" r="40" fill="none" stroke="currentColor" strokeWidth="1" className="text-lambo-gold" />
              </svg>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
};

export default TechOverview;
