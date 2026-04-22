import React from 'react';

const TechOverview = () => {
  return (
    <section id="tech" className="py-40 bg-lambo-black border-t border-lambo-charcoal/30 relative overflow-hidden">
      {/* Top Gradient Line */}
      <div className="absolute top-0 left-0 w-full h-[1px] bg-gradient-to-r from-transparent via-lambo-gold/20 to-transparent"></div>

      <div className="container mx-auto px-5 md:px-10 relative z-10 max-w-screen-lg">
        <div className="flex flex-col lg:flex-row gap-12 md:gap-24 items-start">
          
          {/* Left Column: Text Content */}
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
              {[
                { label: "Orchestrator", value: "LangGraph / Python", detail: "Decision Engine" },
                { label: "Intelligence", value: "Gemini 1.5 Pro", detail: "Payload Generation" },
                { label: "Testing Engine", value: "FastAPI / Playwright", detail: "Execution Layer" },
                { label: "Infrastructure", value: "Supabase / React", detail: "SaaS Management" }
              ].map((item, i) => (
                <div key={i} className="group border-l border-lambo-gold/20 pl-4 hover:border-lambo-gold transition-colors duration-300">
                  <h4 className="text-lambo-white text-xs mb-1 font-bold uppercase tracking-widest group-hover:text-lambo-gold">{item.label}</h4>
                  <p className="text-sm text-lambo-ash font-bold uppercase tracking-tight mb-0">{item.value}</p>
                  <p className="text-[9px] text-lambo-ash/50 uppercase tracking-wider">{item.detail}</p>
                </div>
              ))}
            </div>
          </div>

          {/* Right Column: Radar Visualization */}
          <div className="lg:w-1/2 w-full">
            <div className="aspect-square bg-[#0c0c0d] border border-[#d4af37]/30 flex items-center justify-center relative overflow-hidden group font-mono rounded-3xl">
              
              <svg className="w-[85%] h-[85%]" viewBox="0 0 400 400">
                <defs>
                  {/* Bloom/Glow Filter */}
                  <filter id="bloom">
                    <feGaussianBlur stdDeviation="3" result="coloredBlur"/>
                    <feMerge>
                      <feMergeNode in="coloredBlur"/>
                      <feMergeNode in="SourceGraphic"/>
                    </feMerge>
                  </filter>

                  {/* Radar Grid Pattern */}
                  <pattern id="radar-grid" width="400" height="400" patternUnits="userSpaceOnUse">
                    {[...Array(9)].map((_, i) => (
                      <circle 
                        key={i} 
                        cx="200" 
                        cy="200" 
                        r={(i + 1) * 20} 
                        fill="none" 
                        stroke="#d4af37" 
                        strokeWidth="0.4" 
                        opacity="0.25" 
                      />
                    ))}
                    {[...Array(12)].map((_, i) => (
                      <line 
                        key={i} 
                        x1="200" y1="200" x2="200" y2="10" 
                        stroke="#d4af37" strokeWidth="0.4" opacity="0.1" 
                        transform={`rotate(${i * 30} 200 200)`} 
                      />
                    ))}
                  </pattern>
                </defs>
                
                {/* Main Radar Background */}
                <circle cx="200" cy="200" r="180" fill="url(#radar-grid)" />
                
                {/* Outer Bezel Tick Marks */}
                {[...Array(60)].map((_, i) => {
                  const isMajor = i % 5 === 0;
                  return (
                    <line 
                      key={i}
                      x1="200" y1={isMajor ? "5" : "10"} x2="200" y2={isMajor ? "15" : "12"}
                      stroke={isMajor ? "#d4af37" : "rgba(212,175,55,0.5)"} 
                      strokeWidth={isMajor ? "1.5" : "0.5"}
                      transform={`rotate(${i * 6} 200 200)`}
                    />
                  );
                })}

                {/* Center Lock Point */}
                <circle cx="200" cy="200" r="3.5" fill="#d4af37" filter="url(#bloom)" />

                {/* Animated Radar Sweep */}
                <g filter="url(#bloom)" className="origin-center"
                   style={{ animation: 'radar-sweep 6s linear infinite' }}>
                  <line x1="200" y1="200" x2="380" y2="200" stroke="#d4af37" strokeWidth="2" opacity="0.6"/>
                  <path d="M 200 200 L 380 200 A 180 180 0 0 0 373.2 143.5 Z" 
                        fill="rgba(212,175,55,0.4)" fillOpacity="0.4"/>
                </g>

                {/* Detected Vulnerability Pings */}
                <g filter="url(#bloom)" fill="#d4af37" className="animate-pulse">
                  <circle cx="280" cy="110" r="4.5"/>
                  <text x="290" y="113" fontSize="8" className="tracking-tight uppercase">VULN_01: HIGH</text>

                  <circle cx="120" cy="180" r="4.5"/>
                  <text x="130" y="183" fontSize="8" className="tracking-tight uppercase">VULN_02: CRIT</text>

                  <circle cx="210" cy="290" r="4.5"/>
                  <text x="220" y="293" fontSize="8" className="tracking-tight uppercase">VULN_03: MED</text>
                  
                  {/* Static Data Points */}
                  <circle cx="180" cy="80" r="2.5" opacity="0.6"/>
                  <circle cx="320" cy="230" r="2.5" opacity="0.6"/>
                  <circle cx="70" cy="240" r="2.5" opacity="0.6"/>
                </g>
              </svg>

              {/* Animation Keyframes */}
              <style jsx global>{`
                @keyframes radar-sweep {
                  from { transform: rotate(0deg); }
                  to { transform: rotate(360deg); }
                }
              `}</style>
            </div>
          </div>

        </div>
      </div>
    </section>
  );
};

export default TechOverview;