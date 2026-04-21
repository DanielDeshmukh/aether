import React from 'react';

const CapabilityCard = ({ title, description }) => (
  <div className="bg-lambo-charcoal p-8 border-b-2 border-transparent hover:border-lambo-gold transition-all duration-300 flex flex-col justify-between min-h-[300px] relative group overflow-hidden">
    {/* Subtle hover glow */}
    <div className="absolute inset-0 bg-lambo-gold opacity-0 group-hover:opacity-[0.03] transition-opacity duration-300"></div>
    <div className="relative z-10">
      <div className="w-6 h-[1px] bg-lambo-gold mb-6"></div>
      <h3 className="text-2xl text-lambo-white mb-4 uppercase tracking-tight leading-tight">{title}</h3>
      <p className="text-base text-lambo-ash leading-relaxed group-hover:text-lambo-white/80 transition-colors duration-300">{description}</p>
    </div>
    <div className="relative z-10 mt-6 text-[9px] font-bold text-lambo-gold uppercase opacity-0 group-hover:opacity-100 transition-opacity duration-300">
      Protocol // {title.slice(0, 3).toUpperCase()}
    </div>
  </div>
);

const Capabilities = () => {
  const features = [
    {
      title: "AGENTIC REASONING",
      description: "Moving beyond static payloads. AETHER observes application behavior and formulates hypotheses to discover complex attack surfaces."
    },
    {
      title: "THREAT FEED",
      description: "Real-time visibility into ongoing testing activities. Watch as the agent identifies potential vectors and executes context-aware exploits."
    },
    {
      title: "CUSTOM PAYLOADS",
      description: "Advanced guidance system for precision targeting. Refine attack strategies with algorithmically generated payloads tailored to specific technologies."
    },
    {
      title: "AUTO-REMEDIATION",
      description: "Actionable guidance and automated pull requests. Receive detailed root cause analysis and suggested fixes for every vulnerability."
    }
  ];

  return (
    <section id="capabilities" className="py-32 bg-lambo-black border-t border-lambo-charcoal/50">
      <div className="max-w-[1200px] mx-auto px-5 md:px-10">
        <div className="flex flex-col md:flex-row justify-between items-end mb-20 gap-8">
          <div className="max-w-2xl">
            <h2 className="text-[48px] md:text-[54px] uppercase text-lambo-white tracking-tighter leading-none mb-6">CORE <br />CAPABILITIES</h2>
            <p className="text-lambo-ash uppercase tracking-[0.2em] text-xs">Engineered for absolute dominance</p>
          </div>
          <div className="h-[1px] flex-grow bg-lambo-charcoal hidden md:block mb-4 ml-10"></div>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-[1px] bg-lambo-charcoal/30 border border-lambo-charcoal/30">
          {features.map((f, i) => (
            <CapabilityCard key={i} title={f.title} description={f.description} />
          ))}
        </div>
      </div>
    </section>
  );
};

export default Capabilities;
