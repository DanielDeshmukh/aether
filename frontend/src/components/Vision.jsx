import React from 'react';

const Vision = () => {
  return (
    <section id="vision" className="relative py-48 bg-lambo-black flex items-center justify-center text-center px-10 overflow-hidden">
      <div className="absolute top-0 left-0 w-full h-[1px] bg-gradient-to-r from-transparent via-lambo-charcoal to-transparent"></div>
      <div className="absolute bottom-0 left-0 w-full h-[1px] bg-gradient-to-r from-transparent via-lambo-charcoal to-transparent"></div>
      
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-full h-full bg-[radial-gradient(circle_at_center,rgba(255,192,0,0.02)_0%,transparent_70%)] pointer-events-none"></div>

      <div className="max-w-[1000px] relative z-10">
        <div className="text-[10px] text-lambo-gold font-bold tracking-[0.5em] uppercase mb-12 opacity-80">
          Our Vision // The Autonomous Frontier
        </div>
        
        <h2 className="text-[clamp(2.5rem,8vw,6rem)] mb-12 uppercase text-lambo-white leading-[0.9] tracking-tighter">
          THE FUTURE IS <br /> <span className="text-lambo-white/40">INTELLIGENT &</span> <br /> <span className="text-lambo-gold">ADAPTIVE.</span>
        </h2>
        
        <p className="text-xl md:text-2xl text-lambo-ash uppercase tracking-[0.2em] leading-relaxed mb-16 font-light">
          AETHER represents an advanced approach to security testing. We simulate the <span className="text-lambo-white">reasoning process</span> of a human expert while maintaining the <span className="text-lambo-white">scalability</span> of modern SaaS systems.
        </p>
        
        <div className="flex justify-center gap-2 items-center">
          <div className="w-12 h-[1px] bg-lambo-gold/40"></div>
          <div className="w-2 h-2 border border-lambo-gold rotate-45"></div>
          <div className="w-12 h-[1px] bg-lambo-gold/40"></div>
        </div>
      </div>
    </section>
  );
};

export default Vision;
