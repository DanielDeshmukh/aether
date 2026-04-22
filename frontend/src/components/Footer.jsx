import React from 'react';
import logo from '/images/logo.png';

const Footer = () => {
  return (
    <footer className="py-24 bg-lambo-black border-t border-lambo-charcoal/30 px-10 relative overflow-hidden">
      <div className="absolute bottom-0 left-1/2 -translate-x-1/2 w-full h-[1px] bg-gradient-to-r from-transparent via-lambo-gold/20 to-transparent"></div>
      
      <div className="max-w-[1200px] mx-auto relative z-10">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-16 mb-20">
          <div className="md:col-span-2">
            <div className="flex items-center gap-3 mb-8">
              <div className="w-10 h-9 bg-lambo-black">
                <img src={logo} alt="AETHER" />
              </div>
              <span className="text-2xl font-bold tracking-[0.3em] text-lambo-white uppercase">AETHER</span>
            </div>
            <p className="text-[10px] text-lambo-ash tracking-[0.25em] uppercase leading-relaxed max-w-sm">
              Automated Ethical Testing & Heuristic Evaluation Routine. <br />
              Redefining the standards of autonomous security.
            </p>
          </div>

          <div className="flex flex-col gap-6">
            <h4 className="text-[10px] font-bold tracking-[0.3em] text-lambo-white uppercase">Platform</h4>
            <div className="flex flex-col gap-4 text-[10px] tracking-[0.2em] text-lambo-ash uppercase font-bold">
              <a href="#capabilities" className="hover:text-lambo-gold transition-colors">Capabilities</a>
              <a href="#tech" className="hover:text-lambo-gold transition-colors">Technology</a>
              <a href="#why" className="hover:text-lambo-gold transition-colors">Impact</a>
            </div>
          </div>

          <div className="flex flex-col gap-6">
            <h4 className="text-[10px] font-bold tracking-[0.3em] text-lambo-white uppercase">Contact</h4>
            <div className="flex flex-col gap-4 text-[10px] tracking-[0.2em] text-lambo-ash uppercase font-bold">
              <a href="#" className="hover:text-lambo-white transition-colors">Security</a>
              <a href="#" className="hover:text-lambo-white transition-colors">Legal</a>
              <a href="#" className="hover:text-lambo-white transition-colors text-lambo-gold">Join Us</a>
            </div>
          </div>
        </div>

        <div className="pt-10 border-t border-lambo-charcoal/20 flex flex-col md:flex-row justify-between items-center gap-6">
          <p className="text-[9px] text-lambo-ash tracking-[0.2em] uppercase">
            © 2026 AETHER PLATFORM // ALL RIGHTS RESERVED
          </p>
          <div className="flex items-center gap-4">
            <span className="text-[9px] text-lambo-ash tracking-[0.2em] uppercase">Built for Dominance</span>
            <div className="w-1 h-1 bg-lambo-gold rounded-full"></div>
            <span className="text-[9px] text-lambo-gold tracking-[0.3em] uppercase font-bold">
              Designed by Daniel Deshmukh
            </span>
          </div>
        </div>
      </div>
    </footer>
  );
};

export default Footer;
