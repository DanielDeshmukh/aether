import React from 'react';
import Logo from '/images/logo.png'

const Navbar = () => {
  return (
    <nav className="fixed top-0 w-full z-50 flex justify-between items-center px-10 py-8 bg-lambo-black/80 backdrop-blur-md border-b border-lambo-white/5">
      <div className="flex items-center gap-4 group cursor-pointer">
        <img src={Logo} alt="Logo" className="w-10 h-9 bg-lambo-black " />
        <div className="text-2xl font-bold tracking-[0.3em] "><span className="">AETHER</span></div>
      </div>
      
      <div className="hidden lg:flex gap-12 text-[10px] font-bold tracking-[0.25em] text-lambo-ash uppercase">
        <a href="#capabilities" className="hover:text-lambo-gold transition-all relative group">
          Capabilities
          <span className="absolute -bottom-2 left-0 w-0 h-[1px] bg-lambo-gold transition-all group-hover:w-full"></span>
        </a>
        <a href="#tech" className="hover:text-lambo-gold transition-all relative group">
          Technology
          <span className="absolute -bottom-2 left-0 w-0 h-[1px] bg-lambo-gold transition-all group-hover:w-full"></span>
        </a>
        <a href="#why" className="hover:text-lambo-gold transition-all relative group">
          Impact
          <span className="absolute -bottom-2 left-0 w-0 h-[1px] bg-lambo-gold transition-all group-hover:w-full"></span>
        </a>
        <a href="#vision" className="hover:text-lambo-gold transition-all relative group">
          Vision
          <span className="absolute -bottom-2 left-0 w-0 h-[1px] bg-lambo-gold transition-all group-hover:w-full"></span>
        </a>
      </div>

      <button className="text-[10px] font-bold tracking-[0.2em] text-lambo-black bg-lambo-white px-6 py-2 uppercase hover:bg-lambo-gold transition-colors duration-300">
        Access Portal
      </button>
    </nav>
  );
};

export default Navbar;
