import React from 'react';
import Logo from '/images/logo.png'

const Header = () => {
  return (
    <nav className="fixed top-0 w-full z-50 flex justify-between items-center px-10 py-6 bg-lambo-black/80 backdrop-blur-md border-b border-lambo-white/5">
      <div className="flex items-center gap-4 group cursor-pointer">
        <img src={Logo} alt="Logo" className="w-10 h-9 bg-lambo-black " />
        <div className="text-2xl font-bold tracking-[0.3em] "><span className="">AETHER</span></div>
      </div>
      
      

      
    </nav>
  );
};

export default Header;
