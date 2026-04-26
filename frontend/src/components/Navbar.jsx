import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import Logo from '/images/logo.png';

const Navbar = () => {
  const location = useLocation();
  const isLandingPage = location.pathname === '/';

  const sectionLinks = [
    { href: '/#capabilities', label: 'Capabilities' },
    { href: '/#tech', label: 'Technology' },
    { href: '/#why', label: 'Impact' },
    { href: '/#vision', label: 'Vision' },
  ];

  return (
    <nav className="fixed top-0 z-50 flex w-full items-center justify-between border-b border-white/5 bg-black/80 px-10 py-6 backdrop-blur-md">
      <Link to="/" className="flex items-center gap-4 group cursor-pointer">
        <img src={Logo} alt="Logo" className="w-10 h-9 bg-lambo-black " />
        <div className="text-2xl font-bold tracking-[0.3em] "><span className="">AETHER</span></div>
      </Link>
      
      <div className="hidden lg:flex gap-12 text-[10px] font-bold tracking-[0.25em] text-lambo-ash uppercase">
        {isLandingPage &&
          sectionLinks.map((link) => (
            <a key={link.label} href={link.href} className="relative group transition-all hover:text-[#d4af37]">
              {link.label}
              <span className="absolute -bottom-2 left-0 h-[1px] w-0 bg-[#d4af37] transition-all group-hover:w-full"></span>
            </a>
          ))}
        <Link to="/join-us" className="relative group transition-all hover:text-[#d4af37]">
          Login
          <span className="absolute -bottom-2 left-0 h-[1px] w-0 bg-[#d4af37] transition-all group-hover:w-full"></span>
        </Link>
      </div>

      
    </nav>
  );
};

export default Navbar;
