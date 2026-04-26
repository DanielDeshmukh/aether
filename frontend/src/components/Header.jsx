import React from 'react';
import { Link, NavLink, useNavigate } from 'react-router-dom';
import Logo from '/images/logo.png';
import { supabase } from '../lib/supabaseClient';

const Header = () => {
  const navigate = useNavigate();

  const handleSignOut = async () => {
    await supabase.auth.signOut();
    navigate('/join-us', { replace: true });
  };

  return (
    <nav className="fixed top-0 z-50 flex w-full items-center justify-between border-b border-white/5 bg-black/90 px-6 py-5 backdrop-blur-md md:px-10">
      <Link to="/home" className="group flex items-center gap-4">
        <img src={Logo} alt="Logo" className="h-9 w-10 bg-black" />
        <div className="text-2xl font-bold tracking-[0.3em] text-white">
          <span>AETHER</span>
        </div>
      </Link>

      <div className="flex items-center gap-3 md:gap-6">
        <div className="hidden items-center gap-2 border border-[rgba(0,255,65,0.28)] bg-[rgba(0,255,65,0.08)] px-3 py-2 text-[9px] font-black uppercase tracking-[0.24em] text-[#00ff41] md:flex">
          <span className="h-2 w-2 rounded-full bg-[#00ff41] animate-pulse" />
          Production Ready
        </div>
        <NavLink
          to="/home"
          className={({ isActive }) =>
            `chamfer-button border px-4 py-3 text-[10px] font-black uppercase tracking-[0.28em] transition-colors ${
              isActive
                ? 'border-[#d4af37] bg-[rgba(212,175,55,0.12)] text-[#d4af37]'
                : 'border-white/10 bg-white/[0.02] text-[#8f8a78] hover:border-[#d4af37]/40 hover:text-[#d4af37]'
            }`
          }
        >
          Home
        </NavLink>
        <NavLink
          to="/dashboard"
          className={({ isActive }) =>
            `chamfer-button border px-4 py-3 text-[10px] font-black uppercase tracking-[0.28em] transition-colors ${
              isActive
                ? 'border-[#d4af37] bg-[rgba(212,175,55,0.12)] text-[#d4af37]'
                : 'border-white/10 bg-white/[0.02] text-[#8f8a78] hover:border-[#d4af37]/40 hover:text-[#d4af37]'
            }`
          }
        >
          Dashboard
        </NavLink>
        <button
          type="button"
          onClick={handleSignOut}
          className="chamfer-button hidden border border-[rgba(255,255,255,0.1)] bg-transparent px-4 py-3 text-[10px] font-black uppercase tracking-[0.28em] text-[#8f8a78] transition-colors hover:border-[rgba(255,0,0,0.4)] hover:text-[#ff0000] md:block"
        >
          Exit
        </button>
      </div>
    </nav>
  );
};

export default Header;
