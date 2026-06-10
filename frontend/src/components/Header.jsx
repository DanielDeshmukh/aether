import React, { useState } from 'react';
import { Link, NavLink, useNavigate } from 'react-router-dom';
import Logo from '/images/logo.png';
import { auth } from '../lib/auth';

const Header = () => {
  const navigate = useNavigate();
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);

  const handleSignOut = () => {
    auth.clearTokens();
    navigate('/join-us', { replace: true });
  };

  return (
    <nav className="fixed top-0 z-50 flex w-full items-center justify-between border-b border-white/5 bg-[#050505]/90 px-6 py-5 backdrop-blur-md md:px-10">
      <Link to="/home" className="group flex items-center gap-4">
        <img src={Logo} alt="Logo" className="h-9 w-10 bg-black" />
        <div className="text-2xl font-bold tracking-[0.3em] text-white">
          <span>AETHER</span>
        </div>
      </Link>

      {/* Desktop Navigation */}
      <div className="hidden items-center gap-3 md:flex md:gap-6">
        <div className="flex items-center gap-2 border border-[rgba(0,255,65,0.28)] bg-[rgba(0,255,65,0.08)] px-3 py-2 text-[9px] font-black tracking-[0.24em] text-[#00ff41]">
          <span className="h-2 w-2 rounded-full bg-[#00ff41] animate-pulse" />
          MVP
        </div>
        <NavLink
          to="/home"
          className={({ isActive }) =>
            `chamfer-button border px-4 py-3 text-[10px] font-black tracking-[0.28em] transition-colors ${
              isActive
                ? 'border-lambo-gold bg-lambo-gold/10 text-lambo-gold'
                : 'border-white/10 bg-white/[0.02] text-lambo-ash hover:border-lambo-gold/40 hover:text-lambo-gold'
            }`
          }
        >
          Home
        </NavLink>
        <NavLink
          to="/dashboard"
          className={({ isActive }) =>
            `chamfer-button border px-4 py-3 text-[10px] font-black tracking-[0.28em] transition-colors ${
              isActive
                ? 'border-lambo-gold bg-lambo-gold/10 text-lambo-gold'
                : 'border-white/10 bg-white/[0.02] text-lambo-ash hover:border-lambo-gold/40 hover:text-lambo-gold'
            }`
          }
        >
          Dashboard
        </NavLink>
        <button
          type="button"
          onClick={handleSignOut}
          className="chamfer-button border border-[rgba(255,255,255,0.1)] bg-transparent px-4 py-3 text-[10px] font-black tracking-[0.28em] text-[#8f8a78] transition-colors hover:border-[rgba(255,0,0,0.4)] hover:text-[#ff0000]"
        >
          Exit
        </button>
      </div>

      {/* Mobile Menu Button */}
      <button
        type="button"
        onClick={() => setIsMobileMenuOpen(!isMobileMenuOpen)}
        className="flex flex-col gap-1.5 md:hidden"
        aria-label="Toggle menu"
      >
        <span className={`h-0.5 w-6 bg-lambo-gold transition-transform ${isMobileMenuOpen ? 'rotate-45 translate-y-2' : ''}`} />
        <span className={`h-0.5 w-6 bg-lambo-gold transition-opacity ${isMobileMenuOpen ? 'opacity-0' : ''}`} />
        <span className={`h-0.5 w-6 bg-lambo-gold transition-transform ${isMobileMenuOpen ? '-rotate-45 -translate-y-2' : ''}`} />
      </button>

      {/* Mobile Navigation */}
      {isMobileMenuOpen && (
        <div className="absolute left-0 top-full flex w-full flex-col gap-4 border-b border-white/5 bg-[#050505]/95 p-6 backdrop-blur-md md:hidden">
          <div className="flex items-center gap-2 border border-[rgba(0,255,65,0.28)] bg-[rgba(0,255,65,0.08)] px-3 py-2 text-[9px] font-black tracking-[0.24em] text-[#00ff41] w-fit">
            <span className="h-2 w-2 rounded-full bg-[#00ff41] animate-pulse" />
            MVP
          </div>
          <NavLink
            to="/home"
            onClick={() => setIsMobileMenuOpen(false)}
            className={({ isActive }) =>
              `chamfer-button border px-4 py-3 text-[10px] font-black tracking-[0.28em] transition-colors ${
                isActive
                  ? 'border-lambo-gold bg-lambo-gold/10 text-lambo-gold'
                  : 'border-white/10 bg-white/[0.02] text-lambo-ash hover:border-lambo-gold/40 hover:text-lambo-gold'
              }`
            }
          >
            Home
          </NavLink>
          <NavLink
            to="/dashboard"
            onClick={() => setIsMobileMenuOpen(false)}
            className={({ isActive }) =>
              `chamfer-button border px-4 py-3 text-[10px] font-black tracking-[0.28em] transition-colors ${
                isActive
                  ? 'border-lambo-gold bg-lambo-gold/10 text-lambo-gold'
                  : 'border-white/10 bg-white/[0.02] text-lambo-ash hover:border-lambo-gold/40 hover:text-lambo-gold'
              }`
            }
          >
            Dashboard
          </NavLink>
          <button
            type="button"
            onClick={() => {
              setIsMobileMenuOpen(false);
              handleSignOut();
            }}
            className="chamfer-button border border-[rgba(255,255,255,0.1)] bg-transparent px-4 py-3 text-[10px] font-black tracking-[0.28em] text-[#8f8a78] transition-colors hover:border-[rgba(255,0,0,0.4)] hover:text-[#ff0000]"
          >
            Exit
          </button>
        </div>
      )}
    </nav>
  );
};

export default Header;