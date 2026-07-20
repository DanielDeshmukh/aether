"use client";

import { useState, useEffect } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";

const sectionLinks = [
  { href: "/#capabilities", label: "Capabilities" },
  { href: "/#tech", label: "Technology" },
  { href: "/#why", label: "Impact" },
  { href: "/#vision", label: "Vision" },
];

function hasAccessToken(): boolean {
  if (typeof document === "undefined") return false;
  return /(?:^|;\s*)access_token=([^;]+)/.test(document.cookie);
}

export default function Navbar() {
  const pathname = usePathname();
  const isLandingPage = pathname === "/";
  const [mobileOpen, setMobileOpen] = useState(false);
  const [isLoggedIn, setIsLoggedIn] = useState(false);

  useEffect(() => {
    setIsLoggedIn(hasAccessToken());
    const interval = setInterval(() => setIsLoggedIn(hasAccessToken()), 2000);
    return () => clearInterval(interval);
  }, []);

  return (
    <nav className="fixed top-0 z-50 flex w-full items-center justify-between border-b border-white/5 bg-black/80 px-5 md:px-10 py-6 backdrop-blur-md">
      <Link href={isLoggedIn ? "/home" : "/"} className="flex items-center gap-4 group cursor-pointer">
        <img src="/images/logo.png" alt="Logo" className="w-10 h-9 bg-lambo-black" />
        <div className="text-2xl font-bold tracking-[0.3em]"><span>AETHER</span></div>
      </Link>

      <div className="hidden lg:flex gap-12 text-[10px] font-bold tracking-[0.25em] text-lambo-ash uppercase">
        {isLandingPage &&
          sectionLinks.map((link) => (
            <a key={link.label} href={link.href} className="relative group transition-all hover:text-[#d4af37]">
              {link.label}
              <span className="absolute -bottom-2 left-0 h-[1px] w-0 bg-[#d4af37] transition-all group-hover:w-full"></span>
            </a>
          ))}
        <Link href="/security" className="relative group transition-all hover:text-[#d4af37]">
          Security
          <span className="absolute -bottom-2 left-0 h-[1px] w-0 bg-[#d4af37] transition-all group-hover:w-full"></span>
        </Link>
        <Link href="/legal" className="relative group transition-all hover:text-[#d4af37]">
          Legal
          <span className="absolute -bottom-2 left-0 h-[1px] w-0 bg-[#d4af37] transition-all group-hover:w-full"></span>
        </Link>
        {isLoggedIn ? (
          <Link href="/dashboard" className="relative group transition-all hover:text-[#d4af37]">
            Dashboard
            <span className="absolute -bottom-2 left-0 h-[1px] w-0 bg-[#d4af37] transition-all group-hover:w-full"></span>
          </Link>
        ) : (
          <Link href="/join-us" className="relative group transition-all hover:text-[#d4af37]">
            Login
            <span className="absolute -bottom-2 left-0 h-[1px] w-0 bg-[#d4af37] transition-all group-hover:w-full"></span>
          </Link>
        )}
      </div>

      <button
        className="lg:hidden flex flex-col gap-1.5 p-2"
        onClick={() => setMobileOpen(!mobileOpen)}
        aria-label="Toggle menu"
      >
        <span className={`block w-6 h-0.5 bg-white transition-transform ${mobileOpen ? "rotate-45 translate-y-2" : ""}`} />
        <span className={`block w-6 h-0.5 bg-white transition-opacity ${mobileOpen ? "opacity-0" : ""}`} />
        <span className={`block w-6 h-0.5 bg-white transition-transform ${mobileOpen ? "-rotate-45 -translate-y-2" : ""}`} />
      </button>

      {mobileOpen && (
        <div className="lg:hidden fixed inset-0 top-[72px] bg-black/95 backdrop-blur-md flex flex-col items-center gap-8 py-12 text-sm font-bold tracking-[0.2em] text-lambo-ash uppercase">
          {isLandingPage && sectionLinks.map((link) => (
            <a key={link.label} href={link.href} onClick={() => setMobileOpen(false)} className="hover:text-[#d4af37] transition-colors">
              {link.label}
            </a>
          ))}
          <Link href="/security" onClick={() => setMobileOpen(false)} className="hover:text-[#d4af37] transition-colors">
            Security
          </Link>
          <Link href="/legal" onClick={() => setMobileOpen(false)} className="hover:text-[#d4af37] transition-colors">
            Legal
          </Link>
          {isLoggedIn ? (
            <Link href="/dashboard" onClick={() => setMobileOpen(false)} className="hover:text-[#d4af37] transition-colors">
              Dashboard
            </Link>
          ) : (
            <Link href="/join-us" onClick={() => setMobileOpen(false)} className="hover:text-[#d4af37] transition-colors">
              Login
            </Link>
          )}
        </div>
      )}
    </nav>
  );
}
