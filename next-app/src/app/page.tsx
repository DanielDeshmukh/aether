"use client";

import Link from "next/link";

export default function LandingPage() {
  return (
    <div className="min-h-screen bg-aether-black text-white">
      <nav className="flex items-center justify-between px-8 py-5 border-b border-white/5">
        <Link href="/" className="flex items-center gap-3">
          <div className="w-8 h-8 rounded bg-aether-gold flex items-center justify-center text-black font-bold text-sm">
            A
          </div>
          <span className="text-lg font-semibold tracking-tight">AETHER</span>
        </Link>
        <div className="flex items-center gap-6 text-sm text-white/60">
          <Link href="/security" className="hover:text-white transition-colors">
            Security
          </Link>
          <Link href="/legal" className="hover:text-white transition-colors">
            Legal
          </Link>
          <Link
            href="/home"
            className="px-4 py-2 bg-aether-gold text-black font-semibold rounded chamfer-button hover:bg-aether-gold-deep transition-colors"
          >
            Launch
          </Link>
        </div>
      </nav>

      <main className="flex flex-col items-center justify-center px-8 pt-32 pb-24 text-center">
        <div className="chamfer-badge inline-block px-4 py-1.5 bg-aether-gold/10 border border-aether-gold/20 text-aether-gold text-xs font-medium mb-8">
          Simulating human-expert logic for autonomous penetration testing
        </div>

        <h1 className="text-5xl md:text-7xl font-bold tracking-tight leading-tight max-w-4xl">
          <span className="text-aether-gold">AETHER</span>
          <br />
          <span className="text-white/90">Automated Ethical Testing</span>
          <br />
          <span className="text-white/60 text-4xl md:text-5xl">
            & Heuristic Evaluation Routine
          </span>
        </h1>

        <p className="mt-8 text-white/50 text-lg max-w-2xl leading-relaxed">
          AETHER doesn&apos;t just scan. It thinks, plans, executes, and validates
          exploits against live targets using AI-powered reasoning, then generates
          production-ready remediation patches.
        </p>

        <div className="mt-12 flex items-center gap-4">
          <Link
            href="/home"
            className="px-8 py-3.5 bg-aether-gold text-black font-semibold rounded chamfer-button hover:bg-aether-gold-deep transition-colors text-sm"
          >
            Start Scanning
          </Link>
          <Link
            href="/security"
            className="px-8 py-3.5 border border-white/10 text-white/70 font-medium rounded chamfer-button hover:border-white/20 hover:text-white transition-colors text-sm"
          >
            How It Works
          </Link>
        </div>

        <div className="mt-20 grid grid-cols-3 gap-12 text-center max-w-2xl">
          <div>
            <div className="text-2xl font-bold text-aether-gold">10</div>
            <div className="text-xs text-white/40 mt-1">OWASP Categories</div>
          </div>
          <div>
            <div className="text-2xl font-bold text-aether-gold">5</div>
            <div className="text-xs text-white/40 mt-1">AI Models</div>
          </div>
          <div>
            <div className="text-2xl font-bold text-aether-gold">7</div>
            <div className="text-xs text-white/40 mt-1">Pipeline Stages</div>
          </div>
        </div>
      </main>

      <footer className="border-t border-white/5 py-8 px-8 text-center text-xs text-white/30">
        AETHER &copy; {new Date().getFullYear()} &mdash; Built by Daniel S. Deshmukh
      </footer>
    </div>
  );
}
