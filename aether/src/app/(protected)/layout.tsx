"use client";

import { AuthProvider } from "@/lib/auth-context";
import Link from "next/link";
import { usePathname } from "next/navigation";

const navLinks = [
  { href: "/home", label: "New Scan" },
  { href: "/dashboard", label: "Dashboard" },
  { href: "/settings", label: "Settings" },
];

export default function ProtectedLayout({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();

  return (
    <AuthProvider>
      <div className="min-h-screen bg-aether-black text-white flex">
        <aside className="w-56 border-r border-white/5 flex flex-col">
          <div className="px-5 py-5 border-b border-white/5">
            <Link href="/" className="flex items-center gap-2">
              <div className="w-7 h-7 rounded bg-aether-gold flex items-center justify-center text-black font-bold text-xs">A</div>
              <span className="text-sm font-semibold">AETHER</span>
            </Link>
          </div>
          <nav className="flex-1 px-3 py-4 space-y-1">
            {navLinks.map((link) => (
              <Link
                key={link.href}
                href={link.href}
                className={`block px-3 py-2 rounded text-sm transition-colors ${
                  pathname === link.href
                    ? "bg-white/5 text-aether-gold"
                    : "text-white/50 hover:text-white hover:bg-white/[0.03]"
                }`}
              >
                {link.label}
              </Link>
            ))}
          </nav>
        </aside>
        <main className="flex-1 overflow-y-auto">{children}</main>
      </div>
    </AuthProvider>
  );
}
