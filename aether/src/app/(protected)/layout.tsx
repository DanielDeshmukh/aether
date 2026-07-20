"use client";

import { AuthProvider } from "@/lib/auth-context";
import Header from "@/components/Header";

export default function ProtectedLayout({ children }: { children: React.ReactNode }) {
  return (
    <AuthProvider>
      <div className="min-h-screen bg-aether-black font-mono">
        <Header />
        {children}
      </div>
    </AuthProvider>
  );
}
