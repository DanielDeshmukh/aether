"use client";

import { Suspense, useEffect } from "react";
import { useRouter, useSearchParams } from "next/navigation";

function CallbackHandler() {
  const router = useRouter();
  const searchParams = useSearchParams();

  useEffect(() => {
    const accessToken = searchParams.get("access_token");
    const refreshToken = searchParams.get("refresh_token");
    const error = searchParams.get("error");

    const secure = window.location.protocol === "https:" ? "; Secure" : "";

    if (error) {
      setTimeout(() => router.replace("/join-us"), 2000);
      return;
    }

    if (accessToken) {
      document.cookie = `access_token=${accessToken}; path=/; max-age=3600; SameSite=Lax${secure}`;
      if (refreshToken) {
        document.cookie = `refresh_token=${refreshToken}; path=/; max-age=604800; SameSite=Lax${secure}`;
      }
      setTimeout(() => router.replace("/home"), 500);
      return;
    }

    setTimeout(() => router.replace("/join-us"), 2000);
  }, [searchParams, router]);

  const hasError = searchParams.get("error");
  const hasToken = searchParams.get("access_token");
  const status = hasError ? "Authentication failed. Please try again." : hasToken ? "Access granted. Redirecting..." : "Invalid authentication response.";

  return (
    <section className="min-h-screen bg-lambo-black flex items-center justify-center px-5 font-mono">
      <div className="text-center">
        <div className="flex justify-center items-center gap-3 mb-6">
          <div className="w-10 h-[1px] bg-lambo-gold"></div>
          <span className="text-[10px] text-lambo-gold tracking-[0.4em] uppercase font-black">AETHER</span>
          <div className="w-10 h-[1px] bg-lambo-gold"></div>
        </div>
        <div className="flex items-center justify-center gap-3 mb-6">
          <div className="w-3 h-3 border-2 border-lambo-gold/30 border-t-lambo-gold rounded-full animate-spin" />
          <p className="text-lambo-ash text-xs uppercase tracking-widest">{status}</p>
        </div>
      </div>
    </section>
  );
}

export default function AuthCallbackPage() {
  return (
    <Suspense fallback={
      <div className="min-h-screen flex items-center justify-center bg-aether-black">
        <div className="text-white/30 text-sm">Signing you in...</div>
      </div>
    }>
      <CallbackHandler />
    </Suspense>
  );
}
