"use client";

import { Suspense, useEffect } from "react";
import { useRouter, useSearchParams } from "next/navigation";

function CallbackHandler() {
  const router = useRouter();
  const searchParams = useSearchParams();

  useEffect(() => {
    const accessToken = searchParams.get("access_token");
    const refreshToken = searchParams.get("refresh_token");

    if (accessToken && refreshToken) {
      document.cookie = `access_token=${accessToken}; path=/; max-age=3600; SameSite=Lax${window.location.protocol === "https:" ? "; Secure" : ""}`;
      document.cookie = `refresh_token=${refreshToken}; path=/; max-age=604800; SameSite=Lax${window.location.protocol === "https:" ? "; Secure" : ""}`;
      router.replace("/home");
    } else {
      router.replace("/");
    }
  }, [searchParams, router]);

  return (
    <div className="min-h-screen flex items-center justify-center bg-aether-black">
      <div className="text-white/30 text-sm">Signing you in...</div>
    </div>
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
