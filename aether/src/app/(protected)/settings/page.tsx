"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";

export default function SettingsPage() {
  const [user, setUser] = useState<{ email: string; name: string | null } | null>(null);
  const router = useRouter();

  useEffect(() => {
    fetch("/api/v1/auth/me")
      .then((res) => res.json())
      .then((data) => setUser(data.data));
  }, []);

  const handleLogout = async () => {
    await fetch("/api/v1/auth/logout", { method: "POST" });
    router.push("/");
  };

  const handleDelete = async () => {
    if (!confirm("This will permanently delete your account and all data.")) return;
    await fetch("/api/v1/auth/account", { method: "DELETE" });
    router.push("/");
  };

  return (
    <div className="max-w-2xl mx-auto px-8 py-16 space-y-8">
      <h1 className="text-2xl font-bold">Settings</h1>

      <div className="px-5 py-4 bg-white/[0.02] border border-white/5 rounded space-y-4">
        <div>
          <div className="text-xs text-white/40 uppercase tracking-wider mb-1">Email</div>
          <div className="text-sm">{user?.email || "Loading..."}</div>
        </div>
        <div>
          <div className="text-xs text-white/40 uppercase tracking-wider mb-1">Name</div>
          <div className="text-sm">{user?.name || "Not set"}</div>
        </div>
      </div>

      <div className="space-y-3">
        <button
          onClick={handleLogout}
          className="px-4 py-2 border border-white/10 text-white/60 rounded text-sm hover:border-white/20 hover:text-white transition-colors"
        >
          Sign Out
        </button>
        <button
          onClick={handleDelete}
          className="px-4 py-2 border border-red-500/20 text-red-400 rounded text-sm hover:bg-red-500/10 transition-colors"
        >
          Delete Account
        </button>
      </div>
    </div>
  );
}
