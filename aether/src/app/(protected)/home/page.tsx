"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";

export default function HomePage() {
  const [url, setUrl] = useState("");
  const [consent, setConsent] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const router = useRouter();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!url || !consent) return;
    setLoading(true);
    setError("");

    try {
      const res = await fetch("/api/v1/scans", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target_url: url, consent_confirmed: consent }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "Failed to create scan");
      router.push(`/dashboard/${data.data.scan_id}`);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Something went wrong");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="max-w-2xl mx-auto px-8 py-16">
      <h1 className="text-2xl font-bold mb-2">New Scan</h1>
      <p className="text-white/40 text-sm mb-8">Enter a target URL to begin an autonomous security assessment.</p>

      <form onSubmit={handleSubmit} className="space-y-6">
        <div>
          <label className="block text-xs text-white/50 mb-2 uppercase tracking-wider">Target URL</label>
          <input
            type="text"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="https://example.com"
            className="w-full px-4 py-3 bg-white/5 border border-white/10 rounded text-sm text-white placeholder:text-white/20 focus:outline-none focus:border-aether-gold/50 transition-colors"
          />
        </div>

        <label className="flex items-start gap-3 cursor-pointer">
          <input
            type="checkbox"
            checked={consent}
            onChange={(e) => setConsent(e.target.checked)}
            className="mt-1 accent-[#FFC107]"
          />
          <span className="text-xs text-white/50 leading-relaxed">
            I confirm that I own or have explicit written authorization to test this target.
            AETHER requires verified consent before initiating any security assessment.
          </span>
        </label>

        {error && (
          <div className="px-4 py-3 bg-red-500/10 border border-red-500/20 rounded text-xs text-red-400">
            {error}
          </div>
        )}

        <button
          type="submit"
          disabled={!url || !consent || loading}
          className="w-full py-3 bg-aether-gold text-black font-semibold rounded chamfer-button text-sm disabled:opacity-30 disabled:cursor-not-allowed hover:bg-aether-gold-deep transition-colors"
        >
          {loading ? "Initializing..." : "Initialize Scan"}
        </button>
      </form>
    </div>
  );
}
