"use client";

import { useEffect, useState } from "react";

interface GitTarget {
  id: string;
  domain: string;
  git_provider: string;
  repository: string;
  project_id?: string;
  default_branch?: string;
  base_branch?: string;
  api_base_url?: string;
  repo_web_url?: string;
  target_id?: string;
}

export default function GitIntegration() {
  const [targets, setTargets] = useState<GitTarget[]>([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");

  const [form, setForm] = useState({
    target_id: "",
    git_provider: "github",
    access_token: "",
    repository: "",
    project_id: "",
    default_branch: "main",
    base_branch: "",
    api_base_url: "",
    repo_web_url: "",
  });

  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      setLoading(true);
      try {
        const res = await fetch("/api/v1/git-targets", { credentials: "same-origin" });
        const data = await res.json();
        if (!cancelled) setTargets(data?.data?.targets || []);
      } catch {
        if (!cancelled) setError("Failed to load data.");
      }
      if (!cancelled) setLoading(false);
    };
    load();
    return () => { cancelled = true; };
  }, []);

  const handleScanSelect = (scan: { target_id?: string } & GitTarget) => {
    setForm({
      target_id: scan.target_id || "",
      git_provider: "github",
      access_token: "",
      repository: "",
      project_id: "",
      default_branch: "main",
      base_branch: "",
      api_base_url: "",
      repo_web_url: "",
    });

    const existing = targets.find((t) => t.id === scan.target_id);
    if (existing) {
      setForm({
        target_id: existing.id,
        git_provider: existing.git_provider || "github",
        access_token: "",
        repository: existing.repository || "",
        project_id: existing.project_id || "",
        default_branch: existing.default_branch || "main",
        base_branch: existing.base_branch || "",
        api_base_url: existing.api_base_url || "",
        repo_web_url: existing.repo_web_url || "",
      });
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setSaving(true);
    setMessage("");
    setError("");
    try {
      await fetch("/api/v1/git-targets", {
        method: "POST",
        credentials: "same-origin",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(form),
      });
      setMessage("Git integration configured successfully.");
      const res = await fetch("/api/v1/git-targets", { credentials: "same-origin" });
      const data = await res.json();
      setTargets(data?.data?.targets || []);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to save git configuration.");
    }
    setSaving(false);
  };

  const handleDelete = async (targetId: string) => {
    if (!window.confirm("Remove git integration for this target?")) return;
    try {
      await fetch(`/api/v1/git-targets/${targetId}`, { method: "DELETE", credentials: "same-origin" });
      setMessage("Git integration removed.");
      const res = await fetch("/api/v1/git-targets", { credentials: "same-origin" });
      const data = await res.json();
      setTargets(data?.data?.targets || []);
    } catch {
      setError("Failed to remove git integration.");
    }
  };

  if (loading) {
    return <div className="text-[10px] tracking-[0.3em] text-lambo-ash py-4">Loading git integrations...</div>;
  }

  return (
    <div className="space-y-6">
      <div>
        <p className="text-[10px] font-bold tracking-[0.4em] text-lambo-gold">// Git Integration</p>
        <h2 className="mt-3 text-2xl font-black tracking-[-0.03em] text-lambo-white">Remediation PRs</h2>
        <p className="mt-2 text-xs text-lambo-ash">Configure a Git provider to automatically create pull requests with remediation fixes.</p>
      </div>

      {message && <div className="chamfer-panel border border-green-500/30 bg-green-500/10 px-5 py-4 text-[10px] font-bold tracking-[0.22em] text-green-500">{message}</div>}
      {error && <div className="chamfer-panel border border-red-500/30 bg-red-500/10 px-5 py-4 text-[10px] font-bold tracking-[0.22em] text-red-500">{error}</div>}

      {targets.length > 0 && (
        <div className="chamfer-panel border border-white/10 bg-[#0d0d0d] p-6">
          <h3 className="text-[10px] font-bold tracking-[0.3em] text-lambo-ash mb-4">Configured Targets</h3>
          <div className="space-y-3">
            {targets.map((t) => (
              <div key={t.id} className="flex items-center justify-between border border-white/5 bg-black/20 px-4 py-3">
                <div>
                  <span className="text-xs font-bold text-lambo-white">{t.domain}</span>
                  <span className="ml-3 text-[10px] tracking-[0.2em] text-lambo-gold uppercase">{t.git_provider}</span>
                  <span className="ml-3 text-[10px] text-lambo-ash">{t.repository}</span>
                </div>
                <button onClick={() => handleDelete(t.id)} className="text-[10px] tracking-[0.2em] text-red-400 hover:text-red-300">REMOVE</button>
              </div>
            ))}
          </div>
        </div>
      )}

      <form onSubmit={handleSubmit} className="chamfer-panel border border-lambo-gold/20 bg-[#0d0d0d] p-8 space-y-5">
        <h3 className="text-[10px] font-bold tracking-[0.3em] text-lambo-gold mb-2">Configure Target</h3>

        <div>
          <label className="text-[10px] font-bold tracking-[0.3em] text-lambo-ash block mb-2">Target Domain</label>
          <select value={form.target_id} onChange={(e) => {
            const target = targets.find((t) => t.id === e.target.value);
            if (target) handleScanSelect({ target_id: target.id, ...target });
          }} className="w-full border border-white/10 bg-black/40 px-4 py-3 text-sm text-lambo-white focus:border-lambo-gold/40 focus:outline-none">
            <option value="">Select a verified target...</option>
            {targets.map((t) => <option key={t.id} value={t.id}>{t.domain} ({t.git_provider || "not configured"})</option>)}
          </select>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-5">
          <div>
            <label className="text-[10px] font-bold tracking-[0.3em] text-lambo-ash block mb-2">Provider</label>
            <select value={form.git_provider} onChange={(e) => setForm({ ...form, git_provider: e.target.value })} className="w-full border border-white/10 bg-black/40 px-4 py-3 text-sm text-lambo-white focus:border-lambo-gold/40 focus:outline-none">
              <option value="github">GitHub</option>
              <option value="gitlab">GitLab</option>
            </select>
          </div>
          <div>
            <label className="text-[10px] font-bold tracking-[0.3em] text-lambo-ash block mb-2">Repository</label>
            <input type="text" value={form.repository} onChange={(e) => setForm({ ...form, repository: e.target.value })} placeholder="owner/repo" className="w-full border border-white/10 bg-black/40 px-4 py-3 text-sm text-lambo-white focus:border-lambo-gold/40 focus:outline-none" />
          </div>
        </div>

        <div>
          <label className="text-[10px] font-bold tracking-[0.3em] text-lambo-ash block mb-2">Access Token</label>
          <input type="password" value={form.access_token} onChange={(e) => setForm({ ...form, access_token: e.target.value })} placeholder="ghp_... or glpat-..." className="w-full border border-white/10 bg-black/40 px-4 py-3 text-sm text-lambo-white focus:border-lambo-gold/40 focus:outline-none" />
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-5">
          <div>
            <label className="text-[10px] font-bold tracking-[0.3em] text-lambo-ash block mb-2">Default Branch</label>
            <input type="text" value={form.default_branch} onChange={(e) => setForm({ ...form, default_branch: e.target.value })} className="w-full border border-white/10 bg-black/40 px-4 py-3 text-sm text-lambo-white focus:border-lambo-gold/40 focus:outline-none" />
          </div>
          <div>
            <label className="text-[10px] font-bold tracking-[0.3em] text-lambo-ash block mb-2">Base Branch (PR target)</label>
            <input type="text" value={form.base_branch} onChange={(e) => setForm({ ...form, base_branch: e.target.value })} placeholder="defaults to default branch" className="w-full border border-white/10 bg-black/40 px-4 py-3 text-sm text-lambo-white focus:border-lambo-gold/40 focus:outline-none" />
          </div>
        </div>

        {form.git_provider === "gitlab" && (
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-5">
            <div>
              <label className="text-[10px] font-bold tracking-[0.3em] text-lambo-ash block mb-2">Project ID</label>
              <input type="text" value={form.project_id} onChange={(e) => setForm({ ...form, project_id: e.target.value })} className="w-full border border-white/10 bg-black/40 px-4 py-3 text-sm text-lambo-white focus:border-lambo-gold/40 focus:outline-none" />
            </div>
            <div>
              <label className="text-[10px] font-bold tracking-[0.3em] text-lambo-ash block mb-2">API Base URL</label>
              <input type="text" value={form.api_base_url} onChange={(e) => setForm({ ...form, api_base_url: e.target.value })} placeholder="https://gitlab.com/api/v4" className="w-full border border-white/10 bg-black/40 px-4 py-3 text-sm text-lambo-white focus:border-lambo-gold/40 focus:outline-none" />
            </div>
          </div>
        )}

        <button type="submit" disabled={saving || !form.target_id || !form.access_token || !form.repository} className="chamfer-button w-full border border-lambo-gold/30 bg-lambo-gold/10 px-4 py-4 text-[10px] font-bold tracking-[0.2em] text-lambo-gold transition-colors hover:bg-lambo-gold/20 disabled:opacity-50">
          {saving ? "Saving..." : "Save Git Configuration"}
        </button>
      </form>
    </div>
  );
}
