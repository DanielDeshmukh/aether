"use client";

import { useEffect, useState } from "react";
import { FcGoogle } from "react-icons/fc";
import { useRouter } from "next/navigation";

export default function JoinUsPage() {
  const [email, setEmail] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [message, setMessage] = useState("");
  const router = useRouter();

  useEffect(() => {
    const token = document.cookie.match(/(?:^|;\s*)access_token=([^;]*)/)?.[1];
    if (token) router.replace("/home");
  }, [router]);

  const handleMagicLinkSignIn = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoading(true);
    setMessage("");
    try {
      const response = await fetch("/api/v1/auth/magic-link", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: email.toLowerCase().trim() }),
      });
      if (!response.ok) { const data = await response.json().catch(() => ({})); throw new Error(data.detail || "Failed to send magic link"); }
      setMessage("MAGIC LINK SENT. CHECK YOUR EMAIL.");
    } catch (err) {
      console.error("Error sending magic link:", err);
      setMessage("FAILED TO SEND MAGIC LINK. PLEASE RETRY.");
    } finally { setTimeout(() => setIsLoading(false), 2000); }
  };

  const handleGoogleSignIn = () => { window.location.href = "/api/v1/auth/google"; };

  return (
    <section className="min-h-screen bg-lambo-black flex items-center justify-center px-5 py-20 relative overflow-hidden font-mono">
      <div className="absolute top-0 left-0 w-full h-[1px] bg-gradient-to-r from-transparent via-lambo-gold/30 to-transparent"></div>
      <div className="absolute -top-24 -left-24 w-96 h-96 bg-lambo-gold/5 rounded-full blur-[120px]"></div>

      <div className="w-full max-w-md relative z-10">
        <div className="text-center mb-10">
          <div className="flex justify-center items-center gap-3 mb-4">
            <div className="w-10 h-[1px] bg-lambo-gold"></div>
            <span className="text-[10px] text-lambo-gold tracking-[0.4em] uppercase font-black">Authentication</span>
            <div className="w-10 h-[1px] bg-lambo-gold"></div>
          </div>
          <h1 className="text-4xl md:text-5xl text-lambo-white uppercase tracking-tighter leading-none mb-4">
            JOIN <span className="text-lambo-gold/80">AETHER</span>
          </h1>
          <p className="text-lambo-ash text-xs uppercase tracking-widest opacity-70">Secure access to the neural orchestration engine.</p>
        </div>

        <div className="bg-[#0c0c0d] border border-lambo-charcoal/30 p-8 rounded-2xl shadow-2xl">
          <button onClick={handleGoogleSignIn} className="w-full flex items-center justify-center gap-3 bg-transparent border border-lambo-charcoal/50 hover:border-lambo-gold/50 py-4 rounded-xl transition-all duration-300 group">
            <FcGoogle className="text-2xl" />
            <span className="text-lambo-white text-xs font-bold uppercase tracking-widest group-hover:text-lambo-gold">Continue with Google</span>
          </button>

          <div className="relative my-8 text-center">
            <div className="absolute inset-0 flex items-center"><div className="w-full border-t border-lambo-charcoal/30"></div></div>
            <span className="relative px-4 bg-[#0c0c0d] text-[10px] text-lambo-ash uppercase tracking-[0.3em]">OR</span>
          </div>

          <form onSubmit={handleMagicLinkSignIn} className="space-y-6">
            <div>
              <label className="block text-[10px] text-lambo-gold uppercase tracking-widest mb-2 font-bold pl-1">Email Interface</label>
              <input type="email" required placeholder="[EMAIL_ADDRESS]" value={email} onChange={(e) => setEmail(e.target.value.toUpperCase())} className="w-full bg-neutral-900/50 border border-lambo-charcoal/50 text-lambo-white py-4 px-5 rounded-xl outline-none focus:border-lambo-gold transition-all duration-300 text-sm tracking-widest placeholder:text-lambo-ash/20" />
            </div>

            <button disabled={isLoading} className="w-full bg-lambo-gold hover:bg-[#c2a032] text-black font-black text-xs py-4 rounded-xl uppercase tracking-[0.2em] transition-all duration-300 relative overflow-hidden">
              {isLoading ? (
                <span className="flex items-center justify-center gap-2">
                  <div className="w-3 h-3 border-2 border-black/30 border-t-black rounded-full animate-spin"></div>
                  Dispatching...
                </span>
              ) : "Send Magic Link"}
            </button>
          </form>

          {message && <div className="mt-4 text-center text-[10px] font-bold tracking-[0.2em] text-lambo-gold uppercase">{message}</div>}
        </div>

        <p className="mt-8 text-center text-[9px] text-lambo-ash/40 uppercase tracking-[0.2em] leading-loose">
          By continuing, you authorize the initialization of <br /> biometric-equivalent cryptographic loops.
        </p>
      </div>
    </section>
  );
}
