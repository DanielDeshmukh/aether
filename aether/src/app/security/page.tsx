import Link from "next/link";

export const metadata = {
  title: "Security Policy | AETHER",
};

export default function SecurityPage() {
  return (
    <div className="font-lambo bg-lambo-black min-h-screen selection:bg-lambo-gold selection:text-lambo-black">
      <nav className="fixed top-0 z-50 flex w-full items-center justify-between border-b border-white/5 bg-black/80 px-10 py-6 backdrop-blur-md">
        <Link href="/" className="flex items-center gap-4 group cursor-pointer">
          <div className="text-2xl font-bold tracking-[0.3em] text-lambo-white">AETHER</div>
        </Link>
        <Link href="/" className="text-[10px] font-bold tracking-[0.25em] text-lambo-ash uppercase hover:text-lambo-gold transition-colors">Back to Home</Link>
      </nav>

      <main className="pt-32 pb-24 px-10 max-w-[900px] mx-auto">
        <div className="flex items-center gap-4 mb-8">
          <div className="w-8 h-[1px] bg-lambo-gold"></div>
          <span className="text-[10px] font-black text-lambo-gold tracking-[0.3em] uppercase">SECURITY POLICY</span>
        </div>

        <h1 className="text-[48px] md:text-[64px] uppercase text-lambo-white tracking-tighter leading-[0.9] mb-12">
          SECURITY <br /><span className="text-lambo-white/40">POLICY</span>
        </h1>

        <div className="space-y-12">
          <section>
            <h2 className="text-xl text-lambo-white uppercase tracking-wider mb-4">Responsible Disclosure</h2>
            <p className="text-lambo-ash leading-relaxed">AETHER is committed to ensuring the security and privacy of our users and their data. We encourage responsible disclosure of security vulnerabilities and maintain an open policy for security researchers to report issues.</p>
          </section>

          <section>
            <h2 className="text-xl text-lambo-white uppercase tracking-wider mb-4">Reporting Vulnerabilities</h2>
            <p className="text-lambo-ash leading-relaxed mb-4">If you discover a security vulnerability within the AETHER platform, please report it responsibly. We ask that you:</p>
            <ul className="text-lambo-ash leading-relaxed space-y-2 ml-6 list-disc">
              <li>Allow reasonable time for us to address the issue before public disclosure</li>
              <li>Provide sufficient detail to reproduce the vulnerability</li>
              <li>Avoid accessing or modifying data belonging to other users</li>
              <li>Do not exploit the vulnerability beyond what is necessary to demonstrate it</li>
            </ul>
          </section>

          <section>
            <h2 className="text-xl text-lambo-white uppercase tracking-wider mb-4">Scope</h2>
            <p className="text-lambo-ash leading-relaxed">The following are in scope for security reports: the AETHER web application, API endpoints, authentication mechanisms, and the automated scanning engine. Third-party integrations and infrastructure not operated by AETHER are out of scope.</p>
          </section>

          <section>
            <h2 className="text-xl text-lambo-white uppercase tracking-wider mb-4">Data Protection</h2>
            <p className="text-lambo-ash leading-relaxed">All scan data is encrypted in transit and at rest. We implement strict access controls and audit logging across the platform. User credentials are never stored in plain text. We comply with industry-standard security practices for data handling and storage.</p>
          </section>

          <section>
            <h2 className="text-xl text-lambo-white uppercase tracking-wider mb-4">Authentication &amp; Authorization</h2>
            <p className="text-lambo-ash leading-relaxed">AETHER uses industry-standard OAuth 2.0 for authentication. JWT tokens are short-lived and validated on every request. Role-based access controls ensure users can only access their own scan data and configurations.</p>
          </section>

          <section>
            <h2 className="text-xl text-lambo-white uppercase tracking-wider mb-4">Infrastructure Security</h2>
            <p className="text-lambo-ash leading-relaxed">Our infrastructure is deployed on hardened cloud environments with automatic security patching, network isolation, and continuous monitoring. We employ WAF protections and DDoS mitigation at the edge.</p>
          </section>
        </div>
      </main>

      <footer className="py-12 bg-lambo-black border-t border-lambo-charcoal/30 px-10">
        <div className="max-w-[900px] mx-auto flex flex-col md:flex-row justify-between items-center gap-6">
          <p className="text-[9px] text-lambo-ash tracking-[0.2em] uppercase">&copy; 2026 AETHER PLATFORM // ALL RIGHTS RESERVED</p>
          <div className="flex items-center gap-4 opacity-10">
            <span className="text-[9px] text-lambo-ash tracking-[0.2em] uppercase">Built for Dominance</span>
            <div className="w-1 h-1 bg-lambo-gold rounded-full"></div>
            <span className="text-[9px] text-lambo-gold tracking-[0.3em] uppercase font-bold">Designed by Daniel Deshmukh</span>
          </div>
        </div>
      </footer>
    </div>
  );
}
