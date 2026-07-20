import Link from "next/link";

export const metadata = {
  title: "Legal | AETHER",
};

export default function LegalPage() {
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
          <span className="text-[10px] font-black text-lambo-gold tracking-[0.3em] uppercase">LEGAL</span>
        </div>

        <h1 className="text-[48px] md:text-[64px] uppercase text-lambo-white tracking-tighter leading-[0.9] mb-12">
          TERMS OF <br /><span className="text-lambo-white/40">SERVICE</span>
        </h1>

        <div className="space-y-12">
          <section>
            <h2 className="text-xl text-lambo-white uppercase tracking-wider mb-4">Terms of Service</h2>
            <p className="text-lambo-ash leading-relaxed">By accessing or using the AETHER platform, you agree to be bound by these Terms of Service. If you do not agree, do not use the platform.</p>
          </section>

          <section>
            <h2 className="text-xl text-lambo-white uppercase tracking-wider mb-4">Acceptable Use</h2>
            <p className="text-lambo-ash leading-relaxed mb-4">AETHER is an automated security testing platform designed for authorized penetration testing. You agree to:</p>
            <ul className="text-lambo-ash leading-relaxed space-y-2 ml-6 list-disc">
              <li>Only test systems you own or have explicit written authorization to test</li>
              <li>Comply with all applicable local, state, national, and international laws</li>
              <li>Not use the platform for any malicious, unauthorized, or illegal purpose</li>
              <li>Not attempt to circumvent rate limits, quotas, or security controls</li>
              <li>Maintain the confidentiality of your account credentials</li>
            </ul>
          </section>

          <section>
            <h2 className="text-xl text-lambo-white uppercase tracking-wider mb-4">Account Responsibility</h2>
            <p className="text-lambo-ash leading-relaxed">You are responsible for all activity that occurs under your account. You must notify us immediately of any unauthorized use of your account. AETHER reserves the right to suspend or terminate accounts that violate these terms.</p>
          </section>

          <section>
            <h2 className="text-xl text-lambo-white uppercase tracking-wider mb-4">Intellectual Property</h2>
            <p className="text-lambo-ash leading-relaxed">All content, features, and functionality of the AETHER platform are owned by AETHER and are protected by international copyright, trademark, patent, trade secret, and other intellectual property laws. You may not reproduce, distribute, or create derivative works without express written permission.</p>
          </section>

          <section>
            <h2 className="text-xl text-lambo-white uppercase tracking-wider mb-4">Service Availability</h2>
            <p className="text-lambo-ash leading-relaxed">AETHER is provided on an &quot;as is&quot; and &quot;as available&quot; basis. We do not guarantee uninterrupted or error-free service. We reserve the right to modify, suspend, or discontinue any part of the service at any time without notice.</p>
          </section>

          <section>
            <h2 className="text-xl text-lambo-white uppercase tracking-wider mb-4">Limitation of Liability</h2>
            <p className="text-lambo-ash leading-relaxed">To the maximum extent permitted by law, AETHER shall not be liable for any indirect, incidental, special, consequential, or punitive damages resulting from your use of or inability to use the platform. Our total liability shall not exceed the amount paid by you in the twelve months preceding the claim.</p>
          </section>

          <section>
            <h2 className="text-xl text-lambo-white uppercase tracking-wider mb-4">Privacy</h2>
            <p className="text-lambo-ash leading-relaxed">Your use of the AETHER platform is also governed by our Privacy Policy. By using the platform, you consent to the collection and use of data as described in the Privacy Policy. We do not sell or share your personal data with third parties for marketing purposes.</p>
          </section>

          <section>
            <h2 className="text-xl text-lambo-white uppercase tracking-wider mb-4">Modifications</h2>
            <p className="text-lambo-ash leading-relaxed">We reserve the right to modify these Terms of Service at any time. Changes will be effective immediately upon posting. Your continued use of the platform after changes constitutes acceptance of the new terms.</p>
          </section>

          <section>
            <h2 className="text-xl text-lambo-white uppercase tracking-wider mb-4">Governing Law</h2>
            <p className="text-lambo-ash leading-relaxed">These Terms shall be governed by and construed in accordance with applicable laws. Any disputes shall be resolved through binding arbitration or in courts of competent jurisdiction.</p>
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
