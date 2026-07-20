"use client";

import { useState } from "react";
import { motion } from "framer-motion";
import InputUrl from "@/components/InputUrl";
import ScanningConsole from "@/components/ScanningConsole";
import SidebarTelemetry from "@/components/SidebarTelemetry";

export default function HomePage() {
  const [activeScan, setActiveScan] = useState<Record<string, unknown> | null>(null);
  const [consentConfirmed, setConsentConfirmed] = useState(false);

  return (
    <div className="min-h-screen bg-lambo-black font-mono">
      <main className="px-5 pb-12 pt-24 md:px-10">
        <div className="mx-auto max-w-7xl">
          <div className="grid grid-cols-1 gap-6 xl:grid-cols-12">
            <section className="space-y-6 xl:col-span-8">
              <motion.div
                initial={{ opacity: 0, y: -32 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.55, ease: "easeOut" }}
              >
                <InputUrl
                  onTerminalStart={(payload) => setActiveScan(payload as Record<string, unknown>)}
                  consentConfirmed={consentConfirmed}
                  onConsentChange={setConsentConfirmed}
                />
              </motion.div>

              <motion.div
                initial={{ opacity: 0, y: 48 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.7, ease: "easeOut", delay: 0.1 }}
              >
                <ScanningConsole scanSession={activeScan as { scan_id?: string; target_url?: string } | null} />
              </motion.div>
            </section>

            <section className="xl:col-span-4">
              <SidebarTelemetry />
            </section>
          </div>
        </div>
      </main>
    </div>
  );
}
