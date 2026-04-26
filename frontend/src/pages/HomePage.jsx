import React, { useState } from 'react';
import { motion } from 'framer-motion';
import Header from '../components/Header';
import InputUrl from '../components/InputUrl';
import ScanningConsole from '../components/ScanningConsole';
import SidebarTelemetry from '../components/SidebarTelemetry';
import { useDocumentTitle } from '../lib/useDocumentTitle';

const Homepage = () => {
    const [activeScan, setActiveScan] = useState(null);
    const [consentConfirmed, setConsentConfirmed] = useState(false);
    useDocumentTitle('Home');

    return (
        <div className="min-h-screen bg-lambo-black font-mono">
            <Header />
            <main className="px-5 pb-12 pt-24 md:px-10">
                <div className="mx-auto max-w-7xl">
                    <div className="grid grid-cols-1 gap-6 xl:grid-cols-12">
                        <section className="space-y-6 xl:col-span-8">
                            <motion.div
                                initial={{ opacity: 0, y: -32 }}
                                animate={{ opacity: 1, y: 0 }}
                                transition={{ duration: 0.55, ease: 'easeOut' }}
                            >
                                <InputUrl
                                    onTerminalStart={setActiveScan}
                                    consentConfirmed={consentConfirmed}
                                    onConsentChange={setConsentConfirmed}
                                />
                            </motion.div>

                            <motion.div
                                initial={{ opacity: 0, y: 48 }}
                                animate={{ opacity: 1, y: 0 }}
                                transition={{ duration: 0.7, ease: 'easeOut', delay: 0.1 }}
                            >
                                <ScanningConsole scanSession={activeScan} />
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
};

export default Homepage;
