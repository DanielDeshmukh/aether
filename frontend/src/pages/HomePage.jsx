import React from 'react';
import Header from "../components/Header";

const Homepage = () => {
    const stats = [
        { label: "Active Nodes", value: "14", trend: "+2" },
        { label: "Neural Latency", value: "24ms", trend: "-4ms" },
        { label: "Vulnerabilities Found", value: "128", trend: "0" },
        { label: "System Health", value: "98.2%", trend: "Stable" }
    ];

    const recentActivity = [
        { id: "01", task: "Perimeter Scan", status: "Completed", target: "Alpha_Node" },
        { id: "02", task: "Payload Injection", status: "Active", target: "Beta_Cluster" },
        { id: "03", task: "Data Exfiltration", status: "Queued", target: "Theta_System" },
      ];

    return (
        <div className="min-h-screen bg-lambo-black font-mono">
            <Header />
            
            <main className="pt-24 pb-10 px-5 md:px-10 max-w-screen-2xl mx-auto">
                <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
                    {stats.map((stat, i) => (
                        <div key={i} className="bg-[#0c0c0d] border border-lambo-charcoal/30 p-5 rounded-xl hover:border-lambo-gold/40 transition-all duration-300">
                            <p className="text-[10px] text-lambo-gold uppercase tracking-[0.2em] mb-2">{stat.label}</p>
                            <div className="flex items-baseline gap-3">
                                <h3 className="text-2xl text-lambo-white font-bold">{stat.value}</h3>
                                <span className="text-[9px] text-lambo-gold/50">{stat.trend}</span>
                            </div>
                        </div>
                    ))}
                </div>

                <div className="flex flex-col lg:flex-row gap-8">
                    <div className="lg:w-2/3 space-y-8">
                        <div className="bg-[#0c0c0d] border border-lambo-charcoal/30 rounded-2xl overflow-hidden">
                            <div className="p-6 border-b border-lambo-charcoal/30 flex justify-between items-center bg-lambo-charcoal/10">
                                <h2 className="text-lambo-white text-xs font-black tracking-[0.3em] uppercase">Active Session Logs</h2>
                                <span className="text-[9px] text-lambo-gold bg-lambo-gold/10 px-2 py-1 rounded">Live Feed</span>
                            </div>
                            <div className="p-6 overflow-x-auto">
                                <table className="w-full text-left">
                                    <thead>
                                        <tr className="text-[10px] text-lambo-ash uppercase tracking-widest border-b border-lambo-charcoal/20">
                                            <th className="pb-4 font-normal">ID</th>
                                            <th className="pb-4 font-normal">Task Orchestration</th>
                                            <th className="pb-4 font-normal">Target</th>
                                            <th className="pb-4 font-normal text-right">Status</th>
                                        </tr>
                                    </thead>
                                    <tbody className="text-xs">
                                        {recentActivity.map((log) => (
                                            <tr key={log.id} className="group hover:bg-lambo-gold/5 transition-colors">
                                                <td className="py-4 text-lambo-gold/60">{log.id}</td>
                                                <td className="py-4 text-lambo-white uppercase font-bold">{log.task}</td>
                                                <td className="py-4 text-lambo-ash italic">[{log.target}]</td>
                                                <td className="py-4 text-right">
                                                    <span className={`px-2 py-1 rounded-sm text-[9px] uppercase font-black ${
                                                        log.status === 'Active' ? 'bg-lambo-gold text-black' : 'border border-lambo-charcoal text-lambo-ash'
                                                    }`}>
                                                        {log.status}
                                                    </span>
                                                </td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>

                    <div className="lg:w-1/3 space-y-6">
                        <div className="bg-[#0c0c0d] border border-lambo-gold/20 p-6 rounded-2xl relative overflow-hidden">
                            <div className="absolute top-0 right-0 w-32 h-32 bg-lambo-gold/5 rounded-full -translate-y-1/2 translate-x-1/2 blur-2xl"></div>
                            
                            <h2 className="text-lambo-gold text-xs font-black tracking-[0.3em] uppercase mb-6 flex items-center gap-2">
                                <span className="w-2 h-2 rounded-full bg-lambo-gold animate-pulse"></span>
                                Neural Health
                            </h2>

                            <div className="space-y-6 relative z-10">
                                {['Logic Core', 'Payload Gen', 'Bypass Engine'].map((core, i) => (
                                    <div key={i}>
                                        <div className="flex justify-between text-[10px] uppercase mb-2">
                                            <span className="text-lambo-ash">{core}</span>
                                            <span className="text-lambo-gold">Optimized</span>
                                        </div>
                                        <div className="w-full h-[2px] bg-lambo-charcoal/50">
                                            <div className="h-full bg-lambo-gold" style={{ width: i === 1 ? '75%' : '90%' }}></div>
                                        </div>
                                    </div>
                                ))}
                            </div>

                            <button className="w-full mt-8 bg-transparent border border-lambo-gold/40 hover:bg-lambo-gold hover:text-black text-lambo-gold py-3 text-[10px] uppercase font-black tracking-widest transition-all duration-300">
                                Run Diagnostics
                            </button>
                        </div>

                        <div className="grid grid-cols-2 gap-4">
                            <div className="p-4 border border-lambo-charcoal/30 bg-[#0c0c0d] rounded-xl hover:border-lambo-gold cursor-pointer group transition-all">
                                <div className="text-[18px] mb-2 group-hover:scale-110 transition-transform">🛰️</div>
                                <p className="text-[9px] text-lambo-white uppercase font-bold tracking-tighter">New Scan</p>
                            </div>
                            <div className="p-4 border border-lambo-charcoal/30 bg-[#0c0c0d] rounded-xl hover:border-lambo-gold cursor-pointer group transition-all">
                                <div className="text-[18px] mb-2 group-hover:scale-110 transition-transform">⚡</div>
                                <p className="text-[9px] text-lambo-white uppercase font-bold tracking-tighter">Quick Exploit</p>
                            </div>
                        </div>
                    </div>
                </div>
            </main>

            <div className="fixed inset-0 pointer-events-none opacity-[0.02] bg-[url('https://grainy-gradients.vercel.app/noise.svg')]"></div>
        </div>
    );
};

export default Homepage;