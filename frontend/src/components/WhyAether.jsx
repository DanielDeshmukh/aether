import React from 'react';

const WhyAether = () => {
  const points = [
    { title: "OWASP COVERAGE", value: "FULL", description: "Automated detection of vulnerabilities aligned with the OWASP Top 10 standards." },
    { title: "SCALABLE SAAS", value: "TENANT", description: "Multi-tenant platform enabling organizations to manage continuous security audits." },
    { title: "ROOT CAUSE ANALYSIS", value: "DETAILED", description: "Comprehensive reporting with reproducible steps and actionable remediation guidance." }
  ];

  return (
    <section id="why" className="py-32 bg-lambo-black overflow-hidden">
      <div className="max-w-[1200px] mx-auto px-5 md:px-10">
        <h2 className="text-[48px] md:text-[54px] uppercase text-lambo-white tracking-tighter mb-8">THE ADVANTAGE</h2>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
          {points.map((p, i) => (
            <div key={i} className="p-8 border border-lambo-charcoal/30 hover:bg-lambo-charcoal/10 transition-colors">
              <div className="text-5xl font-light text-lambo-gold mb-4">{p.value}</div>
              <h3 className="text-lg text-lambo-white mb-3 uppercase">{p.title}</h3>
              <p className="text-lambo-ash text-sm uppercase">{p.description}</p>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
};

export default WhyAether;
