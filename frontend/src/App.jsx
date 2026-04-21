import React from 'react';
import './index.css';
import Navbar from './components/Navbar';
import Hero from './components/Hero';
import Capabilities from './components/Capabilities';
import TechOverview from './components/TechOverview';
import WhyAether from './components/WhyAether';
import Vision from './components/Vision';
import Footer from './components/Footer';

function App() {
  return (
    <div className="app-container font-lambo bg-lambo-black min-h-screen selection:bg-lambo-gold selection:text-lambo-black scroll-smooth">
      <Navbar />
      
      <main>
        <Hero />
        <Capabilities />
        <TechOverview />
        <WhyAether />
        <Vision />
      </main>
      
      <Footer />
    </div>
  );
}

export default App;
