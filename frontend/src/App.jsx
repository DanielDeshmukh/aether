import React from 'react';
import './index.css';
import Navbar from './components/Navbar';
import Hero from './components/Hero';
import Homepage from './pages/HomePage';
import Capabilities from './components/Capabilities';
import TechOverview from './components/TechOverview';
import WhyAether from './components/WhyAether';
import Vision from './components/Vision';
import Footer from './components/Footer';
import { Routes, Route } from 'react-router-dom';
import JoinUs from './pages/JoinUs';


const LandingPage = () => {
  return (
    <>
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
    </>
  );
};

function App() {
  return (
    <div className="app-container font-lambo bg-lambo-black min-h-screen selection:bg-lambo-gold selection:text-lambo-black scroll-smooth">
      <main>
        <Routes>
          <Route path="/" element={<LandingPage />} />
          <Route path="/join-us" element={<JoinUs />} />
          <Route path="/home" element={<Homepage/>} />
        </Routes>
      </main>
    </div>
  );
}

export default App;
