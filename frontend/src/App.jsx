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
import AuthCallback from './pages/AuthCallback';
import Dashboard from './pages/Dashboard';
import ScanDetail from './pages/ScanDetail';
import Settings from './pages/Settings';
import Security from './pages/Security';
import Legal from './pages/Legal';
import NotFound from './pages/NotFound';
import ErrorBoundary from './components/ErrorBoundary';
import ProtectedRoute from './components/ProtectedRoute';
import { useDocumentTitle } from './lib/useDocumentTitle';


const LandingPage = () => {
  useDocumentTitle('Agentic Security Platform');

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
    <ErrorBoundary>
      <div className="app-container font-lambo bg-lambo-black min-h-screen selection:bg-lambo-gold selection:text-lambo-black scroll-smooth">
        <main>
          <Routes>
            <Route path="/" element={<LandingPage />} />
            <Route path="/join-us" element={<JoinUs />} />
            <Route path="/auth/callback" element={<AuthCallback />} />
            <Route path="/security" element={<Security />} />
            <Route path="/legal" element={<Legal />} />
            <Route path="/home" element={<ProtectedRoute><Homepage /></ProtectedRoute>} />
            <Route path="/dashboard" element={<ProtectedRoute><Dashboard /></ProtectedRoute>} />
            <Route path="/dashboard/:scanId" element={<ProtectedRoute><ScanDetail /></ProtectedRoute>} />
            <Route path="/settings" element={<ProtectedRoute><Settings /></ProtectedRoute>} />
            <Route path="*" element={<NotFound />} />
          </Routes>
        </main>
      </div>
    </ErrorBoundary>
  );
}

export default App;
