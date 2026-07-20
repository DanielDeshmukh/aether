import Navbar from "@/components/Navbar";
import Hero from "@/components/Hero";
import Capabilities from "@/components/Capabilities";
import TechOverview from "@/components/TechOverview";
import WhyAether from "@/components/WhyAether";
import Vision from "@/components/Vision";
import Footer from "@/components/Footer";

export default function LandingPage() {
  return (
    <div className="min-h-screen bg-lambo-black font-mono">
      <Navbar />
      <Hero />
      <Capabilities />
      <TechOverview />
      <WhyAether />
      <Vision />
      <Footer />
    </div>
  );
}
