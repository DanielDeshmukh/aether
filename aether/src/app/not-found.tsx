import Link from "next/link";

export default function NotFound() {
  return (
    <div className="min-h-screen bg-lambo-black text-white flex items-center justify-center p-8">
      <div className="text-center max-w-md">
        <div className="text-8xl font-bold text-lambo-gold mb-4">404</div>
        <h1 className="text-2xl font-bold mb-4">Page not found</h1>
        <p className="text-gray-400 mb-8">The page you are looking for does not exist or has been moved.</p>
        <Link href="/" className="bg-lambo-gold text-lambo-black px-6 py-3 rounded-lg font-bold hover:bg-yellow-400 transition-colors inline-block">
          Back to Home
        </Link>
      </div>
    </div>
  );
}
