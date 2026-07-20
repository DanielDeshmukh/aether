import type { Metadata } from "next";
import { Inter } from "next/font/google";
import "./globals.css";

const inter = Inter({ subsets: ["latin"] });

export const metadata: Metadata = {
  title: "AETHER | Automated Ethical Testing & Heuristic Evaluation Routine",
  description:
    "An autonomous penetration testing platform that reasons like a human security expert. Discovers, validates, and remediates web application vulnerabilities.",
  icons: {
    icon: [
      { url: "/favicon.png", type: "image/png" },
      { url: "/images/logo.png", type: "image/png" },
    ],
    apple: "/images/logo.png",
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className={`${inter.className} h-full antialiased`}>
      <body className="min-h-full flex flex-col">{children}</body>
    </html>
  );
}
