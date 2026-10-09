import type { Metadata } from "next";
import "./globals.css";
// Using standard Arial font

export const metadata: Metadata = {
  title: "Vertex Autonomous Threat Intelligence",
  description: "Next-Generation Autonomous Threat Interception & Multimodal Defense System",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body className={`font-sans bg-white text-base text-zinc-950 antialiased selection:bg-zinc-900 selection:text-white`} style={{ fontFamily: "Arial, sans-serif" }}>
        {children}
      </body>
    </html>
  );
}
