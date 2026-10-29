import type { Metadata } from "next";
import { IBM_Plex_Mono, Instrument_Sans } from "next/font/google";
import "./globals.css";

// Interface text in a narrow-capable grotesk; package names, versions, and IDs in a true mono.
const uiFont = Instrument_Sans({ subsets: ["latin"], variable: "--font-ui", axes: ["wdth"], display: "swap" });
const dataFont = IBM_Plex_Mono({ subsets: ["latin"], variable: "--font-data", weight: ["400", "500", "600"], display: "swap" });

export const metadata: Metadata = {
  title: { default: "DepRadar", template: "%s · DepRadar" },
  description: "Understand, prioritize, and gate vulnerable dependencies across every project.",
};

export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    <html lang="en" className={`${uiFont.variable} ${dataFont.variable}`}>
      <body>{children}</body>
    </html>
  );
}
