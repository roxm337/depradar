import type { Metadata } from "next";
import { Inter, JetBrains_Mono } from "next/font/google";
import "./globals.css";

// Interface text in Inter with tabular figures; package names, versions, and IDs in a true mono.
const uiFont = Inter({ subsets: ["latin"], variable: "--font-ui", display: "swap" });
const dataFont = JetBrains_Mono({ subsets: ["latin"], variable: "--font-data", display: "swap" });

export const metadata: Metadata = {
  title: { default: "DepRadar", template: "%s · DepRadar" },
  description: "Understand, prioritize, and gate vulnerable dependencies across every project.",
};

// Runs before first paint so a dark theme or compact density never flashes the defaults.
const preferences = `(function(){try{var d=document.documentElement,s=localStorage;var t=s.getItem("depradar-theme")||"system";d.dataset.theme=t==="system"?(matchMedia("(prefers-color-scheme: dark)").matches?"dark":"light"):t;d.dataset.density=s.getItem("depradar-density")||"comfortable";d.dataset.nav=s.getItem("depradar-nav")||"expanded"}catch(e){}})()`;

export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    <html lang="en" className={`${uiFont.variable} ${dataFont.variable}`} suppressHydrationWarning>
      <head><script dangerouslySetInnerHTML={{ __html: preferences }}/></head>
      <body>{children}</body>
    </html>
  );
}
