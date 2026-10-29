import type { Metadata } from "next";

export const metadata: Metadata = { title: "Settings" };

export default function Layout({ children }: LayoutProps<"/settings">) {
  return children;
}
