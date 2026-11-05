import type { Metadata } from "next";

export const metadata: Metadata = { title: "Packages" };

export default function Layout({ children }: LayoutProps<"/packages">) {
  return children;
}
