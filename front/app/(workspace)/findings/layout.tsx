import type { Metadata } from "next";

export const metadata: Metadata = { title: "Findings" };

export default function Layout({ children }: LayoutProps<"/findings">) {
  return children;
}
