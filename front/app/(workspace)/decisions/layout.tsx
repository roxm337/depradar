import type { Metadata } from "next";

export const metadata: Metadata = { title: "Decisions" };

export default function Layout({ children }: LayoutProps<"/decisions">) {
  return children;
}
