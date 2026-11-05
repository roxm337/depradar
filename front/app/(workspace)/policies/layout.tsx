import type { Metadata } from "next";

export const metadata: Metadata = { title: "Policies" };

export default function Layout({ children }: LayoutProps<"/policies">) {
  return children;
}
