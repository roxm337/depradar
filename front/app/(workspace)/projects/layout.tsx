import type { Metadata } from "next";

export const metadata: Metadata = { title: "Projects" };

export default function Layout({ children }: LayoutProps<"/projects">) {
  return children;
}
