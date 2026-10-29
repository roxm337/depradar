import type { Metadata } from "next";

export const metadata: Metadata = { title: "Sign in — DepRadar" };

export default function LoginLayout({ children }: LayoutProps<"/login">) {
  return children;
}
