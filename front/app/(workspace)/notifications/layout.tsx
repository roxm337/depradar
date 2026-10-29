import type { Metadata } from "next";

export const metadata: Metadata = { title: "Notifications" };

export default function Layout({ children }: LayoutProps<"/notifications">) {
  return children;
}
