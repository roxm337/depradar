"use client";

import { ViewTransition, type ReactNode } from "react";
import { ApiUnavailable, AuthShell, Checking } from "@/components/auth-shell";
import { useWorkspace, WorkspaceProvider } from "@/components/workspace/context";
import { FindingDrawer, ProjectDrawer } from "@/components/workspace/drawers";
import { Modals } from "@/components/workspace/modals";
import { Shell } from "@/components/workspace/shell";

export default function WorkspaceLayout({ children }: { children: ReactNode }) {
  return <WorkspaceProvider><Gate>{children}</Gate></WorkspaceProvider>;
}

// Nothing from the workspace renders until the session is confirmed.
function Gate({ children }: { children: ReactNode }) {
  const workspace = useWorkspace();
  if (workspace.session !== "ready") {
    return <AuthShell>{workspace.session === "offline" ? <ApiUnavailable detail={workspace.error} onRetry={() => void workspace.actions.refresh()}/> : <Checking label="Loading your workspace…"/>}</AuthShell>;
  }
  return (
    <Shell>
      <ViewTransition default="page">{children}</ViewTransition>
      <FindingDrawer/>
      <ProjectDrawer/>
      <Modals/>
    </Shell>
  );
}
