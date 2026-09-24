import * as React from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { AlertTriangle, Loader2 } from "lucide-react";

import { RouterProvider, useRouter } from "@/lib/router";
import { GroupsProvider } from "@/lib/groups";
import { AuthProvider, useAuth } from "@/lib/auth";
import { TooltipProvider } from "@/components/ui/tooltip";
import { AppShell } from "@/components/layout/AppShell";
import { OverviewPage } from "@/pages/OverviewPage";
import { AssetsPage } from "@/pages/AssetsPage";
import { AssetDetailPage } from "@/pages/AssetDetailPage";
import { TopologyPage } from "@/pages/TopologyPage";
import { ScansPage } from "@/pages/ScansPage";
import { VulnerabilitiesPage } from "@/pages/VulnerabilitiesPage";
import { FindingsPage } from "@/pages/FindingsPage";
import { DetectionsPage } from "@/pages/DetectionsPage";
import { EventsPage } from "@/pages/EventsPage";
import { ConnectionsPage } from "@/pages/ConnectionsPage";
import { ReportsPage } from "@/pages/ReportsPage";
import { SettingsPage } from "@/pages/SettingsPage";
import { LoginPage } from "@/features/auth/LoginPage";
import { EmptyState } from "@/components/shared";
import { Button } from "@/components/ui/button";
import { Link } from "@/lib/router";
import { Compass } from "lucide-react";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 15_000,
      retry: 1,
      refetchOnWindowFocus: true,
    },
  },
});

function Routes() {
  const { segments, path } = useRouter();
  const [root, id] = segments;

  // Re-mount page components when the primary route changes so local state resets per page
  const key = `${root ?? "overview"}/${id ?? ""}`;

  let page: React.ReactNode;
  switch (root ?? "overview") {
    case "overview":
      page = <OverviewPage />;
      break;
    case "assets":
      page = id ? <AssetDetailPage id={id} /> : <AssetsPage />;
      break;
    case "topology":
      page = <TopologyPage />;
      break;
    case "scans":
      page = <ScansPage />;
      break;
    case "vulnerabilities":
      page = <VulnerabilitiesPage />;
      break;
    case "findings":
      page = <FindingsPage />;
      break;
    case "detections":
      page = <DetectionsPage />;
      break;
    case "events":
      page = <EventsPage />;
      break;
    case "connections":
      page = <ConnectionsPage />;
      break;
    case "reports":
      page = <ReportsPage />;
      break;
    case "settings":
      page = <SettingsPage />;
      break;
    default:
      page = (
        <EmptyState
          icon={Compass}
          title="Page not found"
          description={`Nothing lives at ${path}.`}
          action={
            <Button size="sm" asChild>
              <Link to="/overview">Back to overview</Link>
            </Button>
          }
        />
      );
  }

  return (
    <PageErrorBoundary key={key}>{page}</PageErrorBoundary>
  );
}

/** Per-page crash guard: one broken page renders an error, the shell survives. */
class PageErrorBoundary extends React.Component<
  { children: React.ReactNode },
  { error: Error | null }
> {
  state = { error: null as Error | null };

  static getDerivedStateFromError(error: Error) {
    return { error };
  }

  componentDidCatch(error: Error) {
    console.error("Page crashed:", error);
  }

  render() {
    if (this.state.error) {
      return (
        <EmptyState
          icon={AlertTriangle}
          title="Something went wrong"
          description={this.state.error.message}
          action={
            <Button size="sm" onClick={() => this.setState({ error: null })}>
              Try again
            </Button>
          }
        />
      );
    }
    return this.props.children;
  }
}

/** Route guard: splash while restoring, login when unauthenticated. */
function AuthGate() {
  const { status } = useAuth();
  if (status === "initializing") {
    return (
      <div className="flex h-screen w-full items-center justify-center bg-background">
        <div className="flex flex-col items-center gap-3">
          <div className="glow-primary flex size-11 items-center justify-center rounded-xl bg-gradient-to-br from-primary to-[oklch(0.55_0.2_300)] text-base font-bold text-primary-foreground">
            Æ
          </div>
          <Loader2 className="size-4 animate-spin text-muted-foreground" />
        </div>
      </div>
    );
  }
  if (status === "unauthenticated") {
    return <LoginPage />;
  }
  return (
    <GroupsProvider>
      <AppShell>
        <Routes />
      </AppShell>
    </GroupsProvider>
  );
}

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <RouterProvider>
        <AuthProvider>
          <TooltipProvider>
            <AuthGate />
          </TooltipProvider>
        </AuthProvider>
      </RouterProvider>
    </QueryClientProvider>
  );
}
