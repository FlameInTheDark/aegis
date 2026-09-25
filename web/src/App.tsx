import * as React from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { AlertTriangle, Loader2 } from "lucide-react";

import { RouterProvider, useRouter } from "@/lib/router";
import { GroupsProvider } from "@/lib/groups";
import { AuthProvider, useAuth } from "@/lib/auth";
import { TooltipProvider } from "@/components/ui/tooltip";
import { AppShell } from "@/components/layout/AppShell";
// Route-level code splitting: every page (and its charting/D3 dependency)
// loads in its own chunk on first visit instead of one monolithic bundle.
const OverviewPage = React.lazy(() => import("@/pages/OverviewPage").then((m) => ({ default: m.OverviewPage })));
const AssetsPage = React.lazy(() => import("@/pages/AssetsPage").then((m) => ({ default: m.AssetsPage })));
const AssetDetailPage = React.lazy(() => import("@/pages/AssetDetailPage").then((m) => ({ default: m.AssetDetailPage })));
const TopologyPage = React.lazy(() => import("@/pages/TopologyPage").then((m) => ({ default: m.TopologyPage })));
const ScansPage = React.lazy(() => import("@/pages/ScansPage").then((m) => ({ default: m.ScansPage })));
const VulnerabilitiesPage = React.lazy(() => import("@/pages/VulnerabilitiesPage").then((m) => ({ default: m.VulnerabilitiesPage })));
const FindingsPage = React.lazy(() => import("@/pages/FindingsPage").then((m) => ({ default: m.FindingsPage })));
const DetectionsPage = React.lazy(() => import("@/pages/DetectionsPage").then((m) => ({ default: m.DetectionsPage })));
const AlertsPage = React.lazy(() => import("@/pages/AlertsPage").then((m) => ({ default: m.AlertsPage })));
const EventsPage = React.lazy(() => import("@/pages/EventsPage").then((m) => ({ default: m.EventsPage })));
const ConnectionsPage = React.lazy(() => import("@/pages/ConnectionsPage").then((m) => ({ default: m.ConnectionsPage })));
const ReportsPage = React.lazy(() => import("@/pages/ReportsPage").then((m) => ({ default: m.ReportsPage })));
const SettingsPage = React.lazy(() => import("@/pages/SettingsPage").then((m) => ({ default: m.SettingsPage })));
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
    case "alerts":
      page = <AlertsPage />;
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
    <PageErrorBoundary key={key}>
      {/* Chunk loading fallback: lazy pages suspend on first visit. */}
      <React.Suspense
        fallback={
          <div className="flex items-center justify-center px-4 py-24 text-sm text-muted-foreground">
            <Loader2 className="size-4 animate-spin" />
          </div>
        }
      >
        {page}
      </React.Suspense>
    </PageErrorBoundary>
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
