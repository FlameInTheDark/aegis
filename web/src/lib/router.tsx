import * as React from "react";

export interface RouteState {
  /** e.g. "/assets/a-1" */
  path: string;
  /** path split into segments, e.g. ["assets", "a-1"] */
  segments: string[];
  /** query params from the hash, e.g. #/assets/a-1?tab=traces */
  query: URLSearchParams;
}

interface RouterContextValue extends RouteState {
  navigate: (to: string, opts?: { replace?: boolean }) => void;
}

const RouterContext = React.createContext<RouterContextValue | null>(null);

function parse(hash: string): RouteState {
  const raw = hash.replace(/^#/, "") || "/overview";
  const [pathPart, queryPart = ""] = raw.split("?");
  const path = pathPart.startsWith("/") ? pathPart : `/${pathPart}`;
  const segments = path.split("/").filter(Boolean);
  return { path, segments, query: new URLSearchParams(queryPart) };
}

export function RouterProvider({ children }: { children: React.ReactNode }) {
  const [state, setState] = React.useState<RouteState>(() => parse(window.location.hash));

  React.useEffect(() => {
    const onHash = () => setState(parse(window.location.hash));
    window.addEventListener("hashchange", onHash);
    if (!window.location.hash) window.location.replace("#/overview");
    return () => window.removeEventListener("hashchange", onHash);
  }, []);

  const navigate = React.useCallback((to: string, opts?: { replace?: boolean }) => {
    const target = `#${to.startsWith("/") ? to : `/${to}`}`;
    if (opts?.replace) window.location.replace(target);
    else window.location.hash = target;
    // Scroll main content back to the top on navigation
    document.getElementById("main-scroll")?.scrollTo({ top: 0 });
  }, []);

  const value = React.useMemo(() => ({ ...state, navigate }), [state, navigate]);
  return <RouterContext.Provider value={value}>{children}</RouterContext.Provider>;
}

export function useRouter() {
  const ctx = React.useContext(RouterContext);
  if (!ctx) throw new Error("useRouter must be used inside RouterProvider");
  return ctx;
}

/** Anchor that navigates via the hash router. */
export function Link({
  to,
  className,
  children,
  onClick,
  ...rest
}: React.AnchorHTMLAttributes<HTMLAnchorElement> & { to: string }) {
  const { navigate } = useRouter();
  return (
    <a
      href={`#${to}`}
      className={className}
      onClick={(e) => {
        onClick?.(e);
        if (e.defaultPrevented || e.metaKey || e.ctrlKey) return;
        e.preventDefault();
        navigate(to);
      }}
      {...rest}
    >
      {children}
    </a>
  );
}
