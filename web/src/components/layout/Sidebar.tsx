import * as React from "react";
import { ChevronsUpDown, ChevronLeft, ChevronRight, KeyRound, LogOut, UserRound, BellRing} from "lucide-react";
import { useQuery } from "@tanstack/react-query";

import { cn } from "@/lib/utils";
import { Link, useRouter } from "@/lib/router";
import { navGroups } from "@/lib/domain";
import { useAuth } from "@/lib/auth";
import { useMe } from "@/lib/queries";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Kbd, StatusDot } from "@/components/shared";

export const RAIL = 56;
export const FULL = 244;
const EASE = "cubic-bezier(0.4, 0, 0.2, 1)";
const DUR = 260;

/**
 * Label slot that animates its own width (1fr → 0fr). The icon keeps a fixed
 * position in both states, so collapsing never squishes or misplaces it.
 */
function LabelSlot({ open, children }: { open: boolean; children: React.ReactNode }) {
  return (
    <span
      className="min-w-0 overflow-hidden"
      style={{
        flex: open ? "1 1 auto" : "0 0 0px",
        width: open ? "auto" : 0,
        maxWidth: open ? 184 : 0,
        opacity: open ? 1 : 0,
        visibility: open ? "visible" : "hidden",
        transition: `max-width ${DUR}ms ${EASE}, opacity ${open ? 150 : 70}ms ease ${open ? 70 : 0}ms`,
      }}
      aria-hidden={!open}
    >
      <span
        className="block min-w-0 overflow-hidden whitespace-nowrap pl-2.5"
      >
        {children}
      </span>
    </span>
  );
}

interface SidebarUser {
  name?: string;
  email?: string;
}

export function Sidebar({ collapsed, onToggle, counts, user }: { collapsed: boolean; onToggle: () => void; counts: Record<string, number | string>; user?: SidebarUser }) {
  const { segments } = useRouter();
  const { logout } = useAuth();
  const me = useMe();
  const healthz = useQuery({
    queryKey: ["healthz"],
    queryFn: async (): Promise<{ version: string }> => {
      // healthz sits outside /api/v1 and outside auth (liveness probe).
      const res = await fetch("/healthz");
      return res.json();
    },
    staleTime: 5 * 60_000,
    retry: false,
  });
  const version = healthz.data?.version;
  const current = segments[0] ?? "overview";

  const orgRole = me.data?.organizations?.find((o) => o.id === me.data?.current_organization_id)?.role;
  const initials = (user?.name ?? user?.email ?? "U")
    .split(/[\s@.]+/).filter(Boolean).slice(0, 2).map((p) => p[0]?.toUpperCase()).join("");

  return (
    // Reserves real layout space in BOTH states — pinned-open pushes the page,
    // it never overlaps it.
    <aside
      className="relative z-30 h-full shrink-0"
      style={{ width: collapsed ? RAIL : FULL, transition: `width ${DUR}ms ${EASE}` }}
    >
      <div className="flex h-full w-full max-w-full flex-col overflow-hidden border-r border-sidebar-border bg-sidebar text-sidebar-foreground">
        {/* Brand */}
        <div className="flex h-14 shrink-0 items-center px-3">
          <div className="glow-primary flex size-8 shrink-0 items-center justify-center rounded-lg bg-gradient-to-br from-primary to-[oklch(0.55_0.2_300)] text-sm font-bold text-primary-foreground">
            Æ
          </div>
          <LabelSlot open={!collapsed}>
            <span className="block truncate text-sm font-semibold leading-tight text-foreground">Aegis</span>
            <span className="block truncate text-[10px] leading-tight text-muted-foreground">
              {version ? `v${version}` : "security platform"}{me.data?.organizations?.length ? ` · ${me.data.organizations.find((o) => o.id === me.data?.current_organization_id)?.name ?? "org"}` : ""}
            </span>
          </LabelSlot>
        </div>
        <div className="mx-3 h-px shrink-0 bg-sidebar-border" />

        {/* Nav */}
        <ScrollArea className="min-w-0 flex-1 overflow-x-hidden">
          <nav className="flex min-w-0 flex-col gap-3 overflow-hidden px-2 py-3">
            {navGroups.map((group, gi) => (
              <div key={gi} className="flex min-w-0 flex-col gap-0.5 overflow-hidden">
                {group.label && (
                  <div className="relative mx-1 h-5">
                    <span
                      className="absolute inset-x-2 top-0 whitespace-nowrap text-[10px] font-semibold uppercase leading-5 tracking-wider text-muted-foreground/70"
                      style={{ opacity: collapsed ? 0 : 1, transition: `opacity ${collapsed ? 80 : 160}ms ease ${collapsed ? 0 : 80}ms` }}
                    >
                      {group.label}
                    </span>
                    <span
                      className="absolute left-2.5 right-2.5 top-2.5 h-px bg-sidebar-border"
                      style={{ opacity: collapsed ? 1 : 0, transition: `opacity 140ms ease ${collapsed ? 120 : 0}ms` }}
                    />
                  </div>
                )}

                {group.items.map((item) => {
                  const active = current === item.id;
                  const count = counts[item.id];
                  const hasCount = count !== undefined && count !== 0;
                  const Icon = item.icon;
                  const tone =
                    item.id === "detections" && Number(count) > 0
                      ? "critical"
                      : item.id === "connections" && Number(count) > 0
                        ? "high"
                        : item.id === "scans" && Number(count) > 0
                          ? "primary"
                          : "muted";

                  const link = (
                    <Link
                      to={item.path}
                      className={cn(
                        "relative flex h-9 w-full min-w-0 max-w-full items-center overflow-hidden rounded-md px-3 text-[13px] font-medium transition-colors duration-150",
                        active ? "bg-sidebar-accent text-sidebar-accent-foreground" : "text-sidebar-foreground/75 hover:bg-sidebar-accent/60 hover:text-sidebar-accent-foreground"
                      )}
                    >
                      <Icon className={cn("size-4 shrink-0", active ? "text-primary" : "text-muted-foreground group-hover:text-foreground")} />
                      <LabelSlot open={!collapsed}>
                        <span className="block truncate">{item.label}</span>
                      </LabelSlot>

                      {hasCount && (
                        <>
                          {/* pill when expanded */}
                          {!collapsed && <span
                            className={cn(
                              "tabular shrink-0 overflow-hidden rounded-full text-[10px] font-semibold leading-4",
                              tone === "critical" && "bg-critical/15 text-critical",
                              tone === "high" && "bg-high/15 text-high",
                              tone === "primary" && "bg-primary/15 text-primary",
                              tone === "muted" && "bg-muted text-muted-foreground"
                            )}
                            style={{ paddingInline: 6 }}
                          >
                            {tone === "primary" ? (
                              <span className="flex items-center gap-1">
                                <StatusDot tone="primary" pulse className="size-1.5" /> {count}
                              </span>
                            ) : (
                              count
                            )}
                          </span>}
                          {/* alert dot when collapsed */}
                          {tone !== "muted" && (
                            <span
                              className={cn("absolute right-2 top-1.5 size-1.5 rounded-full", tone === "critical" && "bg-critical", tone === "high" && "bg-high", tone === "primary" && "bg-primary")}
                              style={{ opacity: collapsed ? 1 : 0, transition: `opacity 140ms ease ${collapsed ? 120 : 0}ms` }}
                            />
                          )}
                        </>
                      )}
                    </Link>
                  );

                  return collapsed ? (
                    <Tooltip key={item.id}>
                      <TooltipTrigger asChild>{link}</TooltipTrigger>
                      <TooltipContent side="right" sideOffset={10}>
                        <span className="font-medium">{item.label}</span>
                        {hasCount ? <span className="ml-1.5 opacity-70">{count}</span> : null}
                      </TooltipContent>
                    </Tooltip>
                  ) : (
                    <React.Fragment key={item.id}>{link}</React.Fragment>
                  );
                })}
              </div>
            ))}
          </nav>
        </ScrollArea>

        {/* User */}
        <div className="min-w-0 shrink-0 overflow-hidden border-t border-sidebar-border p-2">
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <button className="flex h-10 w-full min-w-0 max-w-full items-center overflow-hidden rounded-md px-1.5 text-left transition-colors hover:bg-sidebar-accent/60 cursor-pointer">
                <span className="flex size-7 shrink-0 items-center justify-center rounded-md bg-primary/15 text-xs font-semibold text-primary">{initials}</span>
                <LabelSlot open={!collapsed}>
                  <span className="flex items-center gap-1">
                    <span className="min-w-0 flex-1 leading-tight">
                      <span className="block truncate text-[13px] font-medium text-foreground">{user?.name ?? user?.email ?? "Account"}</span>
                      <span className="block truncate text-[11px] capitalize text-muted-foreground">{orgRole ? orgRole.replace("_", " ") : "member"}</span>
                    </span>
                    <ChevronsUpDown className="size-3.5 shrink-0 text-muted-foreground" />
                  </span>
                </LabelSlot>
              </button>
            </DropdownMenuTrigger>
            <DropdownMenuContent side="top" align="start" className="w-56">
              <DropdownMenuLabel className="font-normal">
                <div className="text-sm font-medium text-foreground">{user?.name ?? "Account"}</div>
                <div className="text-xs text-muted-foreground">{user?.email}</div>
              </DropdownMenuLabel>
              <DropdownMenuSeparator />
              <DropdownMenuItem asChild>
                <Link to="/settings?tab=account">
                  <UserRound /> My account
                </Link>
              </DropdownMenuItem>
              <DropdownMenuItem asChild>
                <Link to="/alerts?tab=destinations">
                  <BellRing /> Alerts &amp; destinations
                </Link>
              </DropdownMenuItem>
              <DropdownMenuSeparator />
              <DropdownMenuItem variant="destructive" onClick={() => void logout()}>
                <LogOut /> Sign out
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      </div>

      {/* The single expand/collapse control, sitting on the sidebar border */}
      <Tooltip>
        <TooltipTrigger asChild>
          <button
            onClick={onToggle}
            aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
            className="absolute -right-3 top-[68px] z-50 flex size-6 items-center justify-center rounded-full border bg-card text-muted-foreground shadow-md transition-colors duration-150 hover:border-primary/50 hover:text-foreground cursor-pointer"
          >
            {collapsed ? <ChevronRight className="size-3" /> : <ChevronLeft className="size-3" />}
          </button>
        </TooltipTrigger>
        <TooltipContent side="right" sideOffset={8}>
          {collapsed ? "Expand" : "Collapse"} sidebar <Kbd className="ml-1">[</Kbd>
        </TooltipContent>
      </Tooltip>
    </aside>
  );
}
