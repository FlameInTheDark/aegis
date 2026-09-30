import * as React from "react";
import { KeyRound, Loader2, MoreHorizontal, Plus, Search, UserRound, X } from "lucide-react";

import { timeAgo } from "@/lib/utils";
import { useScope } from "@/components/layout/AppShell";
import type { User } from "@/data/types";
import { useAuth } from "@/lib/auth";
import { useCreateUser, useMe, useResetUserPassword, useUpdateUser, useUsers } from "@/lib/queries";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";
import { toast } from "@/components/ui/toaster";
import { EmptyState, Mono, StateBadge, TableFooterBar, usePagination } from "@/components/shared";

export function UsersSection() {
  const me = useMe();
  const usersQ = useUsers();
  const createUser = useCreateUser();
  const updateUser = useUpdateUser();
  const resetPw = useResetUserPassword();
  const [invite, setInvite] = React.useState(false);
  const [email, setEmail] = React.useState("");
  const [name, setName] = React.useState("");
  const [role, setRole] = React.useState("operator");
  const [password, setPassword] = React.useState("");
  const [resetTarget, setResetTarget] = React.useState<User | null>(null);
  const [resetPwValue, setResetPwValue] = React.useState("");

  const users = usersQ.data ?? [];
  const pagedUsers = usePagination(users, "users");
  const myId = me.data?.user?.id;

  const inviteUser = () => {
    createUser.mutate(
      { email, name, role, password },
      {
        onSuccess: () => {
          toast({ title: "User created", description: `${name || email} can sign in now.`, variant: "success" });
          setInvite(false);
          setEmail("");
          setName("");
          setPassword("");
        },
        onError: (e) => toast({ title: "Invite failed", description: (e as Error).message, variant: "error" }),
      },
    );
  };

  const roleTone: Record<string, "primary" | "high" | "low" | "info"> = {
    owner: "primary",
    administrator: "primary",
    security_analyst: "low",
    operator: "high",
    viewer: "info",
  };

  return (
    <div className="flex flex-col gap-4">
      <div className="flex items-center justify-between">
        <div className="flex gap-2 text-xs">
          <Badge variant="outline" className="py-1">
            {users.filter((u) => u.status === "active").length} active
          </Badge>
          <Badge variant="outline" className="py-1">
            {users.filter((u) => u.status === "disabled").length} disabled
          </Badge>
        </div>
        <Button size="sm" onClick={() => setInvite(true)}>
          <Plus /> Add user
        </Button>
      </div>
      <div className="overflow-hidden rounded-xl border bg-card">
        <Table>
          <TableHeader>
            <TableRow className="hover:bg-transparent">
              <TableHead className="pl-4">User</TableHead>
              <TableHead>Role</TableHead>
              <TableHead>Status</TableHead>
              <TableHead>Last active</TableHead>
              <TableHead className="w-10" />
            </TableRow>
          </TableHeader>
          <TableBody>
            {pagedUsers.slice.map((u) => (
              <TableRow key={u.id}>
                <TableCell className="pl-4">
                  <div className="flex items-center gap-2.5">
                    <span className="flex size-7 items-center justify-center rounded-full bg-primary/15 text-[10px] font-semibold text-primary">
                      {u.name
                        .split(" ")
                        .map((p) => p[0])
                        .join("")
                        .slice(0, 2)}
                    </span>
                    <div className="leading-tight">
                      <div className="font-medium">
                        {u.name} {u.id === myId && <span className="text-xs text-muted-foreground">(you)</span>}
                      </div>
                      <div className="text-[11px] text-muted-foreground">{u.email}</div>
                    </div>
                  </div>
                </TableCell>
                <TableCell>
                  <Select
                    value={u.role}
                    onValueChange={(v) =>
                      updateUser.mutate(
                        { id: u.id, role: v },
                        {
                          onSuccess: () => toast({ title: "Role updated", variant: "success" }),
                          onError: (e) => toast({ title: "Role change failed", description: (e as Error).message, variant: "error" }),
                        },
                      )
                    }
                    disabled={u.id === myId}
                  >
                    <SelectTrigger size="sm" className="h-7 w-36 border-transparent bg-transparent text-xs hover:bg-accent/50">
                      <Badge variant={roleTone[u.role] ?? "info"} className="capitalize">
                        {u.role.replace("_", " ")}
                      </Badge>
                    </SelectTrigger>
                    <SelectContent>
                      {["owner", "administrator", "security_analyst", "operator", "viewer"].map((r) => (
                        <SelectItem key={r} value={r} className="capitalize">
                          {r.replace("_", " ")}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </TableCell>
                <TableCell>
                  <StateBadge label={u.status} tone={u.status === "active" ? "success" : "muted"} />
                </TableCell>
                <TableCell className="tabular text-xs text-muted-foreground">{u.lastActive ? timeAgo(u.lastActive) : "—"}</TableCell>
                <TableCell>
                  <DropdownMenu>
                    <DropdownMenuTrigger asChild>
                      <Button variant="ghost" size="icon-xs" className="text-muted-foreground">
                        <MoreHorizontal />
                      </Button>
                    </DropdownMenuTrigger>
                    <DropdownMenuContent align="end">
                      <DropdownMenuItem
                        onClick={() => {
                          setResetTarget(u);
                          setResetPwValue("");
                        }}
                      >
                        <KeyRound /> Reset password
                      </DropdownMenuItem>
                      <DropdownMenuSeparator />
                      {u.status === "disabled" ? (
                        <DropdownMenuItem
                          onClick={() =>
                            updateUser.mutate(
                              { id: u.id, disabled: false },
                              { onSuccess: () => toast({ title: "Account re-enabled", variant: "success" }) },
                            )
                          }
                        >
                          Re-enable
                        </DropdownMenuItem>
                      ) : (
                        <DropdownMenuItem
                          variant="destructive"
                          disabled={u.id === myId}
                          onClick={() =>
                            updateUser.mutate(
                              { id: u.id, disabled: true },
                              { onSuccess: () => toast({ title: "Account disabled", variant: "warning" }) },
                            )
                          }
                        >
                          Disable account
                        </DropdownMenuItem>
                      )}
                    </DropdownMenuContent>
                  </DropdownMenu>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
        {pagedUsers.slice.length > 0 && <TableFooterBar total={pagedUsers.total} page={pagedUsers.page} pageSize={pagedUsers.pageSize} onPage={pagedUsers.setPage} onPageSize={pagedUsers.setPageSize} label="users" />}
      </div>

      <Dialog open={invite} onOpenChange={setInvite}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Add user</DialogTitle>
            <DialogDescription>Creates the account with a temporary password. The user should change it after first sign-in.</DialogDescription>
          </DialogHeader>
          <div className="grid gap-3">
            <div className="grid gap-1.5">
              <Label>Email</Label>
              <Input type="email" value={email} onChange={(e) => setEmail(e.target.value)} placeholder="name@company.example" />
            </div>
            <div className="grid gap-1.5">
              <Label>Name</Label>
              <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="Full name" />
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div className="grid gap-1.5">
                <Label>Role</Label>
                <Select value={role} onValueChange={setRole}>
                  <SelectTrigger className="w-full">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="administrator">Administrator — full access incl. settings</SelectItem>
                    <SelectItem value="security_analyst">Analyst — triage findings &amp; detections</SelectItem>
                    <SelectItem value="operator">Operator — run scans, manage assets</SelectItem>
                    <SelectItem value="viewer">Viewer — read-only</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="grid gap-1.5">
                <Label>Temporary password</Label>
                <Input type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
              </div>
            </div>
          </div>
          <DialogFooter>
            <Button variant="ghost" onClick={() => setInvite(false)}>
              Cancel
            </Button>
            <Button onClick={inviteUser} disabled={!email.trim() || !password || createUser.isPending}>
              Create user
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={!!resetTarget} onOpenChange={(o) => !o && setResetTarget(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Reset password — {resetTarget?.name}</DialogTitle>
            <DialogDescription>Sets a new temporary password. All existing sessions keep working until their tokens expire.</DialogDescription>
          </DialogHeader>
          <Input type="password" value={resetPwValue} onChange={(e) => setResetPwValue(e.target.value)} placeholder="New temporary password" />
          <DialogFooter>
            <Button variant="ghost" onClick={() => setResetTarget(null)}>
              Cancel
            </Button>
            <Button
              disabled={!resetPwValue}
              onClick={() =>
                resetPw.mutate(
                  { id: resetTarget!.id, password: resetPwValue },
                  {
                    onSuccess: () => {
                      toast({ title: "Password reset", variant: "success" });
                      setResetTarget(null);
                    },
                    onError: (e: unknown) => toast({ title: "Reset failed", description: (e as Error).message, variant: "error" }),
                  },
                )
              }
            >
              Reset
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

