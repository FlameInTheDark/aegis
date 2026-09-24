import * as React from "react";
import { Loader2, Lock, ShieldCheck } from "lucide-react";

import { useAuth } from "@/lib/auth";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Kbd } from "@/components/shared";

/** Full-screen login in the platform's visual language. */
export function LoginPage() {
  const { login } = useAuth();
  const [email, setEmail] = React.useState("");
  const [password, setPassword] = React.useState("");
  const [error, setError] = React.useState("");
  const [busy, setBusy] = React.useState(false);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (busy) return;
    setError("");
    setBusy(true);
    try {
      await login(email.trim(), password);
    } catch (err) {
      const msg = err instanceof Error ? err.message : "Login failed";
      setError(/credentials|unauthorized|401/i.test(msg) ? "Invalid email or password." : msg);
      setBusy(false);
    }
  };

  return (
    <div className="relative flex min-h-screen items-center justify-center overflow-hidden bg-background p-4">
      {/* Ambient brand glow */}
      <div aria-hidden className="pointer-events-none absolute -top-40 left-1/2 h-130 w-200 -translate-x-1/2 rounded-full bg-primary/10 blur-[120px]" />
      <div aria-hidden className="pointer-events-none absolute bottom-0 right-0 h-80 w-80 rounded-full bg-primary/5 blur-[100px]" />

      <div className="relative w-full max-w-sm">
        <div className="mb-6 flex flex-col items-center gap-3 text-center">
          <div className="glow-primary flex size-12 items-center justify-center rounded-xl bg-gradient-to-br from-primary to-[oklch(0.55_0.2_300)] text-lg font-bold text-primary-foreground">
            Æ
          </div>
          <div>
            <h1 className="text-lg font-semibold tracking-tight">Aegis Security Platform</h1>
            <p className="mt-1 text-sm text-muted-foreground">Sign in to your workspace</p>
          </div>
        </div>

        <form
          onSubmit={submit}
          className="rounded-xl border bg-card p-6 shadow-lg"
        >
          <div className="flex flex-col gap-4">
            <div className="flex flex-col gap-2">
              <Label htmlFor="email">Email</Label>
              <Input
                id="email"
                type="email"
                autoComplete="username"
                placeholder="you@company.com"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
                autoFocus
              />
            </div>
            <div className="flex flex-col gap-2">
              <Label htmlFor="password">Password</Label>
              <Input
                id="password"
                type="password"
                autoComplete="current-password"
                placeholder="••••••••••••"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
              />
            </div>

            {error && (
              <div role="alert" className="rounded-md border border-destructive/30 bg-destructive/10 px-3 py-2 text-[13px] text-destructive">
                {error}
              </div>
            )}

            <Button type="submit" className="mt-1 w-full gap-2" disabled={busy || !email || !password}>
              {busy ? <Loader2 className="size-4 animate-spin" /> : <Lock className="size-4" />}
              {busy ? "Signing in…" : "Sign in"}
            </Button>
          </div>
        </form>

        <p className="mt-4 flex items-center justify-center gap-1.5 text-center text-[11px] text-muted-foreground">
          <ShieldCheck className="size-3" />
          Sessions rotate automatically · all actions audited
        </p>
        <p className="mt-2 flex items-center justify-center gap-1 text-center text-[11px] text-muted-foreground/70">
          Press <Kbd>⏎</Kbd> to continue
        </p>
      </div>
    </div>
  );
}
