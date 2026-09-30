import * as React from "react";
import { KeyRound, Trash2 } from "lucide-react";

import { useDeleteSSO, useOrgSSO, useUpsertSSO } from "@/lib/queries";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { toast } from "@/components/ui/toaster";
import { Mono } from "@/components/shared";

// F4 (SSO first slice): one OIDC provider per organization. Local
// break-glass accounts keep password login; the owner role is never granted
// through a group claim, and users must already hold a membership in this
// organization unless JIT provisioning is on.

export function SsoSection() {
  const ssoQ = useOrgSSO();
  const upsert = useUpsertSSO();
  const del = useDeleteSSO();
  const [issuer, setIssuer] = React.useState("");
  const [clientId, setClientId] = React.useState("");
  const [clientSecret, setClientSecret] = React.useState("");
  const [defaultRole, setDefaultRole] = React.useState("viewer");
  const [mapping, setMapping] = React.useState("");
  const [allowJIT, setAllowJIT] = React.useState(true);
  const [loaded, setLoaded] = React.useState(false);

  React.useEffect(() => {
    if (ssoQ.data && !loaded) {
      setIssuer(ssoQ.data.issuer ?? "");
      setClientId(ssoQ.data.clientId ?? "");
      setDefaultRole(ssoQ.data.defaultRole ?? "viewer");
      setAllowJIT(ssoQ.data.allowJIT ?? true);
      const rm = ssoQ.data.roleMappings ?? {};
      setMapping(Object.entries(rm).map(([g, r]) => `${g}=${r}`).join("\n"));
      setLoaded(true);
    }
  }, [ssoQ.data, loaded]);

  const parseMappings = (): Record<string, string> | undefined => {
    const out: Record<string, string> = {};
    for (const line of mapping.split("\n")) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      const [g, r] = trimmed.split("=");
      if (!g?.trim() || !r?.trim()) {
        toast({ title: "Role mapping error", description: `Line "${trimmed}" must be group=role.`, variant: "error" });
        return undefined;
      }
      out[g.trim()] = r.trim();
    }
    return out;
  };

  const save = () => {
    const roleMappings = parseMappings();
    if (roleMappings === undefined) return;
    upsert.mutate(
      {
        issuer: issuer.trim(), client_id: clientId.trim(),
        client_secret: clientSecret || undefined,
        groups_claim: "groups", role_mappings: roleMappings,
        default_role: defaultRole, allow_jit: allowJIT, enabled: true,
      },
      {
        onSuccess: () => { setClientSecret(""); toast({ title: "SSO provider saved", variant: "success" }); },
        onError: (e) => toast({ title: "Save failed", description: (e as Error).message, variant: "error" }),
      },
    );
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-sm"><KeyRound className="size-4" /> Single sign-on (OIDC)</CardTitle>
        <CardDescription className="text-xs">
          One OpenID Connect provider for this organization. The login page shows a "Sign in with SSO" action for every enabled
          provider. Local password login stays available for break-glass accounts.
        </CardDescription>
      </CardHeader>
      <CardContent className="grid gap-3">
        <div className="grid gap-1.5">
          <Label htmlFor="sso-issuer">Issuer URL</Label>
          <Input id="sso-issuer" value={issuer} onChange={(e) => setIssuer(e.target.value)} placeholder="https://idp.example.com/realms/main" />
          <p className="text-[11px] text-muted-foreground">Discovery is read from <Mono>{issuer || "…"}/.well-known/openid-configuration</Mono>.</p>
        </div>
        <div className="grid grid-cols-2 gap-2">
          <div className="grid gap-1.5">
            <Label htmlFor="sso-client">Client id</Label>
            <Input id="sso-client" value={clientId} onChange={(e) => setClientId(e.target.value)} placeholder="aegis-console" />
          </div>
          <div className="grid gap-1.5">
            <Label htmlFor="sso-secret">Client secret</Label>
            <Input
              id="sso-secret" type="password" value={clientSecret} onChange={(e) => setClientSecret(e.target.value)}
              placeholder={ssoQ.data?.clientSecretMasked ? `current: ${ssoQ.data.clientSecretMasked} (leave empty to keep)` : "client secret"}
            />
          </div>
        </div>
        <div className="grid gap-1.5">
          <Label htmlFor="sso-redirect">Redirect URI to register at the provider</Label>
          <Mono className="rounded border bg-muted/30 px-2 py-1 text-[11px]">
            {typeof window !== "undefined" ? `${window.location.protocol}//${window.location.host}` : ""}/api/v1/auth/oidc/callback
          </Mono>
        </div>
        <div className="grid gap-1.5">
          <Label htmlFor="sso-mapping">Group → role mappings (one per line, group=role)</Label>
          <textarea
            id="sso-mapping" value={mapping} onChange={(e) => setMapping(e.target.value)} rows={4}
            placeholder={"soc-team=security_analyst\noperators=operator"}
            className="w-full rounded-md border bg-transparent px-3 py-2 font-mono text-xs"
          />
          <p className="text-[11px] text-muted-foreground">
            Allowed roles: viewer, operator, security_analyst, administrator. <b>Owner can never be granted by a claim.</b> The
            first matching group wins; unmapped logins get the default role. Existing users keep their database role.
          </p>
        </div>
        <div className="grid gap-1.5">
          <Label htmlFor="sso-role">Default role for unmapped logins</Label>
          <Input id="sso-role" value={defaultRole} onChange={(e) => setDefaultRole(e.target.value)} placeholder="viewer" />
        </div>
        <label className="flex items-center gap-2 text-sm">
          <Switch checked={allowJIT} onCheckedChange={(v) => setAllowJIT(!!v)} />
          Just-in-time provisioning (create the local account on first SSO login)
        </label>
        <div className="flex items-center gap-2">
          <Button size="sm" onClick={save} disabled={upsert.isPending || !issuer.trim() || !clientId.trim()}>Save</Button>
          {ssoQ.data?.configured && (
            <Button
              variant="outline" size="sm" onClick={() =>
                del.mutate(undefined, { onSuccess: () => toast({ title: "SSO provider removed" }) })
              }
              disabled={del.isPending}
            >
              <Trash2 className="size-4" /> Remove provider
            </Button>
          )}
          {ssoQ.data?.configured && ssoQ.data.enabled && (
            <span className="text-xs text-muted-foreground">Enabled — members see "Sign in with SSO" on the login page.</span>
          )}
        </div>
      </CardContent>
    </Card>
  );
}
