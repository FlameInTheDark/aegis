import * as React from "react";
import { Cloud, Github, RefreshCw, Ticket } from "lucide-react";

import { useAWSSync, useIntegration, useUpsertIntegration } from "@/lib/queries";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { toast } from "@/components/ui/toaster";

// F6 + F10 settings: tracker integrations for finding handoff and the AWS
// account connector. Secrets are stored server-side and returned masked.

export function IntegrationsSection() {
  return (
    <div className="flex flex-col gap-4">
      <TrackerCard kind="github" title="GitHub Issues" icon={<Github className="size-4" />}
        description="Create issues on findings. Needs a fine-grained token with Issues: write for the target repository." />
      <TrackerCard kind="jira" title="Jira" icon={<Ticket className="size-4" />}
        description="Create issues on findings. Uses the account email + API token (Basic auth against your site)." />
      <AwsCard />
    </div>
  );
}

function TrackerCard({ kind, title, description, icon }: {
  kind: "github" | "jira";
  title: string;
  description: string;
  icon: React.ReactNode;
}) {
  const integQ = useIntegration(kind);
  const upsert = useUpsertIntegration(kind);
  const [repo, setRepo] = React.useState("");
  const [site, setSite] = React.useState("");
  const [email, setEmail] = React.useState("");
  const [project, setProject] = React.useState("");
  const [secret, setSecret] = React.useState("");
  const [loaded, setLoaded] = React.useState(false);

  React.useEffect(() => {
    if (integQ.data && !loaded) {
      const cfg = (integQ.data.config ?? {}) as Record<string, string>;
      setRepo(cfg.repo ?? "");
      setSite(cfg.site ?? "");
      setEmail(cfg.email ?? "");
      setProject(cfg.project ?? "");
      setLoaded(true);
    }
  }, [integQ.data, loaded]);

  const save = () => {
    const config = kind === "github" ? { repo } : { site, email, project };
    upsert.mutate({ config, secret: secret || undefined }, {
      onSuccess: () => { setSecret(""); toast({ title: `${title} integration saved`, variant: "success" }); },
      onError: (e) => toast({ title: "Save failed", description: (e as Error).message, variant: "error" }),
    });
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-sm">{icon} {title}</CardTitle>
        <CardDescription className="text-xs">{description}</CardDescription>
      </CardHeader>
      <CardContent className="grid gap-3">
        {kind === "github" ? (
          <div className="grid gap-1.5">
            <Label htmlFor="gh-repo">Repository</Label>
            <Input id="gh-repo" value={repo} onChange={(e) => setRepo(e.target.value)} placeholder="owner/repo" className="font-mono text-xs" />
          </div>
        ) : (
          <>
            <div className="grid gap-1.5">
              <Label htmlFor="jira-site">Site</Label>
              <Input id="jira-site" value={site} onChange={(e) => setSite(e.target.value)} placeholder="https://example.atlassian.net" />
            </div>
            <div className="grid gap-1.5">
              <Label htmlFor="jira-email">Account email</Label>
              <Input id="jira-email" value={email} onChange={(e) => setEmail(e.target.value)} placeholder="bot@example.com" />
            </div>
            <div className="grid gap-1.5">
              <Label htmlFor="jira-project">Project key</Label>
              <Input id="jira-project" value={project} onChange={(e) => setProject(e.target.value)} placeholder="OPS" className="font-mono text-xs" />
            </div>
          </>
        )}
        <div className="grid gap-1.5">
          <Label htmlFor={`${kind}-secret`}>API token</Label>
          <Input
            id={`${kind}-secret`} type="password" value={secret}
            onChange={(e) => setSecret(e.target.value)}
            placeholder={integQ.data?.secretMasked ? `current: ${integQ.data.secretMasked} (leave empty to keep)` : "token"}
          />
        </div>
        <div className="flex items-center gap-2">
          <Button size="sm" onClick={save} disabled={upsert.isPending}>Save</Button>
          {integQ.data?.configured && (
            <span className="text-xs text-muted-foreground">Configured — findings can be handed off from the Findings page.</span>
          )}
        </div>
      </CardContent>
    </Card>
  );
}

function AwsCard() {
  const integQ = useIntegration("aws");
  const upsert = useUpsertIntegration("aws");
  const syncM = useAWSSync();
  const [region, setRegion] = React.useState("us-east-1");
  const [accessKey, setAccessKey] = React.useState("");
  const [siteId, setSiteId] = React.useState("");
  const [secret, setSecret] = React.useState("");
  const [loaded, setLoaded] = React.useState(false);

  React.useEffect(() => {
    if (integQ.data && !loaded) {
      const cfg = (integQ.data.config ?? {}) as Record<string, string>;
      setRegion(cfg.region ?? "us-east-1");
      setAccessKey(cfg.access_key ?? "");
      setSiteId(cfg.site_id ?? "");
      setLoaded(true);
    }
  }, [integQ.data, loaded]);

  const save = () => {
    upsert.mutate(
      { config: { region, access_key: accessKey, site_id: siteId }, secret: secret || undefined },
      { onSuccess: () => { setSecret(""); toast({ title: "AWS integration saved", variant: "success" }); },
        onError: (e) => toast({ title: "Save failed", description: (e as Error).message, variant: "error" }) },
    );
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-sm"><Cloud className="size-4" /> AWS (EC2 inventory)</CardTitle>
        <CardDescription className="text-xs">
          Read-only DescribeInstances sweep. Instances land as assets in the chosen site, correlated by instance id; public
          addresses set exposure on creation. Use a read-only IAM access key.
        </CardDescription>
      </CardHeader>
      <CardContent className="grid gap-3">
        <div className="grid grid-cols-2 gap-2">
          <div className="grid gap-1.5">
            <Label htmlFor="aws-region">Region</Label>
            <Input id="aws-region" value={region} onChange={(e) => setRegion(e.target.value)} placeholder="us-east-1" className="font-mono text-xs" />
          </div>
          <div className="grid gap-1.5">
            <Label htmlFor="aws-site">Site ID</Label>
            <Input id="aws-site" value={siteId} onChange={(e) => setSiteId(e.target.value)} placeholder="site the assets belong to" className="font-mono text-xs" />
          </div>
        </div>
        <div className="grid gap-1.5">
          <Label htmlFor="aws-access-key">Access key id</Label>
          <Input id="aws-access-key" value={accessKey} onChange={(e) => setAccessKey(e.target.value)} placeholder="AKIA…" className="font-mono text-xs" />
        </div>
        <div className="grid gap-1.5">
          <Label htmlFor="aws-secret">Secret access key</Label>
          <Input
            id="aws-secret" type="password" value={secret} onChange={(e) => setSecret(e.target.value)}
            placeholder={integQ.data?.secretMasked ? `current: ${integQ.data.secretMasked} (leave empty to keep)` : "secret access key"}
          />
        </div>
        <div className="flex items-center gap-2">
          <Button size="sm" onClick={save} disabled={upsert.isPending}>Save</Button>
          <Button
            variant="outline" size="sm" onClick={() =>
              syncM.mutate(undefined, {
                onSuccess: (res) => toast({ title: "AWS sync complete", description: `${res.created} created · ${res.updated} updated`, variant: "success" }),
                onError: (e) => toast({ title: "AWS sync failed", description: (e as Error).message, variant: "error" }),
              })
            }
            disabled={!integQ.data?.configured || syncM.isPending}
          >
            <RefreshCw className={syncM.isPending ? "size-4 animate-spin" : "size-4"} /> Sync now
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}
