import * as React from "react";
import { Copy, Play, Plus, Radio, Trash2 } from "lucide-react";

import { formatDateTime, timeAgo } from "@/lib/utils";
import {
  useCreateIngestToken, useIngestTokens, useRevokeIngestToken, useTestIngest,
} from "@/lib/queries";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { toast } from "@/components/ui/toaster";
import { Mono } from "@/components/shared";

// F11 (sensor setup that finishes in the console): create hashed, revocable
// ingest tokens, copy a ready Vector/Filebeat snippet, and push the shipped
// sample files through the real pipeline tagged synthetic — so the Events
// page lights up before a real sensor is ever connected.

const SAMPLE_SNIPPET = (base: string, token: string) => `# Vector — Suricata EVE + Zeek logs -> Aegis
[sources.suricata]
type = "file"
include = ["/var/log/suricata/eve.json"]
read_from = "beginning"

[sources.zeek]
type = "file"
include = ["/usr/local/zeek/logs/current/*.log"]
read_from = "beginning"

[sinks.aegis]
type = "http"
inputs = ["suricata", "zeek"]
uri = "${base}/api/v1/ingest/events?source=suricata"
method = "post"
headers.Authorization = "Bearer ${token}"
compression = "none"

[sinks.aegis.encoding]
codec = "json"`;

const FILEBEAT_SNIPPET = (base: string, token: string) => `# Filebeat — Suricata EVE -> Aegis
filebeat.inputs:
  - type: filestream
    id: suricata-eve
    paths:
      - /var/log/suricata/eve.json
output.http:
  host: "${base}/api/v1/ingest/events?source=suricata"
  headers:
    Authorization: "Bearer ${token}"
  codec: json`;

export function SensorsSection() {
  const tokensQ = useIngestTokens();
  const createM = useCreateIngestToken();
  const revokeM = useRevokeIngestToken();
  const testM = useTestIngest();
  const [name, setName] = React.useState("");
  const [createdToken, setCreatedToken] = React.useState<string | null>(null);
  const base = typeof window !== "undefined" ? `${window.location.protocol}//${window.location.host}` : "";

  const create = () => {
    createM.mutate(name.trim(), {
      onSuccess: (res) => {
        setCreatedToken(res.token_plain);
        setName("");
        toast({ title: "Ingest token created", description: "Copy it now — it is shown only once.", variant: "success" });
      },
      onError: (e) => toast({ title: "Token create failed", description: (e as Error).message, variant: "error" }),
    });
  };

  const test = (source: "suricata" | "zeek" | "snort") => {
    testM.mutate(source, {
      onSuccess: (res) =>
        toast({ title: `Test ingest accepted (${res.accepted} events)`, description: "Tagged synthetic — watch the Events page.", variant: "success" }),
      onError: (e) => toast({ title: "Test ingest failed", description: (e as Error).message, variant: "error" }),
    });
  };

  return (
    <div className="flex flex-col gap-4">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-sm"><Radio className="size-4" /> Ingest tokens</CardTitle>
          <CardDescription className="text-xs">
            Sensors authenticate with <Mono>Authorization: Bearer aeg_evt_…</Mono> against <Mono>POST /api/v1/ingest/events?source=…</Mono>.
            Tokens are stored hashed, shown once, and revocable.
          </CardDescription>
        </CardHeader>
        <CardContent className="grid gap-3">
          <div className="flex items-end gap-2">
            <div className="grid flex-1 gap-1.5">
              <Label htmlFor="token-name">Token name</Label>
              <Input id="token-name" value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. edge-sensor-1" />
            </div>
            <Button size="sm" onClick={create} disabled={!name.trim() || createM.isPending}>
              <Plus className="size-4" /> Create token
            </Button>
          </div>
          {createdToken && (
            <div className="rounded-lg border border-warning/40 bg-warning/10 p-2.5">
              <div className="mb-1 flex items-center justify-between">
                <p className="text-xs font-semibold">Copy this token now — it will not be shown again</p>
                <Button
                  variant="ghost" size="icon-xs" aria-label="Copy token"
                  onClick={() => { navigator.clipboard?.writeText(createdToken); toast({ title: "Copied" }); }}
                >
                  <Copy className="size-3.5" />
                </Button>
              </div>
              <p className="break-all font-mono text-xs">{createdToken}</p>
            </div>
          )}
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Prefix</TableHead>
                <TableHead>Created</TableHead>
                <TableHead>Last event</TableHead>
                <TableHead>Status</TableHead>
                <TableHead />
              </TableRow>
            </TableHeader>
            <TableBody>
              {(tokensQ.data ?? []).map((t) => (
                <TableRow key={t.id}>
                  <TableCell className="text-sm">{t.name}</TableCell>
                  <TableCell><Mono className="text-xs">{t.prefix}</Mono></TableCell>
                  <TableCell className="text-xs text-muted-foreground">{formatDateTime(t.createdAt)}</TableCell>
                  <TableCell className="text-xs text-muted-foreground">
                    {t.lastUsedAt ? timeAgo(t.lastUsedAt) : "never"}
                  </TableCell>
                  <TableCell>
                    {t.revokedAt ? <Badge variant="outline">revoked</Badge> : <Badge variant="outline" className="text-success">active</Badge>}
                  </TableCell>
                  <TableCell className="text-right">
                    {!t.revokedAt && (
                      <Button
                        variant="ghost" size="icon-xs" aria-label={`Revoke ${t.name}`}
                        onClick={() => revokeM.mutate(t.id, { onSuccess: () => toast({ title: "Token revoked" }) })}
                      >
                        <Trash2 />
                      </Button>
                    )}
                  </TableCell>
                </TableRow>
              ))}
              {(tokensQ.data ?? []).length === 0 && (
                <TableRow>
                  <TableCell colSpan={6} className="py-8 text-center text-sm text-muted-foreground">
                    No tokens yet. Create one to connect a sensor.
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-sm">Test ingest</CardTitle>
          <CardDescription className="text-xs">
            Sends the shipped sample file through the real pipeline, tagged <Mono>synthetic</Mono> so it never reads as real telemetry.
          </CardDescription>
        </CardHeader>
        <CardContent className="flex gap-2">
          {(["suricata", "zeek", "snort"] as const).map((s) => (
            <Button key={s} variant="outline" size="sm" onClick={() => test(s)} disabled={testM.isPending}>
              <Play className="size-3.5" /> Send {s} sample
            </Button>
          ))}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-sm">Collector snippets</CardTitle>
          <CardDescription className="text-xs">Point a collector at the machine ingest endpoint with your token.</CardDescription>
        </CardHeader>
        <CardContent className="grid gap-3">
          {(["vector", "filebeat"] as const).map((tool) => {
            const text = tool === "vector" ? SAMPLE_SNIPPET(base, "aeg_evt_…") : FILEBEAT_SNIPPET(base, "aeg_evt_…");
            return (
              <div key={tool} className="rounded-lg border bg-muted/30 p-2.5">
                <div className="mb-1 flex items-center justify-between">
                  <p className="text-xs font-semibold capitalize">{tool}</p>
                  <Button
                    variant="ghost" size="icon-xs" aria-label={`Copy ${tool} snippet`}
                    onClick={() => { navigator.clipboard?.writeText(text); toast({ title: "Copied" }); }}
                  >
                    <Copy className="size-3.5" />
                  </Button>
                </div>
                <pre className="overflow-x-auto font-mono text-[11px] leading-relaxed text-muted-foreground">{text}</pre>
              </div>
            );
          })}
        </CardContent>
      </Card>
    </div>
  );
}
