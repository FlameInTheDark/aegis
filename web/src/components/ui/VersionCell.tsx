import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import type { Software, Port } from "@/data/types";

type VersionMeta = NonNullable<Software["versionMeta"]>;

/**
 * VersionCell renders one version value with its full normalization
 * picture on hover/focus: the verbatim reported string, the normalized
 * form CVE matching actually compares, and the parsed epoch/upstream/
 * revision breakdown behind it. The bubble is a Radix tooltip rendered
 * through a portal with collision-aware placement — the previous pure-CSS
 * implementation was an absolutely-positioned span inside the table's
 * overflow-x-auto container, so table edges clipped it and the content
 * became unreadable. Without meta it renders the raw value plainly:
 * nothing to explain.
 *
 * Display order: the UPSTREAM version first (the clean version the
 * project actually published, without distro epoch/revision mangling);
 * when there is none, the normalized form (what CVE matching runs on);
 * otherwise the verbatim reported string.
 */
export function VersionCell({
  version,
  meta,
}: {
  version?: string;
  meta?: Port["versionMeta"];
}) {
  const reported = meta?.raw ?? version ?? "";
  const normalized = meta?.normalized ?? "";
  if (!reported && !normalized) return <>—</>;
  const display = meta?.upstream || normalized || reported || "—";
  const parts = [
    meta?.epoch ? `epoch ${meta.epoch}` : "",
    meta?.upstream ? `upstream ${meta.upstream}` : "",
    meta?.revision ? `revision ${meta.revision}` : "",
  ].filter(Boolean);
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span
          tabIndex={0}
          className="cursor-help underline decoration-dotted underline-offset-2 outline-none data-[state=delayed-open]:text-primary focus-visible:text-primary"
          aria-label={`Version ${display}.${meta?.upstream ? ` Upstream: ${meta.upstream}.` : ""} Reported: ${reported || "unknown"}.${normalized ? ` Normalized for CVE matching: ${normalized}.` : ""}`}
        >
          {display}
        </span>
      </TooltipTrigger>
      {/* [&>svg]:hidden drops the shared dark Arrow — it would render as a
          dark triangle against this popover-toned bubble. */}
      <TooltipContent
        side="bottom"
        sideOffset={6}
        collisionPadding={12}
        className="w-max max-w-[360px] border bg-popover p-2.5 text-left text-[11.5px] font-normal normal-case text-popover-foreground shadow-lg [&>svg]:hidden"
      >
        <span className="block text-[10px] uppercase tracking-wider text-muted-foreground">Version details</span>
        {meta?.upstream && (
          <span className="mt-1.5 block">
            <span className="text-muted-foreground">Upstream: </span>
            <span className="break-all font-mono text-[11px]">{meta.upstream}</span>
            <span className="ml-1 text-muted-foreground/70">— shown first</span>
          </span>
        )}
        <span className="mt-1.5 block">
          <span className="text-muted-foreground">Reported: </span>
          <span className="break-all font-mono text-[11px]">{reported || "—"}</span>
        </span>
        {normalized && (
          <span className="mt-0.5 block">
            <span className="text-muted-foreground">Normalized: </span>
            <span className="break-all font-mono text-[11px]">{normalized}</span>
            {normalized !== reported && <span className="ml-1 text-muted-foreground/70">— compared for CVE matching</span>}
          </span>
        )}
        {parts.length > 0 && (
          <span className="mt-0.5 block">
            <span className="text-muted-foreground">Structure: </span>
            <span className="font-mono text-[11px]">{parts.join(" · ")}</span>
          </span>
        )}
        {meta && (
          <span className="mt-1 block text-muted-foreground/70">
            grammar <span className="font-mono">{meta.grammar}</span> ·{" "}
            {meta.wellFormed ? (
              <span className="text-success">well-formed</span>
            ) : (
              <span className="text-critical">malformed — excluded from matching</span>
            )}
          </span>
        )}
      </TooltipContent>
    </Tooltip>
  );
}
