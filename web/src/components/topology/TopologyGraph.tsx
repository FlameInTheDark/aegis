import * as React from "react";
import { Boxes, ChevronDown, ChevronUp, Info, Maximize2, Minus, Plus, RotateCcw, Server } from "lucide-react";

import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { assetTypeMeta } from "@/lib/domain";
import { colorOf, groupPalette, type GroupColor } from "@/lib/groups";
import { riskTone } from "@/components/shared";
import type { Asset } from "@/data/types";
import { cablePath, curvePath, type ArrangeMode, type Box, type LayoutResult, type Pt } from "@/lib/topology-graph";

/**
 * Graph canvas for the topology page — a faithful port of the
 * network-topology-view reference implementation (interaction + layout
 * rendering logic), wearing the platform's visual language: risk-filled
 * pins with a centred device-type icon, dot badges for group / agent /
 * findings state, and haloed name-first labels.
 *
 * Ported logic: cursor-anchored wheel zoom, pan, node dragging via offsets,
 * 380 ms layout interpolation (reduced-motion aware), hierarchy cable
 * routing with sibling lanes, hover neighbourhood isolation, route
 * lighting, collapse badges, minimap, keyboard walk (arrows / enter / f /
 * escape) and fitKey-driven refits.
 */

export interface GraphNode {
  asset: Asset;
  r: number;
  hub: boolean;
}

export interface GraphLink {
  id: string;
  source: string;
  target: string;
  /** observed traceroute route (confidence >= 0.8) vs inferred link */
  observed: boolean;
  /** analyst-pinned parent (asset override) — certain by decree, amber */
  manual?: boolean;
  confidence: number;
}

interface Tf {
  x: number;
  y: number;
  k: number;
}

/** imperative handle so the page's detail panel can drive the viewport */
export interface TopologyGraphHandle {
  centerOn: (id: string) => void;
  fit: () => void;
}

interface Props {
  nodes: GraphNode[];
  links: GraphLink[];
  mode: ArrangeMode;
  layout: LayoutResult;
  selectedId: string | null;
  trace: string[];
  collapsed: Set<string>;
  offsets: Record<string, Pt>;
  lit: { nodes: Set<string>; links: Set<string> } | null;
  matchSet: Set<string>;
  hasQuery: boolean;
  parentOf: (id: string) => string | undefined;
  /** collapsed- and filter-aware children (layout + badges + keyboard) */
  childrenOf: (id: string) => string[];
  /** static derived children, for cable lane indexing */
  childrenStatic: Record<string, string[]>;
  /** primary group colour per asset id — empty string when ungrouped
   *  (ungrouped pins carry no group dot) */
  groupColorOf: (id: string) => string;
  onSelect: (id: string | null) => void;
  onToggleTrace: (id: string) => void;
  onToggleCollapse: (id: string) => void;
  onMove: (id: string, ox: number, oy: number) => void;
  onResetLayout: () => void;
  onResetFilters: () => void;
  fitKey: string;
}

const riskFillOf = (risk: number) =>
  risk >= 80 ? "oklch(0.64 0.22 22)" : risk >= 60 ? "oklch(0.72 0.18 45)" : risk >= 35 ? "oklch(0.8 0.16 85)" : risk > 0 ? "oklch(0.74 0.12 230)" : "oklch(0.5 0.01 262)";

/** cable colours — saturated hues from the group palette instead of gray-on-gray:
 *  observed traceroute routes are solid cyan, inferred links dashed violet,
 *  analyst-pinned parents solid amber, and a selection keeps the indigo
 *  accent so it always wins attention. */
const EDGE_OBSERVED = "oklch(0.75 0.13 210)";
const EDGE_INFERRED = "oklch(0.68 0.19 305)";
const EDGE_MANUAL = "oklch(0.8 0.15 80)";
const EDGE_SELECTED = "oklch(0.66 0.17 275)";
const EDGE_HALO = "oklch(0.17 0.011 262)";
const EDGE_SHADOW = "oklch(0.09 0.012 262)";

/** box colors carry a palette key (groups) or a raw css color (sites) */
const boxSolid = (color: string): GroupColor | undefined => groupPalette.find((p) => p.id === color);

/* ------------------------------------------------------------------ */
/* render-cost containment                                             */
/* ------------------------------------------------------------------ */

/**
 * Device-glyph elements are cached per (icon, half-size, variant) and the
 * SAME React element object is reused across every pin that shows it.
 * React bails out of diffing identical element references, so a re-render
 * that touches all 60+ pins re-diffs zero glyph subtrees — the two-copy
 * dark/light look from v1.22.0 stays, its cost does not.
 */
const glyphCache = new WeakMap<React.ComponentType<any>, Map<string, React.ReactElement>>();
function pinGlyph(TypeIcon: React.ComponentType<any>, ir: number, variant: "under" | "over"): React.ReactElement {
  let m = glyphCache.get(TypeIcon);
  if (!m) {
    m = new Map();
    glyphCache.set(TypeIcon, m);
  }
  const key = `${ir}|${variant}`;
  let el = m.get(key);
  if (!el) {
    el = (
      <TypeIcon
        x={-ir}
        y={-ir}
        width={ir * 2}
        height={ir * 2}
        color={variant === "under" ? "oklch(0.14 0.02 262)" : "oklch(0.97 0.005 262)"}
        strokeWidth={variant === "under" ? 5 : 2.2}
      />
    );
    m.set(key, el);
  }
  return el;
}

interface PinVisProps {
  asset: Asset;
  r: number;
  hub: boolean;
  isSel: boolean;
  matched: boolean;
  hovered: boolean;
  traced: boolean;
  groupColor: string;
  kidsCount: number;
  isCollapsed: boolean;
  showName: boolean;
  showIp: boolean;
  onToggleCollapse: (id: string) => void;
}

/**
 * Everything inside a pin except the outer translate: halos, disc, glyph,
 * rim dots, collapse pill and labels. Memoized on primitives + the asset
 * object — a pan/zoom/animation frame only moves the outer translate, so
 * the whole subtree is skipped by React.memo.
 */
const PinVis = React.memo(function PinVis({
  asset: a, r, hub, isSel, matched, hovered, traced, groupColor, kidsCount, isCollapsed, showName, showIp, onToggleCollapse,
}: PinVisProps) {
  const fill = riskFillOf(a.risk);
  const TypeIcon = assetTypeMeta[a.type]?.icon ?? Boxes;
  // glyph half-size — the icon fills ~58% of the disc so the risk colour
  // still reads as a ring of colour around the device glyph
  const ir = Math.max(3.5, r * 0.58);
  // 45° rim point — corner badge centres straddle the disc edge
  const dd = r * 0.7071;
  // state strength: selection > search match > hub — all rendered as one
  // soft halo plus a gentle scale-up, never as extra circles
  const haloOp = isSel ? 1 : matched ? 0.7 : hub ? 0.5 : 0;
  const pinScale = isSel ? 1.12 : matched ? 1.06 : 1;
  return (
    <>
      {/* hover halo sits under everything so it never tints rings */}
      <circle r={r + 20} fill="oklch(0.66 0.17 275)" fillOpacity={hovered ? 0.07 : 0} style={{ transition: "fill-opacity 160ms" }} />
      {haloOp > 0 && <circle r={r + 16} fill="url(#pin-halo)" opacity={haloOp} />}
      {/* the pin — one disc + badges, scaling as ONE unit when selected or
          matched */}
      <g style={{ transform: `scale(${pinScale})`, transition: "transform 180ms ease" }}>
        {traced && <circle r={r + 6.5} fill="none" stroke="oklch(0.9 0.01 262)" strokeOpacity={0.75} strokeWidth={1} strokeDasharray="2 4" />}
        {/* the pin is ONE disc: risk colour fill, device glyph centred, no
            identity ring — the donut look is gone and the silhouette never
            exceeds a single circle + dots */}
        <circle r={r} fill={fill} stroke={isSel ? "white" : "oklch(0.13 0.01 262)"} strokeWidth={isSel ? 2.5 : 2} />
        <g pointerEvents="none">
          {/* dark under-stroke + light over-stroke keeps the glyph readable
              on every risk fill without any filter */}
          {pinGlyph(TypeIcon, ir, "under")}
          {pinGlyph(TypeIcon, ir, "over")}
        </g>
        {/* corner badges straddle the rim at 45°: findings top-right, agent
            bottom-right, group colour bottom-left — dots instead of rings,
            so the pin silhouette stays one circle */}
        {((a.findings?.critical ?? 0) > 0 || (a.findings?.high ?? 0) > 0) && (
          <circle cx={dd} cy={-dd} r={4} fill="oklch(0.64 0.22 22)" stroke="oklch(0.94 0.005 262)" strokeWidth={1.5} />
        )}
        {a.agentId && <circle cx={dd} cy={dd} r={3} fill="oklch(0.8 0.15 145)" stroke="oklch(0.13 0.01 262)" strokeWidth={1.25} />}
        {groupColor && <circle cx={-dd} cy={dd} r={3.5} fill={groupColor} stroke="oklch(0.13 0.01 262)" strokeWidth={1.25} />}
        {kidsCount > 0 && (
          <g
            /* collapse badge on the free top-left diagonal — the top-right
               one carries the findings dot */
            transform={`translate(${-(r * 0.7071 + 14)},${-(r * 0.7071 + 14)})`}
            onPointerDown={(e) => e.stopPropagation()}
            onClick={(e) => { e.stopPropagation(); onToggleCollapse(a.id); }}
            className="cursor-pointer"
          >
            <rect x={-13} y={-9} width={26} height={18} rx={9} fill="oklch(0.22 0.01 262)" stroke="oklch(0.35 0.02 262)" />
            <text textAnchor="middle" y={4} fontSize={10} fill="oklch(0.75 0.01 262)" fontFamily="JetBrains Mono, monospace">
              {isCollapsed ? `+${kidsCount}` : "–"}
            </text>
          </g>
        )}
      </g>
      {/* labels — the human name first, the technical ip second; a
          paint-order stroke halo keeps them readable over cables without
          any filter. At overview zoom the two-line label overlaps into
          noise, so the ip drops first (k < 0.55) and the name follows
          (k < 0.3), leaving clean pins. */}
      {showName && (
        <text
          y={r + 16}
          textAnchor="middle"
          fontSize={11}
          fontWeight={600}
          fill="oklch(0.87 0.01 262)"
          fontFamily="Inter, sans-serif"
          stroke="oklch(0.13 0.012 262)"
          strokeWidth={3}
          paintOrder="stroke"
          strokeLinejoin="round"
        >
          {a.hostname || a.ip}
        </text>
      )}
      {showIp && a.hostname && a.hostname !== a.ip && (
        <text
          y={r + 28}
          textAnchor="middle"
          fontSize={9.5}
          fill="oklch(0.62 0.01 262)"
          fontFamily="JetBrains Mono, monospace"
          stroke="oklch(0.13 0.012 262)"
          strokeWidth={2.5}
          paintOrder="stroke"
          strokeLinejoin="round"
        >
          {a.ip}
        </text>
      )}
    </>
  );
});

interface CableVisProps {
  link: GraphLink;
  d: string;
  /** group opacity — 1, or one of the two dim levels (lit route / hover) */
  dimOpacity: number;
  /** this cable carries the animated route flow */
  flow: boolean;
  /** selection endpoint — wins colour + weight */
  onHot: boolean;
  hoveredLink: boolean;
  wrapRef: React.RefObject<HTMLDivElement | null>;
  onEnter: (link: GraphLink, x: number, y: number) => void;
  onLeave: () => void;
}

/** One cable: halo + main stroke + optional route flow + the wide hit
 *  area. Memoized on (d + state flags) — panning re-diffs nothing here;
 *  dragging a node only re-renders the cables that actually reach it. */
const CableVis = React.memo(function CableVis({
  link, d, dimOpacity, flow, onHot, hoveredLink, wrapRef, onEnter, onLeave,
}: CableVisProps) {
  const dim = dimOpacity !== 1;
  const color = onHot ? EDGE_SELECTED : link.manual ? EDGE_MANUAL : link.observed ? EDGE_OBSERVED : EDGE_INFERRED;
  return (
    <g opacity={dimOpacity}>
      {/* halo separates the cable from the fill underneath */}
      <path d={d} stroke={EDGE_HALO} strokeWidth={hoveredLink ? 5.5 : onHot ? 5 : 3.5} strokeOpacity={0.85} />
      <path
        d={d}
        stroke={color}
        strokeWidth={hoveredLink ? 2.4 : onHot ? 2 : link.manual ? 1.6 : link.observed ? 1.5 : 1.3}
        strokeOpacity={dim ? 0.5 : onHot ? 1 : link.manual ? 0.95 : link.observed ? 0.9 : 0.62}
        strokeDasharray={!link.manual && !link.observed && !onHot ? "5 4" : undefined}
        markerEnd={onHot ? "url(#arrow-on)" : link.manual ? "url(#arrow-amber)" : link.observed ? "url(#arrow-teal)" : "url(#arrow-violet)"}
      />
      {flow && <path d={d} stroke={EDGE_SELECTED} strokeWidth={2.1} strokeOpacity={0.95} strokeDasharray="6 10" className="edge-flow" />}
      <path
        d={d}
        stroke="transparent"
        strokeWidth={16}
        style={{ cursor: "pointer" }}
        onPointerEnter={(e) => {
          const r = wrapRef.current?.getBoundingClientRect();
          if (r) onEnter(link, e.clientX - r.left, e.clientY - r.top);
        }}
        onPointerLeave={onLeave}
      />
    </g>
  );
});

const TopologyGraph = React.forwardRef<TopologyGraphHandle, Props>(function TopologyGraph(props, ref) {
  const {
    nodes, links, mode, layout, selectedId, trace, collapsed, offsets, lit, matchSet, hasQuery,
    parentOf, childrenOf, childrenStatic, groupColorOf,
    onSelect, onToggleTrace, onToggleCollapse, onMove, onResetLayout, onResetFilters, fitKey,
  } = props;

  const wrapRef = React.useRef<HTMLDivElement>(null);
  const [size, setSize] = React.useState({ w: 1000, h: 640 });
  const [tf, setTf] = React.useState<Tf>({ x: 0, y: 0, k: 0.8 });
  const [hoverId, setHoverId] = React.useState<string | null>(null);
  const [hoverLink, setHoverLink] = React.useState<{ link: GraphLink; x: number; y: number } | null>(null);
  const [tip, setTip] = React.useState<{ id: string; x: number; y: number } | null>(null);
  const dragRef = React.useRef<{ id: string | null; sx: number; sy: number; rl: number; rt: number; ox: number; oy: number; moved: boolean } | null>(null);
  const [dragging, setDragging] = React.useState(false);
  // legend collapsed by default — the full legend is long and rarely needs
  // to be visible; the choice persists per browser
  const [legendOpen, setLegendOpen] = React.useState(() => {
    try {
      return localStorage.getItem("aegis-topology-legend") === "open";
    } catch {
      return false;
    }
  });
  const toggleLegend = React.useCallback((open: boolean) => {
    setLegendOpen(open);
    try {
      localStorage.setItem("aegis-topology-legend", open ? "open" : "closed");
    } catch {
      /* private mode */
    }
  }, []);

  const activeSet = React.useMemo(() => new Set(nodes.map((n) => n.asset.id)), [nodes]);
  const assetById = React.useMemo(() => new Map(nodes.map((n) => [n.asset.id, n.asset])), [nodes]);

  // hovering isolates the neighbourhood; a lit route always wins over hover
  const hoverSet = React.useMemo(() => {
    if (!hoverId || lit) return null;
    const set = new Set<string>([hoverId]);
    for (const link of links) {
      if (link.source === hoverId) set.add(link.target);
      else if (link.target === hoverId) set.add(link.source);
    }
    return set;
  }, [hoverId, lit, links]);

  const layoutPositions = layout.nodes;

  // Nodes and cables interpolate together when the arrangement changes, so a
  // switch from Hierarchy to Radial reads as re-patching a panel (380ms).
  const animRef = React.useRef<Record<string, Pt>>({});
  const [anim, setAnim] = React.useState<Record<string, Pt>>({});
  React.useEffect(() => {
    const target = layoutPositions;
    const reduce = typeof window !== "undefined" && window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;
    if (reduce || dragging) {
      animRef.current = target;
      // while dragging, positions flow through layout directly (pos() reads
      // layout first) — skipping the anim write keeps a drag move at one
      // render instead of two
      if (!dragging) setAnim(target);
      return;
    }
    const from: Record<string, Pt> = {};
    let settled = true;
    for (const [id, p] of Object.entries(target)) {
      const a0 = animRef.current[id];
      from[id] = a0 ?? p;
      if (a0 && (Math.abs(a0.x - p.x) > 0.01 || Math.abs(a0.y - p.y) > 0.01)) settled = false;
    }
    // nothing visibly moved (drag end, filter no-op) — snap instead of
    // burning a 380ms rAF interpolation on an identity tween
    if (settled) {
      animRef.current = target;
      setAnim(target);
      return;
    }
    const t0 = performance.now();
    let frame = 0;
    const tick = (t: number) => {
      const k = Math.min(1, (t - t0) / 380);
      const e = 1 - Math.pow(1 - k, 3);
      const next: Record<string, Pt> = {};
      for (const [id, p] of Object.entries(target)) {
        const a = from[id];
        next[id] = a ? { x: a.x + (p.x - a.x) * e, y: a.y + (p.y - a.y) * e } : p;
      }
      animRef.current = next;
      setAnim(next);
      if (k < 1) frame = requestAnimationFrame(tick);
    };
    frame = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(frame);
  }, [layoutPositions, dragging]);

  // ---- viewport -----------------------------------------------------------
  React.useEffect(() => {
    const el = wrapRef.current;
    if (!el) return;
    const ro = new ResizeObserver(() => setSize({ w: el.clientWidth, h: el.clientHeight }));
    ro.observe(el);
    setSize({ w: el.clientWidth, h: el.clientHeight });
    return () => ro.disconnect();
  }, []);

  const fitTo = React.useCallback(
    (pad = 84) => {
      const b2 = layout.bounds;
      const bw = Math.max(1, b2.maxX - b2.minX);
      const bh = Math.max(1, b2.maxY - b2.minY);
      const k = Math.max(0.18, Math.min((size.w - pad * 2) / bw, (size.h - pad * 2) / bh, 1.35));
      setTf({ k, x: size.w / 2 - (b2.minX + bw / 2) * k, y: size.h / 2 - (b2.minY + bh / 2) * k });
    },
    [layout, size],
  );

  // fit is re-run on layout mode / filter changes only (never mid-drag)
  const fitRef = React.useRef(fitTo);
  fitRef.current = fitTo;
  React.useEffect(() => {
    fitTo(80);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [fitKey, size.w, size.h]);

  const zoomBy = React.useCallback(
    (factor: number, cx = size.w / 2, cy = size.h / 2) => {
      setTf((t) => {
        const k = Math.min(2.6, Math.max(0.18, t.k * factor));
        return { k, x: cx - ((cx - t.x) / t.k) * k, y: cy - ((cy - t.y) / t.k) * k };
      });
    },
    [size.w, size.h],
  );

  // Pan/zoom re-render is coalesced to one frame: high-Hz pointer/wheel
  // event storms would otherwise schedule a full component render per event.
  const tfRafRef = React.useRef<number | null>(null);
  const tfPendingRef = React.useRef<((t: Tf) => Tf) | null>(null);
  const setTfSoon = React.useCallback((updater: (t: Tf) => Tf) => {
    tfPendingRef.current = updater;
    if (tfRafRef.current == null) {
      tfRafRef.current = requestAnimationFrame(() => {
        tfRafRef.current = null;
        const up = tfPendingRef.current;
        tfPendingRef.current = null;
        if (up) setTf(up);
      });
    }
  }, []);
  React.useEffect(
    () => () => {
      if (tfRafRef.current != null) cancelAnimationFrame(tfRafRef.current);
    },
    [],
  );

  // wheel zoom at cursor (non-passive)
  React.useEffect(() => {
    const el = wrapRef.current;
    if (!el) return;
    const onWheel = (e: WheelEvent) => {
      e.preventDefault();
      const rect = el.getBoundingClientRect();
      const cx = e.clientX - rect.left;
      const cy = e.clientY - rect.top;
      const factor = Math.exp(-e.deltaY * 0.0016);
      setTfSoon((t) => {
        const k = Math.min(2.6, Math.max(0.18, t.k * factor));
        return { k, x: cx - ((cx - t.x) / t.k) * k, y: cy - ((cy - t.y) / t.k) * k };
      });
    };
    el.addEventListener("wheel", onWheel, { passive: false });
    return () => el.removeEventListener("wheel", onWheel);
  }, []);

  // ---- pointer: pan + node drag -------------------------------------------
  const onPointerDown = (e: React.PointerEvent) => {
    const target = e.target as Element;
    const nodeEl = target.closest("[data-node-id]");
    const rect = wrapRef.current!.getBoundingClientRect();
    if (nodeEl) {
      const id = nodeEl.getAttribute("data-node-id")!;
      dragRef.current = {
        id,
        sx: e.clientX - rect.left,
        sy: e.clientY - rect.top,
        rl: rect.left,
        rt: rect.top,
        ox: offsets[id]?.x ?? 0,
        oy: offsets[id]?.y ?? 0,
        moved: false,
      };
    } else {
      dragRef.current = { id: null, sx: e.clientX - rect.left, sy: e.clientY - rect.top, rl: rect.left, rt: rect.top, ox: tf.x, oy: tf.y, moved: false };
    }
    setDragging(true);
    (e.currentTarget as HTMLElement).setPointerCapture(e.pointerId);
  };

  const onPointerMove = (e: React.PointerEvent) => {
    const d = dragRef.current;
    if (!d) return;
    // rect cached at pointerdown — a layout read per move would force
    // reflow on every pointer event
    const dx = e.clientX - d.rl - d.sx;
    const dy = e.clientY - d.rt - d.sy;
    if (Math.abs(dx) > 3 || Math.abs(dy) > 3) d.moved = true;
    if (d.id) {
      onMove(d.id, d.ox + dx / tf.k, d.oy + dy / tf.k);
    } else {
      setTfSoon((t) => ({ ...t, x: d.ox + dx, y: d.oy + dy }));
    }
  };

  const onPointerUp = (e: React.PointerEvent) => {
    const d = dragRef.current;
    dragRef.current = null;
    setDragging(false);
    (e.currentTarget as HTMLElement).releasePointerCapture?.(e.pointerId);
    if (d && d.id && !d.moved) {
      if (e.shiftKey) onToggleTrace(d.id);
      else onSelect(selectedId === d.id ? null : d.id);
    } else if (d && !d.id && !d.moved) {
      onSelect(null);
    }
  };

  const moveFocus = (dir: "up" | "down" | "left" | "right") => {
    const cur = selectedId ?? hoverId;
    if (!cur) return;
    if (dir === "up") {
      const par = parentOf(cur);
      if (par && activeSet.has(par)) return onSelect(par);
    }
    if (dir === "down") {
      const kids = childrenOf(cur);
      if (kids.length) return onSelect(kids[0]);
    }
    const par = parentOf(cur);
    const sibs = par ? childrenOf(par) : [];
    if (sibs.length > 1) {
      const sorted = sibs.slice().sort((a, b) => (layoutPositions[a]?.x ?? 0) - (layoutPositions[b]?.x ?? 0));
      const i = sorted.indexOf(cur);
      const next = dir === "left" ? sorted[(i - 1 + sorted.length) % sorted.length] : sorted[(i + 1) % sorted.length];
      return onSelect(next);
    }
  };

  const onKeyDown = (e: React.KeyboardEvent) => {
    const map: Record<string, "up" | "down" | "left" | "right"> = {
      ArrowUp: "up", ArrowDown: "down", ArrowLeft: "left", ArrowRight: "right",
    };
    if (map[e.key]) {
      e.preventDefault();
      moveFocus(map[e.key]);
    } else if (e.key === "Enter" && selectedId) {
      e.preventDefault();
      onToggleTrace(selectedId);
    } else if (e.key === "Escape") {
      onSelect(null);
    } else if (e.key.toLowerCase() === "f") {
      e.preventDefault();
      fitRef.current();
    }
  };

  // ---- geometry helpers ---------------------------------------------------
  // while dragging, positions flow through layout (kept fresh per move);
  // otherwise the 380ms interpolation owns the picture
  const pos = (id: string): Pt =>
    dragging ? layoutPositions[id] ?? anim[id] ?? { x: 0, y: 0 } : anim[id] ?? layoutPositions[id] ?? { x: 0, y: 0 };
  // pin radius per asset — cables trim to the real rim, not a hardcoded guess
  const rOf = React.useMemo(() => {
    const m = new Map<string, number>();
    for (const n of nodes) m.set(n.asset.id, n.r);
    return m;
  }, [nodes]);
  const edgePath = (link: GraphLink) => {
    const a = pos(link.source);
    const b = pos(link.target);
    if (mode !== "hierarchy") return curvePath(a, b, mode);
    const isTreeEdge = parentOf(link.source) === link.target;
    if (!isTreeEdge) return curvePath(a, b, mode);
    // land ON the pin rim: radius + disc stroke + ~2px of breathing, with a
    // nudge for the gentle scale-up of a selected pin (the vertical
    // short-circuit for stacked nodes lives inside cablePath)
    const trim = (id: string) => (rOf.get(id) ?? 10) + 3 + (selectedId === id ? 1.2 : 0);
    const sibs = (childrenStatic[link.target] ?? []).filter((id) => activeSet.has(id));
    const idx = Math.max(0, sibs.indexOf(link.source));
    const xs = sibs.map((id) => pos(id).x).concat(b.x);
    const left = a.x < b.x;
    const lane = (idx % 3) * 9 * (left ? -1 : 1);
    const gutterX = (left ? Math.min(...xs) - 62 : Math.max(...xs) + 62) + lane;
    return cablePath(a, b, gutterX, trim(link.source), trim(link.target));
  };
  const isDimNode = (id: string) =>
    (lit ? !lit.nodes.has(id) : hoverSet ? !hoverSet.has(id) : false) || (hasQuery && !matchSet.has(id));
  const isDimLink = (link: GraphLink) =>
    lit ? !lit.links.has(link.id) : hoverSet ? !(link.source === hoverId || link.target === hoverId) : false;

  /** cables that must paint above their siblings: selection, pinned-route and
   *  hover — otherwise a later cable's halo silences the flow animation */
  const isHotLink = (link: GraphLink) =>
    selectedId === link.source || selectedId === link.target || hoverLink?.link.id === link.id || (!!lit && lit.links.has(link.id));

  const b = layout.bounds;
  const worldW = Math.max(1, b.maxX - b.minX);
  const worldH = Math.max(1, b.maxY - b.minY);
  const MINI_W = 168;
  const MINI_H = Math.max(76, Math.min(132, (MINI_W * worldH) / worldW));
  const ms = Math.min(MINI_W / worldW, MINI_H / worldH);
  const mx = (MINI_W - worldW * ms) / 2;
  const my = (MINI_H - worldH * ms) / 2;
  const viewRect = {
    x: (-tf.x / tf.k - b.minX) * ms + mx,
    y: (-tf.y / tf.k - b.minY) * ms + my,
    w: (size.w / tf.k) * ms,
    h: (size.h / tf.k) * ms,
  };

  const minimapJump = (e: React.PointerEvent) => {
    const el = e.currentTarget as HTMLElement;
    const r = el.getBoundingClientRect();
    const wx = (e.clientX - r.left - mx) / ms + b.minX;
    const wy = (e.clientY - r.top - my) / ms + b.minY;
    setTfSoon((t) => ({ ...t, x: size.w / 2 - wx * t.k, y: size.h / 2 - wy * t.k }));
  };

  React.useImperativeHandle(ref, () => ({
    centerOn: (id: string) => {
      const p = pos(id);
      setTf((t) => ({ ...t, x: size.w / 2 - p.x * t.k, y: size.h / 2 - p.y * t.k }));
    },
    fit: () => fitTo(),
  }));

  const hovered = hoverId ? assetById.get(hoverId) : null;
  const linkIp = (id: string) => assetById.get(id)?.ip ?? id;

  const renderBox = (box: Box) => {
    const c = boxSolid(box.color);
    const solid = c ? c.solid : box.color;
    return (
      <g key={`box-${box.id}`}>
        <rect
          x={box.x} y={box.y} width={box.w} height={box.h} rx={16}
          fill={c ? c.soft : solid} fillOpacity={c ? 0.5 : 0.06}
          stroke={solid} strokeOpacity={0.42} strokeWidth={1.4}
        />
        {/* header: title left, member count right — both carry a paint-order
            stroke halo so they lift off the tray fill; no separator, the
            tray reads as one continuous card. (Was an feDropShadow filter —
            removed because filters re-rasterize on every animation frame.) */}
        <text
          x={box.x + 16} y={box.y + 30} fontSize={13} fontWeight={600} fill={solid} fontFamily="Inter, sans-serif"
          stroke={EDGE_SHADOW} strokeWidth={2.6} paintOrder="stroke" strokeLinejoin="round"
        >
          {box.title}
        </text>
        <g>
          <rect x={box.x + box.w - 42} y={box.y + 18} width={26} height={15} rx={7.5} fill={solid} fillOpacity={0.14} stroke={solid} strokeOpacity={0.4} />
          <text x={box.x + box.w - 29} y={box.y + 28.5} textAnchor="middle" fontSize={9.5} fill={solid} fontFamily="JetBrains Mono, monospace">
            {box.count}
          </text>
        </g>
      </g>
    );
  };

  const handleLinkEnter = React.useCallback((link: GraphLink, x: number, y: number) => setHoverLink({ link, x, y }), []);
  const handleLinkLeave = React.useCallback(() => setHoverLink(null), []);
  // stable collapse handler — the page re-creates its callback per render,
  // which would otherwise defeat PinVis memoization on every page render
  const onToggleCollapseRef = React.useRef(onToggleCollapse);
  onToggleCollapseRef.current = onToggleCollapse;
  const collapseStable = React.useCallback((id: string) => onToggleCollapseRef.current(id), []);
  const renderLink = (link: GraphLink) => (
    <CableVis
      key={link.id}
      link={link}
      d={edgePath(link)}
      dimOpacity={isDimLink(link) ? (lit ? 0.13 : 0.4) : 1}
      flow={!!lit && lit.links.has(link.id)}
      onHot={selectedId === link.source || selectedId === link.target}
      hoveredLink={hoverLink?.link.id === link.id}
      wrapRef={wrapRef}
      onEnter={handleLinkEnter}
      onLeave={handleLinkLeave}
    />
  );

  return (
    <div
      ref={wrapRef}
      tabIndex={0}
      onKeyDown={onKeyDown}
      onPointerDown={onPointerDown}
      onPointerMove={onPointerMove}
      onPointerUp={onPointerUp}
      onPointerLeave={() => { setHoverId(null); setTip(null); setHoverLink(null); }}
      className={cn("grid-bg absolute inset-0 overflow-hidden rounded-xl border bg-card outline-none ring-primary/40 focus-visible:ring-1", dragging ? "cursor-grabbing" : "cursor-grab")}
    >
      <svg width="100%" height="100%" className="block select-none" style={{ touchAction: "none" }}>
        <defs>
          {/* soft halo under pins — selection / search match / hub speak
              through this gradient instead of extra rings or per-node blur
              filters, so a pin never wears more than two concentric circles */}
          <radialGradient id="pin-halo">
            <stop offset="45%" stopColor={EDGE_SELECTED} stopOpacity="0.32" />
            <stop offset="100%" stopColor={EDGE_SELECTED} stopOpacity="0" />
          </radialGradient>
          <marker id="arrow-teal" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="5" markerHeight="5" orient="auto-start-reverse">
            <path d="M 0 1.5 L 9 5 L 0 8.5 z" fill={EDGE_OBSERVED} />
          </marker>
          <marker id="arrow-violet" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="5" markerHeight="5" orient="auto-start-reverse">
            <path d="M 0 1.5 L 9 5 L 0 8.5 z" fill={EDGE_INFERRED} />
          </marker>
          <marker id="arrow-amber" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="5" markerHeight="5" orient="auto-start-reverse">
            <path d="M 0 1.5 L 9 5 L 0 8.5 z" fill={EDGE_MANUAL} />
          </marker>
          <marker id="arrow-on" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="5.5" markerHeight="5.5" orient="auto-start-reverse">
            <path d="M 0 1.5 L 9 5 L 0 8.5 z" fill={EDGE_SELECTED} />
          </marker>
        </defs>

        <g transform={`translate(${tf.x},${tf.y}) scale(${tf.k})`}>
          {/* links — the deepest layer, below everything else, so a cable
              never covers tray labels; hot cables (selected / lit route /
              hovered) render last within the layer so the flow animation is
              never overlapped. No shadows on cables: every fake-blur trick
              (layer filter, blend-mode bands) still re-composited on
              pan/zoom and dragged the canvas below 60fps. */}
          <g fill="none" strokeLinecap="round">
            {links.filter((link) => !isHotLink(link)).map(renderLink)}
            {links.filter(isHotLink).map(renderLink)}
          </g>

          {/* site / group containers — above the cables, below the nodes;
              not interactive (link hover keeps working inside trays) and
              dimmed while a route is lit so the animation reads through */}
          <g pointerEvents="none" opacity={lit ? 0.45 : 1} style={{ transition: "opacity 240ms" }}>
            {layout.boxes.map(renderBox)}
          </g>

          {/* nodes — the outer translate is the only thing that moves on
              pan/zoom/animation frames; PinVis (memoized) holds everything
              else, so those frames skip every pin subtree */}
          {nodes.map((n) => {
            const a = n.asset;
            const p = pos(a.id);
            return (
              <g
                key={a.id}
                data-node-id={a.id}
                data-r={n.r}
                transform={`translate(${p.x},${p.y})`}
                opacity={isDimNode(a.id) ? 0.18 : 1}
                className="cursor-pointer transition-opacity"
                onPointerEnter={(e) => {
                  setHoverId(a.id);
                  const rect = wrapRef.current!.getBoundingClientRect();
                  setTip({ id: a.id, x: e.clientX - rect.left, y: e.clientY - rect.top });
                }}
                onPointerLeave={() => { setHoverId(null); setTip(null); }}
                onDoubleClick={(e) => { e.stopPropagation(); onToggleCollapse(a.id); }}
              >
                <PinVis
                  asset={a}
                  r={n.r}
                  hub={n.hub}
                  isSel={selectedId === a.id}
                  matched={hasQuery && matchSet.has(a.id)}
                  hovered={hoverId === a.id}
                  traced={trace.includes(a.id)}
                  groupColor={groupColorOf(a.id)}
                  kidsCount={(childrenStatic[a.id] ?? []).length}
                  isCollapsed={collapsed.has(a.id)}
                  showName={tf.k >= 0.3}
                  showIp={tf.k >= 0.55}
                  onToggleCollapse={collapseStable}
                />
              </g>
            );
          })}
        </g>
      </svg>

      {/* zoom furniture */}
      <div className="absolute left-3 top-3 z-10 flex flex-col gap-1 rounded-lg border bg-popover/90 p-1 shadow-sm backdrop-blur">
        <Button variant="ghost" size="icon-xs" title="Zoom in" onPointerDown={(e) => e.stopPropagation()} onClick={() => zoomBy(1.25)}>
          <Plus />
        </Button>
        <Button variant="ghost" size="icon-xs" title="Zoom out" onPointerDown={(e) => e.stopPropagation()} onClick={() => zoomBy(0.8)}>
          <Minus />
        </Button>
        <Button variant="ghost" size="icon-xs" title="Fit to view (F)" onPointerDown={(e) => e.stopPropagation()} onClick={() => fitTo()}>
          <Maximize2 />
        </Button>
        <Button variant="ghost" size="icon-xs" title="Reset layout — drop every dragged node back into place" onPointerDown={(e) => e.stopPropagation()} onClick={onResetLayout}>
          <RotateCcw />
        </Button>
      </div>

      {nodes.length === 0 && (
        <div className="pointer-events-none absolute inset-0 z-10 flex items-center justify-center">
          <div className="pointer-events-auto max-w-[360px] rounded-xl border bg-popover/95 px-6 py-5 text-center shadow-lg backdrop-blur">
            <div className="text-sm font-semibold text-foreground">Nothing on the wire</div>
            <p className="mt-1.5 text-xs leading-relaxed text-muted-foreground">
              Every node is filtered out by the current site, group or search filter. The canvas keeps its grid so the map
              stays where you left it.
            </p>
            <Button size="sm" variant="outline" className="mt-4" onPointerDown={(e) => e.stopPropagation()} onClick={onResetFilters}>
              Reset all filters
            </Button>
          </div>
        </div>
      )}

      <div className="pointer-events-none absolute right-3 top-3 z-10 rounded-md border bg-popover/90 px-2 py-1 font-mono text-[11px] tabular text-muted-foreground backdrop-blur">
        {Math.round(tf.k * 100)}%
      </div>

      {/* legend — a small card in the zoom-furniture design language. The
          toggle lives in the card header (top-right) instead of floating
          after wrapped inline content, and the body is a fixed-width
          vertical list that documents the pin language: risk fills, group
          ring, agent and findings badges. Choice persists per browser. */}
      <div
        onPointerDown={(e) => e.stopPropagation()}
        className="absolute bottom-3 left-3 z-10 w-56 overflow-hidden rounded-lg border bg-popover/90 text-[11px] text-muted-foreground shadow-sm backdrop-blur"
      >
        <div className={cn("flex items-center justify-between py-1 pl-2.5 pr-1", legendOpen && "border-b border-border/60")}>
          <span className="flex items-center gap-1.5 font-medium text-foreground/80">
            <Info className="size-3.5" /> Legend
          </span>
          <button
            onClick={() => toggleLegend(!legendOpen)}
            className="flex size-6 cursor-pointer items-center justify-center rounded hover:bg-accent"
            aria-label={legendOpen ? "Collapse legend" : "Expand legend"}
            aria-expanded={legendOpen}
          >
            {legendOpen ? <ChevronDown className="size-3.5" /> : <ChevronUp className="size-3.5" />}
          </button>
        </div>
        {legendOpen && (
          <div className="grid gap-2 px-2.5 py-2">
            <div className="grid grid-cols-2 gap-x-3 gap-y-1.5">
              {(["critical", "high", "medium", "low"] as const).map((k) => (
                <span key={k} className="flex items-center gap-1.5 capitalize">
                  <span className={cn("size-2 rounded-full", riskTone(k === "critical" ? 90 : k === "high" ? 65 : k === "medium" ? 40 : 10).bar)} /> {k}
                </span>
              ))}
            </div>
            <div className="grid gap-1.5 border-t border-border/60 pt-2">
              <span className="flex items-center gap-1.5">
                <Server className="size-3 text-fg/80" /> device type icon
              </span>
              <span className="flex items-center gap-1.5">
                <span className="size-2 rounded-full bg-[oklch(0.66_0.17_275)] ring-1 ring-[oklch(0.13_0.01_262)]" /> group colour
              </span>
              <span className="flex items-center gap-1.5">
                <span className="size-2 rounded-full bg-[oklch(0.8_0.15_145)] ring-1 ring-[oklch(0.13_0.01_262)]" /> agent installed
              </span>
              <span className="flex items-center gap-1.5">
                <span className="size-2 rounded-full bg-[oklch(0.64_0.22_22)] ring-1 ring-[oklch(0.94_0.005_262)]" /> critical / high findings
              </span>
            </div>
            <div className="grid gap-1.5 border-t border-border/60 pt-2">
              <span className="flex items-center gap-1.5">
                <span className="h-0 w-4 border-t-2 border-[oklch(0.75_0.13_210)]" /> observed route
              </span>
              <span className="flex items-center gap-1.5">
                <span className="h-0 w-4 border-t-2 border-dashed border-[oklch(0.68_0.19_305)]" /> inferred link
              </span>
              <span className="flex items-center gap-1.5">
                <span className="h-0 w-4 border-t-2 border-[oklch(0.8_0.15_80)]" /> pinned parent (analyst)
              </span>
            </div>
            <p className="border-t border-border/60 pt-2 text-[10px] leading-relaxed text-muted-foreground/70">
              drag to pan · scroll to zoom · click to light the route · shift-click to pin a trace · double-click to collapse
            </p>
          </div>
        )}
      </div>

      {/* minimap */}
      <div
        className="absolute bottom-3 right-3 z-10 rounded-lg border bg-popover/90 p-1.5 shadow-sm backdrop-blur"
        onPointerDown={(e) => e.stopPropagation()}
        onPointerMove={(e) => { if (e.buttons === 1) minimapJump(e); }}
      >
        <svg width={MINI_W} height={MINI_H} className="cursor-crosshair rounded" onPointerDown={minimapJump}>
          <rect width={MINI_W} height={MINI_H} fill="oklch(0.18 0.01 262)" opacity={0.6} />
          {layout.boxes.map((box) => {
            const c = boxSolid(box.color);
            const solid = c ? c.solid : box.color;
            return (
            <rect
              key={box.id}
              x={(box.x - b.minX) * ms + mx}
              y={(box.y - b.minY) * ms + my}
              width={box.w * ms}
              height={box.h * ms}
              fill={solid}
              fillOpacity={0.12}
              stroke={solid}
              strokeOpacity={0.3}
            />
            );
          })}
          {nodes.map((n) => {
            const p = pos(n.asset.id);
            return (
              <rect
                key={n.asset.id}
                x={(p.x - b.minX) * ms + mx - 2}
                y={(p.y - b.minY) * ms + my - 2}
                width={4}
                height={4}
                rx={1}
                fill={riskFillOf(n.asset.risk)}
                opacity={isDimNode(n.asset.id) ? 0.25 : 1}
              />
            );
          })}
          <rect x={viewRect.x} y={viewRect.y} width={viewRect.w} height={viewRect.h} fill="oklch(0.66 0.17 275)" fillOpacity={0.08} stroke="oklch(0.66 0.17 275)" strokeOpacity={0.55} strokeWidth={1} />
        </svg>
      </div>

      {/* hover tooltip */}
      {tip && hovered && (
        <div
          className="pointer-events-none absolute z-20 rounded-md border bg-popover px-2.5 py-1.5 text-xs shadow-lg"
          style={{ left: Math.min(tip.x + 16, size.w - 190), top: Math.max(8, Math.min(tip.y + 14, size.h - 80)) }}
        >
          <div className="font-medium">{hovered.hostname ?? hovered.ip}</div>
          <div className="text-muted-foreground">
            {assetTypeMeta[hovered.type].label} · risk {hovered.risk}
          </div>
        </div>
      )}

      {/* link tooltip */}
      {hoverLink && !tip && (
        <div
          className="pointer-events-none absolute z-20 rounded-md border bg-popover px-2.5 py-1.5 font-mono text-[10px] text-muted-foreground shadow-lg"
          style={{ left: hoverLink.x + 14, top: hoverLink.y + 12 }}
        >
          <span className="text-foreground">{linkIp(hoverLink.link.source)}</span> →{" "}
          <span className="text-foreground">{linkIp(hoverLink.link.target)}</span>
          <span className="mx-1.5 opacity-40">|</span>
          {hoverLink.link.observed ? "observed route" : "inferred link"} · confidence {Math.round(hoverLink.link.confidence * 100)}%
        </div>
      )}
    </div>
  );
});

export default TopologyGraph;
