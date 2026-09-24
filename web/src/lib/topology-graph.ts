/**
 * Topology graph engine for the topology page — a faithful port of the
 * network-topology-view reference implementation (graph logic), extended for
 * live platform data: evidence-derived parent trees, forests (disconnected
 * components) and device-metadata root election.
 *
 * Pure and deterministic: the same graph always produces the same picture.
 *
 *   - hierarchy : tidy tree — children wrap into grid rows under their parent
 *                 (patch-panel cells); edges route as orthogonal cables through
 *                 a gutter outside the grid, so they never cross a node
 *   - radial    : weighted angular sectors (leaf-count proportional) around
 *                 the elected root
 *   - groups    : labelled container boxes side by side, members gridded
 *                 inside, sorted by IP (numeric)
 *   - sites     : the same cluster layout keyed by site
 *
 * User drags are offsets on top of the canonical layout — a re-layout never
 * fights the user, and the same graph plus the same offsets always render
 * identically.
 */

export type ArrangeMode = "hierarchy" | "groups" | "sites" | "radial";

export interface Pt {
  x: number;
  y: number;
}

export interface Box {
  id: string;
  title: string;
  color: string;
  count: number;
  x: number;
  y: number;
  w: number;
  h: number;
}

export interface LayoutResult {
  nodes: Record<string, Pt>;
  boxes: Box[];
  bounds: { minX: number; minY: number; maxX: number; maxY: number };
}

export interface ClusterMeta {
  label: string;
  color: string;
}

/* ------------------------------------------------------------------ */
/* patch-panel cell: wide enough for a long mono label, tall enough    */
/* for the node badge and its IP + hostname labels                     */
/* ------------------------------------------------------------------ */
export const CELL_W = 116;
export const CELL_H = 122;

/* cluster box metrics (reference values) */
const BOX_CELL_W = 146;
const BOX_CELL_H = 122;
const BOX_PAD_X = 34;
const BOX_HEAD = 54;
const BOX_PAD_B = 34;
const BOX_GAP = 72;

/** trees of a forest sit side by side with this separation */
const FOREST_GAP = 170;

const keyOfBy = (key: (id: string) => string) => key;

/** Fan-out wraps into a grid so a 9-guest hypervisor stays square, not a fan. */
export function colsFor(n: number): number {
  if (n <= 2) return n;
  if (n <= 4) return n;
  if (n <= 9) return 3;
  return 4;
}

function chunk<T>(items: T[], size: number): T[][] {
  const out: T[][] = [];
  for (let i = 0; i < items.length; i += size) out.push(items.slice(i, i + size));
  return out;
}

interface Block {
  w: number;
  h: number;
}

function measure(
  id: string,
  children: (id: string) => string[],
  cache: Map<string, Block>,
): Block {
  const kids = children(id);
  if (kids.length === 0) {
    const b: Block = { w: CELL_W, h: CELL_H };
    cache.set(id, b);
    return b;
  }
  const rows = chunk(kids, colsFor(kids.length)).map((row) => row.map((k) => measure(k, children, cache)));
  const rowW = rows.map((row) => row.reduce((s, b) => s + b.w, 0));
  const rowH = rows.map((row) => Math.max(...row.map((b) => b.h)));
  const b: Block = {
    w: Math.max(CELL_W, ...rowW),
    h: CELL_H + rowH.reduce((s, x) => s + x, 0),
  };
  cache.set(id, b);
  return b;
}

function layoutTree(rootId: string, children: (id: string) => string[]): Record<string, Pt> {
  const cache = new Map<string, Block>();
  measure(rootId, children, cache);
  const out: Record<string, Pt> = {};

  const place = (id: string, cx: number, top: number) => {
    out[id] = { x: cx, y: top };
    const kids = children(id);
    if (kids.length === 0) return;
    let y = top + CELL_H;
    for (const row of chunk(kids, colsFor(kids.length))) {
      const rowWidth = row.reduce((s, k) => s + (cache.get(k)?.w ?? CELL_W), 0);
      let x = cx - rowWidth / 2;
      for (const k of row) {
        const b = cache.get(k) ?? { w: CELL_W, h: CELL_H };
        place(k, x + b.w / 2, y);
        x += b.w;
      }
      y += Math.max(...row.map((k) => cache.get(k)?.h ?? CELL_H));
    }
  };

  place(rootId, 0, 0);
  return out;
}

/** ring radii of the radial layout — the reference trio, generalized for deeper graphs */
export function radiusForDepth(depth: number): number {
  if (depth <= 0) return 0;
  if (depth === 1) return 240;
  return 462 + 222 * (depth - 2);
}

function layoutRadial(rootId: string, children: (id: string) => string[]): Record<string, Pt> {
  // Weighted angular sectors inherited from the tidy-tree leaf ordering.
  const leaves = new Map<string, number>();
  const countLeaves = (id: string): number => {
    const kids = children(id);
    if (kids.length === 0) {
      leaves.set(id, 1);
      return 1;
    }
    let sum = 0;
    for (const kid of kids) sum += countLeaves(kid);
    leaves.set(id, sum);
    return sum;
  };
  countLeaves(rootId);
  const angle = new Map<string, number>();
  const depthOf = new Map<string, number>();
  const assign = (id: string, start: number, end: number, depth: number) => {
    const kids = children(id);
    angle.set(id, (start + end) / 2);
    depthOf.set(id, depth);
    let cursor = start;
    for (const kid of kids) {
      const span = ((end - start) * (leaves.get(kid) ?? 1)) / (leaves.get(id) || 1);
      assign(kid, cursor, cursor + span, depth + 1);
      cursor += span;
    }
  };
  assign(rootId, -Math.PI / 2, -Math.PI / 2 + Math.PI * 2, 0);

  const out: Record<string, Pt> = {};
  for (const [id, a] of angle.entries()) {
    const d = depthOf.get(id) ?? 0;
    const r = radiusForDepth(d);
    out[id] = d === 0 ? { x: 0, y: 0 } : { x: Math.cos(a) * r, y: Math.sin(a) * r };
  }
  return out;
}

interface ClusterOptions {
  nodes: { id: string; ip?: string }[];
  key: (id: string) => string;
  titles: Record<string, ClusterMeta>;
}

/** numeric-aware IP compare so 192.168.1.9 sorts before 192.168.1.10 */
function ipCompare(a?: string, b?: string): number {
  const av = a ?? "";
  const bv = b ?? "";
  const ap = av.split(".");
  const bp = bv.split(".");
  const numeric = ap.length === 4 && bp.length === 4 && ap.concat(bp).every((x) => /^\d+$/.test(x));
  if (numeric) {
    for (let i = 0; i < 4; i++) {
      const d = Number(ap[i]) - Number(bp[i]);
      if (d !== 0) return d;
    }
    return 0;
  }
  return av.localeCompare(bv);
}

function layoutCluster({ nodes, key, titles }: ClusterOptions): LayoutResult {
  const buckets = new Map<string, string[]>();
  for (const node of nodes) {
    const k = key(node.id);
    if (!buckets.has(k)) buckets.set(k, []);
    buckets.get(k)!.push(node.id);
  }
  const ipOf = new Map(nodes.map((n) => [n.id, n.ip]));
  const order = [...buckets.keys()].sort(
    (a, b) => buckets.get(b)!.length - buckets.get(a)!.length || a.localeCompare(b),
  );

  const out: Record<string, Pt> = {};
  const boxes: Box[] = [];
  let cursorX = 0;
  let maxH = 0;

  for (const k of order) {
    const members = buckets.get(k)!.slice().sort((a, b) => ipCompare(ipOf.get(a), ipOf.get(b)));
    const cols = Math.min(members.length, Math.max(2, Math.ceil(Math.sqrt(members.length * 1.6))));
    const rows = Math.ceil(members.length / cols);
    const w = cols * BOX_CELL_W + BOX_PAD_X * 2;
    const h = BOX_HEAD + rows * BOX_CELL_H + BOX_PAD_B;
    const meta = titles[k] ?? { label: k, color: "#8A94A2" };
    boxes.push({
      id: k,
      title: meta.label,
      color: meta.color,
      count: members.length,
      x: cursorX,
      y: -h / 2,
      w,
      h,
    });
    members.forEach((id, i) => {
      const col = i % cols;
      const row = Math.floor(i / cols);
      out[id] = {
        x: cursorX + BOX_PAD_X + col * BOX_CELL_W + BOX_CELL_W / 2,
        y: -h / 2 + BOX_HEAD + row * BOX_CELL_H + BOX_CELL_H / 2,
      };
    });
    cursorX += w + BOX_GAP;
    maxH = Math.max(maxH, h);
  }

  const bounds = { minX: -60, minY: -maxH / 2 - 60, maxX: cursorX - BOX_GAP + 60, maxY: maxH / 2 + 60 };
  return { nodes: out, boxes, bounds };
}

function frameOf(positions: Record<string, Pt>) {
  const xs = Object.values(positions).map((p) => p.x);
  const ys = Object.values(positions).map((p) => p.y);
  const minX = xs.length ? Math.min(...xs) : 0;
  const maxX = xs.length ? Math.max(...xs) : 0;
  const minY = ys.length ? Math.min(...ys) : 0;
  const maxY = ys.length ? Math.max(...ys) : 0;
  return { minX, minY, maxX, maxY };
}

/** place each tree of a forest side by side, vertically centered as a band */
function layoutForest(rootIds: string[], children: (id: string) => string[], mode: "hierarchy" | "radial"): Record<string, Pt> {
  const out: Record<string, Pt> = {};
  let cursor = 0;
  for (const root of rootIds) {
    const raw = mode === "radial" ? layoutRadial(root, children) : layoutTree(root, children);
    const f = frameOf(raw);
    const dx = cursor - f.minX;
    const dy = -(f.minY + f.maxY) / 2;
    for (const [id, p] of Object.entries(raw)) out[id] = { x: p.x + dx, y: p.y + dy };
    cursor += f.maxX - f.minX + FOREST_GAP;
  }
  return out;
}

export interface ClusterSpec {
  keyOf: (id: string) => string;
  titles: Record<string, ClusterMeta>;
}

export function computeLayout(
  mode: ArrangeMode,
  nodes: { id: string; ip?: string }[],
  roots: string[],
  children: (id: string) => string[],
  offsets: Record<string, Pt>,
  clusters?: ClusterSpec,
): LayoutResult {
  let base: LayoutResult;
  if (mode === "groups" || mode === "sites") {
    base = layoutCluster({ nodes, key: keyOfBy(clusters?.keyOf ?? (() => "")), titles: clusters?.titles ?? {} });
  } else {
    const raw = roots.length === 1 ? (mode === "radial" ? layoutRadial(roots[0], children) : layoutTree(roots[0], children)) : layoutForest(roots, children, mode);
    const pts: Record<string, Pt> = {};
    for (const node of nodes) if (raw[node.id]) pts[node.id] = raw[node.id];
    const f = frameOf(pts);
    base = {
      nodes: pts,
      boxes: [],
      bounds: { minX: f.minX - 86, minY: f.minY - 74, maxX: f.maxX + 86, maxY: f.maxY + 74 },
    };
  }

  const applied: Record<string, Pt> = {};
  for (const [id, p] of Object.entries(base.nodes)) {
    const off = offsets[id];
    applied[id] = off ? { x: p.x + off.x, y: p.y + off.y } : p;
  }
  return { nodes: applied, boxes: base.boxes, bounds: base.bounds };
}

/* ------------------------------------------------------------------ */
/* edge geometry — routed patch cables and soft curves                 */
/* ------------------------------------------------------------------ */

/** Polyline with rounded corners — the geometry of a routed patch cable. */
export function roundedPolyline(points: Pt[], radius = 9): string {
  const pts = points.filter((p, i) => i === 0 || Math.abs(p.x - points[i - 1].x) > 0.5 || Math.abs(p.y - points[i - 1].y) > 0.5);
  if (pts.length < 2) return "";
  let d = `M${pts[0].x},${pts[0].y}`;
  for (let i = 1; i < pts.length - 1; i += 1) {
    const prev = pts[i - 1];
    const cur = pts[i];
    const next = pts[i + 1];
    const r = Math.min(radius, Math.hypot(cur.x - prev.x, cur.y - prev.y) / 2, Math.hypot(next.x - cur.x, next.y - cur.y) / 2);
    const inPt = {
      x: cur.x - ((cur.x - prev.x) / (Math.hypot(cur.x - prev.x, cur.y - prev.y) || 1)) * r,
      y: cur.y - ((cur.y - prev.y) / (Math.hypot(cur.x - prev.x, cur.y - prev.y) || 1)) * r,
    };
    const outPt = {
      x: cur.x + ((next.x - cur.x) / (Math.hypot(next.x - cur.x, next.y - cur.y) || 1)) * r,
      y: cur.y + ((next.y - cur.y) / (Math.hypot(next.x - cur.x, next.y - cur.y) || 1)) * r,
    };
    d += ` L${inPt.x},${inPt.y} Q${cur.x},${cur.y} ${outPt.x},${outPt.y}`;
  }
  const last = pts[pts.length - 1];
  return `${d} L${last.x},${last.y}`;
}

/**
 * Patch-panel routing: leave the child vertically, run along a horizontal
 * cable channel under the row above, climb the block gutter (outside the
 * grid, so it never crosses a node), then drop onto the parent.
 *
 * `startOff` / `endOff` are the vertical clearances between each pin's
 * CENTRE and the cable endpoint above it — callers pass the actual pin
 * radius (+ stroke + breathing) so the cable lands on the rim instead of
 * hovering in space; the defaults keep the historical 26/24 geometry.
 */
export function cablePath(a: Pt, b: Pt, gutterX: number, startOff = 26, endOff = 24): string {
  if (Math.abs(a.x - b.x) < 2) return `M${a.x},${a.y - startOff} L${b.x},${b.y - endOff}`;
  const chA = a.y - startOff - 26;
  const chB = b.y - endOff - 28;
  return roundedPolyline(
    [
      { x: a.x, y: a.y - startOff },
      { x: a.x, y: chA },
      { x: gutterX, y: chA },
      { x: gutterX, y: chB },
      { x: b.x, y: chB },
      { x: b.x, y: b.y - endOff },
    ],
    9,
  );
}

/** Soft bezier used inside cluster boxes and across the radial field. */
export function curvePath(a: Pt, b: Pt, mode: ArrangeMode): string {
  if (mode === "radial") {
    const mx = (a.x + b.x) / 2;
    const my = (a.y + b.y) / 2;
    const k = 0.22;
    return `M${a.x},${a.y} Q${mx - my * k},${my + mx * k} ${b.x},${b.y}`;
  }
  const dx = Math.abs(b.x - a.x);
  const c = Math.max(60, dx * 0.45);
  return `M${a.x},${a.y} C${a.x + (b.x > a.x ? c : -c)},${a.y} ${b.x - (b.x > a.x ? c : -c)},${b.y} ${b.x},${b.y}`;
}

/* ------------------------------------------------------------------ */
/* tree derivation from evidence — the platform-data adapter           */
/* ------------------------------------------------------------------ */

export interface EdgeInput {
  source: string;
  target: string;
  /** upstream confidence (0..1); routes observed by traceroute carry >= 0.8 */
  confidence?: number;
}

export interface OrientedEdge {
  /** child end — arrows point upstream, cables run toward the gateway */
  source: string;
  /** upstream end (parent / gateway side) */
  target: string;
  tree: boolean;
  confidence: number;
}

export interface DerivedTree {
  parent: Record<string, string>;
  children: Record<string, string[]>;
  /** elected root of every component, in deterministic component order */
  roots: string[];
  /** every input edge, deduped per unordered pair and oriented child → upstream */
  oriented: OrientedEdge[];
  /** BFS depth from the component root (roots sit at depth 0) */
  depth: Record<string, number>;
}

/**
 * Build the parent tree from directed evidence edges (`source` routes to
 * `target`'s side — gateway → host), without ever inventing a relationship:
 * only the given edges are used. Components are detected on the undirected
 * graph; a root is elected per component (explicit rank, then degree, then
 * id); a spanning tree is grown by BFS and refined so the best-confidence
 * upstream wins where the evidence offers several — cycle-safe.
 *
 * `forceParent` pins analyst-asserted links (asset parent overrides) above
 * any evidence: the BFS + refinement result is re-parented to the forced
 * parent wherever that does not close a cycle. Depth, children and roots are
 * rebuilt over the final map, so two components joined by a forced link
 * become one tree.
 */
export function deriveForest(
  ids: string[],
  edges: EdgeInput[],
  electRank?: (id: string) => number,
  forceParent?: Record<string, string>,
): DerivedTree {
  const idSet = new Set(ids);
  const rank = electRank ?? (() => 5);

  // adjacency (undirected, deduped, deterministic order)
  const neighbors = new Map<string, string[]>();
  ids.forEach((id) => neighbors.set(id, []));
  const pairKey = (a: string, b: string) => (a < b ? `${a}|${b}` : `${b}|${a}`);
  const seenPair = new Set<string>();
  const degree = new Map<string, number>(ids.map((id) => [id, 0]));
  const bestUpstream = new Map<string, { from: string; confidence: number }>();
  for (const e of edges) {
    if (!idSet.has(e.source) || !idSet.has(e.target) || e.source === e.target) continue;
    const key = pairKey(e.source, e.target);
    if (seenPair.has(key)) {
      // parallel evidence for the same pair keeps the highest confidence
      const prev = bestUpstream.get(e.target);
      if (prev?.from === e.source && (e.confidence ?? 0) > prev.confidence) {
        prev.confidence = e.confidence ?? 0;
      }
      continue;
    }
    seenPair.add(key);
    neighbors.get(e.source)!.push(e.target);
    neighbors.get(e.target)!.push(e.source);
    degree.set(e.source, (degree.get(e.source) ?? 0) + 1);
    degree.set(e.target, (degree.get(e.target) ?? 0) + 1);
    const conf = e.confidence ?? 0;
    const prev = bestUpstream.get(e.target);
    if (!prev || conf > prev.confidence || (conf === prev.confidence && e.source < prev.from)) {
      bestUpstream.set(e.target, { from: e.source, confidence: conf });
    }
  }
  neighbors.forEach((list) => list.sort());

  // connected components in deterministic order
  const componentOf = new Map<string, number>();
  const components: string[][] = [];
  for (const start of ids) {
    if (componentOf.has(start)) continue;
    const index = components.length;
    const members: string[] = [];
    const queue = [start];
    componentOf.set(start, index);
    while (queue.length) {
      const cur = queue.shift()!;
      members.push(cur);
      for (const nb of neighbors.get(cur) ?? []) {
        if (!componentOf.has(nb)) {
          componentOf.set(nb, index);
          queue.push(nb);
        }
      }
    }
    members.sort();
    components.push(members);
  }

  const parent: Record<string, string> = {};
  const depth: Record<string, number> = {};
  const roots: string[] = [];

  const isAncestor = (ancestor: string, node: string): boolean => {
    let cur: string | undefined = node;
    let guard = 0;
    while (cur && guard++ <= ids.length) {
      if (cur === ancestor) return true;
      cur = parent[cur];
    }
    return false;
  };

  for (const members of components) {
    // elect a root: no upstream evidence first, then explicit rank, degree, id
    const withUpstream = members.filter((m) => bestUpstream.has(m) && componentOf.get(bestUpstream.get(m)!.from!) === componentOf.get(m));
    const candidates = withUpstream.length < members.length ? members.filter((m) => !withUpstream.includes(m)) : members;
    const root = candidates.slice().sort((a, b) => {
      const ra = rank(a);
      const rb = rank(b);
      if (ra !== rb) return ra - rb;
      const da = degree.get(a) ?? 0;
      const db = degree.get(b) ?? 0;
      if (da !== db) return db - da;
      return a < b ? -1 : 1;
    })[0];
    roots.push(root);
    depth[root] = 0;

    // BFS spanning tree from the root
    const visited = new Set<string>([root]);
    const queue = [root];
    while (queue.length) {
      const cur = queue.shift()!;
      for (const nb of neighbors.get(cur) ?? []) {
        if (!visited.has(nb)) {
          visited.add(nb);
          parent[nb] = cur;
          depth[nb] = depth[cur] + 1;
          queue.push(nb);
        }
      }
    }

    // refinement: among visited upstream candidates the best evidence wins —
    // rejected when the switch would create a cycle (candidate sits below us)
    for (const node of members) {
      if (node === root || !parent[node]) continue;
      const best = bestUpstream.get(node);
      if (!best || !visited.has(best.from) || best.from === node) continue;
      if (isAncestor(node, best.from)) continue;
      if (best.from === parent[node]) continue;
      parent[node] = best.from;
    }
  }

  // analyst parent overrides: pin the forced child→parent links above any
  // evidence. Applied sequentially against the evolving (acyclic) map, and
  // skipped when the forced parent already sits below the child — a corrupt
  // override chain can bend the layout but never break it. Applied links are
  // remembered so the orientation pass emits them even when the caller did
  // not pass them as evidence edges (the common case: a pin without a scan).
  const appliedForce: Record<string, string> = {};
  if (forceParent) {
    for (const [child, par] of Object.entries(forceParent)) {
      if (!idSet.has(child) || !idSet.has(par) || child === par) continue;
      if (isAncestor(child, par)) continue;
      if (parent[child] === par) continue;
      parent[child] = par;
      appliedForce[child] = par;
    }
    const finalRoots = ids.filter((id) => !parent[id]);
    roots.length = 0;
    roots.push(...finalRoots);
  }

  // children maps in deterministic (sorted) order
  const children: Record<string, string[]> = {};
  ids.forEach((id) => (children[id] = []));
  for (const [child, par] of Object.entries(parent)) {
    if (children[par]) children[par].push(child);
  }
  Object.values(children).forEach((list) => list.sort());

  // after re-parenting, BFS depth is stale — rebuild it over the final tree
  // (parent-chain depth, roots at 0). Chains always terminate: every forced
  // link was cycle-checked against the map it joined.
  if (forceParent) {
    for (const key of Object.keys(depth)) delete depth[key];
    const queue = [...roots];
    for (const r of roots) depth[r] = 0;
    while (queue.length) {
      const cur = queue.shift()!;
      for (const kid of children[cur] ?? []) {
        if (depth[kid] === undefined) {
          depth[kid] = depth[cur] + 1;
          queue.push(kid);
        }
      }
    }
  }

  // orient every deduped pair child → upstream; cross links go deep → shallow
  const confByPair = new Map<string, number>();
  for (const e of edges) {
    if (!idSet.has(e.source) || !idSet.has(e.target) || e.source === e.target) continue;
    const key = pairKey(e.source, e.target);
    const conf = e.confidence ?? 0;
    if (!confByPair.has(key) || conf > confByPair.get(key)!) confByPair.set(key, conf);
  }
  const oriented: OrientedEdge[] = [];
  for (const key of [...seenPair]) {
    const [a, b] = key.split("|");
    const da = depth[a] ?? 0;
    const db = depth[b] ?? 0;
    let source: string;
    let target: string;
    let tree: boolean;
    if (parent[a] === b) {
      source = a;
      target = b;
      tree = true;
    } else if (parent[b] === a) {
      source = b;
      target = a;
      tree = true;
    } else if (da !== db) {
      source = da > db ? a : b;
      target = da > db ? b : a;
      tree = false;
    } else {
      [source, target] = a < b ? [a, b] : [b, a];
      tree = false;
    }
    oriented.push({ source, target, tree, confidence: confByPair.get(key) ?? 0 });
  }
  // an applied forced link always renders, even without evidence for the pair
  if (forceParent) {
    const covered = new Set(oriented.map((e) => pairKey(e.source, e.target)));
    for (const [child, par] of Object.entries(appliedForce)) {
      if (covered.has(pairKey(child, par))) continue;
      oriented.push({ source: child, target: par, tree: true, confidence: 1 });
    }
  }
  oriented.sort((x, y) => (x.source + x.target < y.source + y.target ? -1 : 1));

  return { parent, children, roots, oriented, depth };
}

/* ------------------------------------------------------------------ */
/* routes — the lit path set the graph highlights                      */
/* ------------------------------------------------------------------ */

/** Nodes + edges on the lit route(s): the union of every traced node's path to its root. */
export function routeSet(
  ids: string[],
  parent: Record<string, string>,
  edges: { source: string; target: string }[],
): { nodes: Set<string>; links: Set<string> } {
  const nodes = new Set<string>();
  const links = new Set<string>();
  const maxHops = Object.keys(parent).length + 1;
  for (const id of ids) {
    const path: string[] = [];
    let cur: string | undefined = id;
    let guard = 0;
    // walk the full chain to the root every time — an early stop on already
    // visited nodes would drop the links on the shared tail
    while (cur && guard++ <= maxHops) {
      path.push(cur);
      nodes.add(cur);
      cur = parent[cur];
    }
    for (let i = 0; i < path.length - 1; i += 1) {
      const child = path[i];
      const par = path[i + 1];
      edges.forEach((e, idx) => {
        if ((e.source === child && e.target === par) || (e.source === par && e.target === child)) links.add(String(idx));
      });
    }
  }
  return { nodes, links };
}
