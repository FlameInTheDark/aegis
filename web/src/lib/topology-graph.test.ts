import { describe, expect, it } from "vitest";

import {
  CELL_H,
  CELL_W,
  cablePath,
  computeLayout,
  curvePath,
  deriveForest,
  colsFor,
  radiusForDepth,
  routeSet,
  roundedPolyline,
  type EdgeInput,
  type Pt,
} from "./topology-graph";

/* ------------------------------------------------------------------ */
/* helpers                                                             */
/* ------------------------------------------------------------------ */

/** gateway + n clients as ids — gw is the elected root */
function starIds(gateway: string, n: number, prefix = "10.0.0.") {
  const ids = [gateway, ...Array.from({ length: n }, (_, i) => `${prefix}${i + 1}`)];
  const edges: EdgeInput[] = ids
    .filter((id) => id !== gateway)
    .map((id) => ({ source: gateway, target: id, confidence: 0.9 }));
  return { ids, edges };
}

const chain = (from: string, to: string, confidence = 0.9): EdgeInput => ({ source: from, target: to, confidence });

const ipOf = (ids: string[]) => Object.fromEntries(ids.map((id) => [id, id]));

describe("colsFor", () => {
  it("wraps fan-out so a 9-guest hub stays square, not a fan", () => {
    expect(colsFor(1)).toBe(1);
    expect(colsFor(4)).toBe(4);
    expect(colsFor(9)).toBe(3);
    expect(colsFor(15)).toBe(4);
    expect(colsFor(40)).toBe(4);
  });
});

describe("hierarchy layout", () => {
  it("puts the gateway on top and its clients in one row below", () => {
    const { ids, edges } = starIds("gw", 4); // colsFor(4) = 4 → a single row
    const tree = deriveForest(ids, edges);
    const layout = computeLayout("hierarchy", ids.map((id) => ({ id, ip: id })), tree.roots, (id) => tree.children[id] ?? [], {}, undefined);

    expect(Object.keys(layout.nodes).sort()).toEqual(ids.slice().sort());
    const gw = layout.nodes["gw"];
    for (const id of ids.slice(1)) {
      const kid = layout.nodes[id];
      expect(kid.y).toBeCloseTo(gw.y + CELL_H, 5);
    }
    // children are centered under the gateway and evenly spaced
    const xs = ids.slice(1).map((id) => layout.nodes[id].x).sort((a, b) => a - b);
    expect(xs[1] - xs[0]).toBeCloseTo(xs[3] - xs[2], 5);
    expect(xs[2] - xs[1]).toBeCloseTo(xs[1] - xs[0], 5);
    expect(layout.boxes).toEqual([]);
  });

  it("wraps 5 clients into a 3+2 patch grid like the reference", () => {
    const { ids, edges } = starIds("gw", 5);
    const tree = deriveForest(ids, edges);
    const layout = computeLayout("hierarchy", ids.map((id) => ({ id, ip: id })), tree.roots, (id) => tree.children[id] ?? [], {}, undefined);
    const ys = [...new Set(ids.slice(1).map((id) => layout.nodes[id].y))].sort((a, b) => a - b);
    expect(ys).toHaveLength(2);
    expect(ids.slice(1).filter((id) => layout.nodes[id].y === ys[0])).toHaveLength(3);
    expect(ids.slice(1).filter((id) => layout.nodes[id].y === ys[1])).toHaveLength(2);
  });

  it("wraps 15 clients into a 4-wide grid", () => {
    const { ids, edges } = starIds("gw", 15);
    const tree = deriveForest(ids, edges);
    const layout = computeLayout("hierarchy", ids.map((id) => ({ id, ip: id })), tree.roots, (id) => tree.children[id] ?? [], {}, undefined);
    const ys = [...new Set(ids.slice(1).map((id) => layout.nodes[id].y))].sort((a, b) => a - b);
    expect(ys).toHaveLength(4); // 4 rows of 4
    const rowXs = ids.slice(1).filter((id) => layout.nodes[id].y === ys[0]).map((id) => layout.nodes[id].x);
    expect(rowXs).toHaveLength(4);
  });

  it("keeps grandchildren in blocks under their parent (router → switch → clients)", () => {
    const ids = ["rtr", "sw1", "sw2", ...Array.from({ length: 6 }, (_, i) => `c${i + 1}`)];
    const edges = [chain("rtr", "sw1"), chain("rtr", "sw2"), ...[0, 1, 2].map((i) => chain("sw1", `c${i + 1}`)), ...[3, 4, 5].map((i) => chain("sw2", `c${i + 1}`))];
    const tree = deriveForest(ids, edges);
    const layout = computeLayout("hierarchy", ids.map((id) => ({ id, ip: id })), tree.roots, (id) => tree.children[id] ?? [], {}, undefined);

    expect(tree.roots).toEqual(["rtr"]);
    expect(tree.children["rtr"]).toEqual(["sw1", "sw2"]);
    // each switch sits on the gateway row, its clients one row below
    for (const sw of ["sw1", "sw2"]) {
      const swPos = layout.nodes[sw];
      expect(swPos.y).toBeCloseTo(layout.nodes["rtr"].y + CELL_H, 5);
      for (let i = 1; i <= 3; i++) {
        expect(layout.nodes[`c${(sw === "sw1" ? 0 : 3) + i}`].y).toBeCloseTo(swPos.y + CELL_H, 5);
      }
    }
    // the two subtrees do not overlap horizontally
    const left = ["c1", "c2", "c3"].map((c) => layout.nodes[c].x);
    const right = ["c4", "c5", "c6"].map((c) => layout.nodes[c].x);
    expect(Math.max(...left)).toBeLessThan(Math.min(...right));
  });
});

describe("radial layout", () => {
  it("centers the root and distributes children on weighted sectors", () => {
    const { ids, edges } = starIds("gw", 8);
    const tree = deriveForest(ids, edges);
    const layout = computeLayout("radial", ids.map((id) => ({ id, ip: id })), tree.roots, (id) => tree.children[id] ?? [], {}, undefined);

    const gw = layout.nodes["gw"];
    expect(gw).toEqual({ x: 0, y: 0 });
    const ring = radiusForDepth(1);
    expect(ring).toBe(240);
    for (const id of ids.slice(1)) {
      const p = layout.nodes[id];
      expect(Math.hypot(p.x, p.y)).toBeCloseTo(ring, 5);
    }
    // even fan: consecutive angular gaps are equal
    const angles = ids.slice(1).map((id) => Math.atan2(layout.nodes[id].y, layout.nodes[id].x)).sort((a, b) => a - b);
    for (let i = 1; i < angles.length; i++) {
      expect(angles[i] - angles[i - 1]).toBeCloseTo((Math.PI * 2) / 8, 5);
    }
  });

  it("gives heavier subtrees wider sectors", () => {
    const ids = ["gw", "hub", "a1", "a2", "a3", "b1"];
    const edges = [chain("gw", "hub"), chain("hub", "a1"), chain("hub", "a2"), chain("hub", "a3"), chain("gw", "b1")];
    const tree = deriveForest(ids, edges);
    const layout = computeLayout("radial", ids.map((id) => ({ id, ip: id })), tree.roots, (id) => tree.children[id] ?? [], {}, undefined);
    const angle = (id: string) => Math.atan2(layout.nodes[id].y, layout.nodes[id].x);
    const a = angle("a2") - angle("a1");
    const gapLeaf = angle("b1") - angle("a3");
    // the 3-leaf subtree spans wider than the single leaf's sector
    expect(2 * a + gapLeaf > gapLeaf).toBe(true);
  });
});

describe("cluster layout (groups / sites)", () => {
  const titles = {
    hq: { label: "HQ", color: "indigo" },
    branch: { label: "Branch", color: "cyan" },
  };

  it("trays members inside site boxes, sorted by IP, boxes side by side", () => {
    const ids = ["10.0.0.10", "10.0.0.9", "10.0.0.11", "10.0.1.2", "10.0.1.100"];
    const siteOf: Record<string, string> = {
      "10.0.0.10": "hq", "10.0.0.9": "hq", "10.0.0.11": "hq",
      "10.0.1.2": "branch", "10.0.1.100": "branch",
    };
    const layout = computeLayout("sites", ids.map((id) => ({ id, ip: id })), [], () => [], {}, { keyOf: (id) => siteOf[id], titles });

    expect(layout.boxes).toHaveLength(2);
    const hq = layout.boxes.find((b) => b.id === "hq")!;
    const branch = layout.boxes.find((b) => b.id === "branch")!;
    expect(hq.count).toBe(3);
    // largest tray first
    expect(layout.boxes[0].id).toBe("hq");
    // numeric IP order: .9 before .10
    expect(layout.nodes["10.0.0.9"].x).toBeCloseTo(hq.x + 34 + 73, 5);
    expect(layout.nodes["10.0.0.10"].x).toBeGreaterThan(layout.nodes["10.0.0.9"].x);
    // trays share one band and never overlap
    expect(branch.y).toBeCloseTo(hq.y, 5);
    expect(branch.x).toBeGreaterThan(hq.x + hq.w);
    // all members sit inside their box
    for (const b of [hq, branch]) {
      for (const id of ids.filter((i) => siteOf[i] === b.id)) {
        const p = layout.nodes[id];
        expect(p.x).toBeGreaterThanOrEqual(b.x);
        expect(p.x).toBeLessThanOrEqual(b.x + b.w);
        expect(p.y).toBeGreaterThanOrEqual(b.y);
        expect(p.y).toBeLessThanOrEqual(b.y + b.h);
      }
    }
  });

  it("orders boxes by member count, largest first", () => {
    const ids = ["a", "b", "c", "d"];
    const key: Record<string, string> = { a: "big", b: "big", c: "big", d: "small" };
    const layout = computeLayout("sites", ids.map((id) => ({ id, ip: id })), [], () => [], {}, { keyOf: (id) => key[id], titles: { big: titles.hq, small: titles.branch } });
    expect(layout.boxes[0].id).toBe("big");
    expect(layout.boxes[1].id).toBe("small");
  });
});

describe("forests (disconnected networks)", () => {
  it("packs two independent trees side by side without overlap", () => {
    const ids = ["gw1", "c1", "gw2", "c2", "c3"];
    const edges = [chain("gw1", "c1"), chain("gw2", "c2"), chain("gw2", "c3")];
    const tree = deriveForest(ids, edges);
    expect(tree.roots).toEqual(["gw1", "gw2"]);
    const layout = computeLayout("hierarchy", ids.map((id) => ({ id, ip: id })), tree.roots, (id) => tree.children[id] ?? [], {}, undefined);
    const xs1 = [layout.nodes["gw1"].x, layout.nodes["c1"].x];
    const xs2 = [layout.nodes["gw2"].x, layout.nodes["c2"].x, layout.nodes["c3"].x];
    expect(Math.max(...xs1)).toBeLessThan(Math.min(...xs2));
    // children stay under their own root
    expect(layout.nodes["c2"].y).toBeCloseTo(layout.nodes["gw2"].y + CELL_H, 5);
  });

  it("elects nodes without incoming evidence as roots before metadata rank", () => {
    // gw claims both hosts; c1 weakly, c1's claim on gw is stronger data —
    // either way the hosts carry incoming evidence, gw carries none
    const ids = ["gw", "c1", "c2"];
    const edges = [chain("gw", "c1", 0.4), chain("gw", "c2", 0.2), chain("c1", "gw", 0.9)];
    const tree = deriveForest(ids, edges, (id) => (id === "gw" ? 0 : 4));
    expect(tree.roots).toEqual(["gw"]);
    expect(tree.parent["c1"]).toBe("gw");
    expect(tree.parent["c2"]).toBe("gw");
  });
});

describe("deriveForest", () => {
  it("keeps the best-confidence upstream when several gateways claim a host", () => {
    const ids = ["gwA", "gwB", "host"];
    const edges = [chain("gwB", "host", 0.55), chain("gwA", "host", 0.95)];
    const tree = deriveForest(ids, edges, (id) => (id === "gwA" ? 0 : id === "gwB" ? 0 : 4));
    expect(tree.parent["host"]).toBe("gwA");
    const oriented = tree.oriented.find((e) => e.source === "host")!;
    expect(oriented.target).toBe("gwA");
    expect(oriented.confidence).toBe(0.95);
  });

  it("survives cycles: every input edge comes back oriented, the tree stays acyclic", () => {
    const ids = ["a", "b", "c", "d"];
    const edges = [chain("a", "b"), chain("b", "c"), chain("c", "a"), chain("c", "d")];
    const tree = deriveForest(ids, edges, () => 4);
    // the highest-degree node c is elected; the refinement pass then follows
    // the evidence directions (a routes to b), giving parents {a: c, b: a, d: c}
    expect(Object.values(tree.parent).sort()).toEqual(["a", "c", "c"]);
    // walk-up from any node terminates
    for (const id of ids) {
      let cur: string | undefined = id;
      let guard = 0;
      while (cur && guard++ < 10) cur = tree.parent[cur];
      expect(guard).toBeLessThan(10);
    }
    expect(tree.oriented).toHaveLength(4);
  });

  it("marks non-tree edges so they render as curves", () => {
    const ids = ["gw", "h1", "h2"];
    const edges = [chain("gw", "h1"), chain("gw", "h2"), chain("h1", "h2", 0.6)];
    const tree = deriveForest(ids, edges);
    expect(tree.roots).toEqual(["gw"]);
    const cross = tree.oriented.find((e) => !e.tree)!;
    expect([cross.source, cross.target].sort()).toEqual(["h1", "h2"]);
    expect(tree.oriented.filter((e) => e.tree)).toHaveLength(2);
  });
});

describe("analyst parent overrides (forceParent)", () => {
  it("re-parents a node against the evidence when forced", () => {
    // transparent switch: traceroute wires h1 straight to the gateway, the
    // analyst pins it under the switch instead
    const ids = ["gw", "sw", "h1"];
    const edges = [chain("gw", "sw", 0.8), chain("gw", "h1", 0.95)];
    const tree = deriveForest(ids, edges, undefined, { h1: "sw" });
    expect(tree.parent["h1"]).toBe("sw");
    expect(tree.parent["sw"]).toBe("gw");
    expect(tree.depth["h1"]).toBe(2);
    expect(tree.roots).toEqual(["gw"]);
  });

  it("joins two disconnected components through a forced link", () => {
    const ids = ["gw1", "h1", "sw2"];
    const edges = [chain("gw1", "h1", 0.9)];
    // gw1's tree hangs under the standalone switch: one tree, three nodes
    const tree = deriveForest(ids, edges, undefined, { gw1: "sw2" });
    expect(tree.roots).toEqual(["sw2"]);
    expect(tree.parent["gw1"]).toBe("sw2");
    expect(tree.parent["h1"]).toBe("gw1");
    expect(tree.depth["h1"]).toBe(2);
  });

  it("splits a subtree out when the forced parent stands alone", () => {
    const ids = ["gw1", "h1", "sw2"];
    const edges = [chain("gw1", "h1", 0.9)];
    const tree = deriveForest(ids, edges, undefined, { h1: "sw2" });
    expect(tree.roots).toEqual(["gw1", "sw2"]);
    expect(tree.parent["h1"]).toBe("sw2");
    expect(tree.depth["h1"]).toBe(1);
  });

  it("renders the forced link as a tree edge and lights routes through it", () => {
    const ids = ["gw", "sw", "h1"];
    const edges = [chain("gw", "sw", 0.8), chain("gw", "h1", 0.95)];
    const tree = deriveForest(ids, edges, undefined, { h1: "sw" });
    const forced = tree.oriented.find((e) => e.source === "h1" && e.target === "sw")!;
    expect(forced.tree).toBe(true);
    // override pairs ship upstream→downstream with confidence 1.0 so the UI
    // can style them as manual
    const withOverrideEdge = deriveForest(
      ids,
      [...edges, { source: "sw", target: "h1", confidence: 1 }],
      undefined,
      { h1: "sw" },
    );
    expect(withOverrideEdge.oriented.find((e) => e.source === "h1" && e.target === "sw")!.confidence).toBe(1);
    const lit = routeSet(["h1"], tree.parent, tree.oriented.map((e) => ({ source: e.source, target: e.target })));
    expect([...lit.nodes].sort()).toEqual(["gw", "h1", "sw"]);
  });

  it("skips a forced link that would close a cycle, tree stays acyclic", () => {
    const ids = ["gw", "sw", "h1"];
    const edges = [chain("gw", "sw", 0.8), chain("sw", "h1", 0.8)];
    // gw under h1 would close gw→sw→h1→gw
    const tree = deriveForest(ids, edges, undefined, { gw: "h1", h1: "sw" });
    expect(tree.parent["gw"]).toBeUndefined();
    expect(tree.parent["h1"]).toBe("sw");
    for (const id of ids) {
      let cur: string | undefined = id;
      let guard = 0;
      while (cur && guard++ < 10) cur = tree.parent[cur];
      expect(guard).toBeLessThan(10);
    }
  });

  it("ignores forced links referencing unknown nodes or self", () => {
    const ids = ["gw", "h1"];
    const edges = [chain("gw", "h1", 0.9)];
    const tree = deriveForest(ids, edges, undefined, { h1: "ghost", gw: "gw" });
    expect(tree.parent["h1"]).toBe("gw");
    expect(tree.roots).toEqual(["gw"]);
  });
});

describe("route lighting", () => {
  it("collects the full path to the root plus the edge indexes on it", () => {
    const ids = ["gw", "sw", "h1", "h2"];
    const edges = [chain("gw", "sw"), chain("sw", "h1"), chain("sw", "h2")];
    const tree = deriveForest(ids, edges);
    const rendered = tree.oriented.map((e) => ({ source: e.source, target: e.target }));
    const lit = routeSet(["h1"], tree.parent, rendered);
    expect([...lit.nodes].sort()).toEqual(["gw", "h1", "sw"]);
    expect(lit.links.size).toBe(2);
    const lit2 = routeSet(["h1", "h2"], tree.parent, rendered);
    expect([...lit2.nodes].sort()).toEqual(["gw", "h1", "h2", "sw"]);
    expect(lit2.links.size).toBe(3);
  });
});

describe("stability and determinism", () => {
  it("re-running the layout on the same graph yields identical positions", () => {
    // mixed 100-node graph: a hub star, two chains, one mesh-ish island, two trays
    const ids: string[] = [];
    const edges: EdgeInput[] = [];
    const hub = "hub";
    ids.push(hub);
    for (let i = 0; i < 30; i++) {
      const c = `hub-c${i}`;
      ids.push(c);
      edges.push(chain(hub, c, 0.9));
      if (i % 5 === 0) {
        for (let j = 0; j < 2; j++) {
          const g = `${c}-g${j}`;
          ids.push(g);
          edges.push(chain(c, g, 0.9));
        }
      }
    }
    for (let i = 0; i < 20; i++) {
      const c = `chain-a-${i}`;
      ids.push(c);
      if (i > 0) edges.push(chain(`chain-a-${i - 1}`, c, 0.9));
    }
    ids.push("mesh");
    for (let i = 0; i < 12; i++) {
      const c = `mesh-c${i}`;
      ids.push(c);
      edges.push(chain("mesh", c, 0.5));
      if (i > 0) edges.push(chain(`mesh-c${i - 1}`, c, 0.5));
    }
    ids.push("lonely");

    for (const mode of ["hierarchy", "radial", "sites", "groups"] as const) {
      const run = () => {
        const tree = deriveForest(ids, edges);
        const childFn = (id: string) => tree.children[id] ?? [];
        const clusters =
          mode === "sites" || mode === "groups"
            ? {
                keyOf: (id: string) => (id.startsWith("mesh") ? "mesh" : id.startsWith("chain") ? "chain" : "core"),
                titles: { mesh: { label: "Mesh", color: "cyan" }, chain: { label: "Chain", color: "indigo" }, core: { label: "Core", color: "amber" } },
              }
            : undefined;
        return computeLayout(mode, ids.map((id) => ({ id, ip: ipOf(ids)[id] })), tree.roots, childFn, {}, clusters);
      };
      const a = run();
      const b = run();
      expect(a.nodes).toEqual(b.nodes);
      expect(a.boxes).toEqual(b.boxes);
      expect(a.bounds).toEqual(b.bounds);
      // every node landed somewhere
      expect(Object.keys(a.nodes).sort()).toEqual(ids.slice().sort());
    }
  });

  it("applies user offsets on top of the canonical picture", () => {
    const { ids, edges } = starIds("gw", 4);
    const tree = deriveForest(ids, edges);
    const childFn = (id: string) => tree.children[id] ?? [];
    const nodes = ids.map((id) => ({ id, ip: id }));
    const base = computeLayout("hierarchy", nodes, tree.roots, childFn, {}, undefined);
    const moved = computeLayout("hierarchy", nodes, tree.roots, childFn, { "10.0.0.1": { x: 37, y: -14 } }, undefined);
    expect(moved.nodes["10.0.0.1"].x).toBeCloseTo(base.nodes["10.0.0.1"].x + 37, 5);
    expect(moved.nodes["10.0.0.1"].y).toBeCloseTo(base.nodes["10.0.0.1"].y - 14, 5);
    expect(moved.nodes.gw).toEqual(base.nodes.gw);
  });
});

describe("edge geometry", () => {
  it("routes straight when parent and child share a column", () => {
    const a: Pt = { x: 10, y: 200 };
    const b: Pt = { x: 10, y: 78 };
    expect(cablePath(a, b, -80)).toBe(`M${a.x},${a.y - 26} L${b.x},${b.y - 24}`);
  });

  it("routes offset cables through the gutter with rounded corners", () => {
    const a: Pt = { x: 200, y: 200 };
    const b: Pt = { x: 40, y: 78 };
    const d = cablePath(a, b, -80);
    expect(d.startsWith(`M${a.x},${a.y - 26}`)).toBe(true);
    expect(d).toContain(`L${b.x},${b.y - 24}`);
    expect(d).toContain("Q"); // rounded corners on the channel bends
    // deterministic
    expect(cablePath(a, b, -80)).toBe(d);
  });

  it("honours radius-aware clearances so cables land on the pin rim", () => {
    // small child pin (r=8) → trim 11; hub parent (r=18) → trim 21
    const a: Pt = { x: 10, y: 200 };
    const b: Pt = { x: 10, y: 78 };
    expect(cablePath(a, b, -80, 11, 21)).toBe("M10,189 L10,57");
  });

  it("routes radius-aware cables through the gutter with matching clearances", () => {
    const a: Pt = { x: 200, y: 200 };
    const b: Pt = { x: 40, y: 78 };
    const d = cablePath(a, b, -80, 11, 21);
    expect(d.startsWith("M200,189")).toBe(true); // child rim: y - 11
    expect(d).toContain("L40,57"); // parent rim: y - 21
    expect(d).toContain("Q200,163 191,163"); // channel above child: y - 11 - 26
    expect(d).toContain("Q-80,29 -71,29"); // channel above parent: y - 21 - 28
    expect(d).toContain("Q");
  });

  it("draws radial curves with the rotational control point and cluster curves horizontal", () => {
    const a: Pt = { x: 240, y: 0 };
    const b: Pt = { x: 0, y: 240 };
    const radial = curvePath(a, b, "radial");
    expect(radial.startsWith(`M${a.x},${a.y}`)).toBe(true);
    expect(radial).toContain("Q");
    const flat = curvePath(a, b, "groups");
    expect(flat).toContain("C");
    expect(curvePath(a, b, "sites")).toBe(flat);
  });

  it("keeps rounded polylines clean of duplicate points", () => {
    const d = roundedPolyline([
      { x: 0, y: 0 },
      { x: 0, y: 0 },
      { x: 100, y: 0 },
      { x: 100, y: 100 },
    ]);
    expect(d.startsWith("M0,0")).toBe(true);
    // the corner at (100,0) is rounded: the line stops 9 short, the arc
    // carries the path around, and the final leg lands on (100,100)
    expect(d).toContain("L91,0 Q100,0 100,9");
    expect(d.endsWith("L100,100")).toBe(true);
  });
});

describe("geometry constants", () => {
  it("keeps the patch-panel cell and generalized ring radii", () => {
    expect(CELL_W).toBeGreaterThan(0);
    expect(CELL_H).toBeGreaterThan(CELL_W / 2);
    expect(radiusForDepth(0)).toBe(0);
    expect(radiusForDepth(1)).toBe(240);
    expect(radiusForDepth(2)).toBe(462);
    expect(radiusForDepth(3)).toBeGreaterThan(radiusForDepth(2));
  });
});
