// fetchSites is the useSites query body — these tests pin the response
// contract: a valid list payload maps with embedded networks, a contract
// violation THROWS (so the UI shows an error instead of a lying empty
// list), and a failed/malformed networks fan-out never takes the sites
// list down with it.
import { beforeEach, describe, expect, it, vi, type Mock } from "vitest";

vi.mock("@/lib/api", () => ({ api: { get: vi.fn() } }));
vi.mock("@/lib/ws", () => ({
  ws: { connect: vi.fn(), disconnect: vi.fn(), subscribe: vi.fn(), unsubscribe: vi.fn(), on: vi.fn(), off: vi.fn() },
  useWSStatus: () => "connected",
}));
vi.mock("@/components/ui/toaster", () => ({ toast: vi.fn() }));

import { api } from "@/lib/api";
import { fetchSites } from "@/lib/queries";

const get = api.get as unknown as Mock;

const SITE = {
  id: "01a0c55c-06f4-7b1f-a0fc-0910de2a0029",
  organization_id: "01a0c55c-06e3-7b00-9437-c4b052bceff6",
  name: "Default Site",
  site_type: "lab",
  created_at: "2026-09-21T19:05:37.78143Z",
  updated_at: "2026-09-23T01:22:08.212601Z",
  asset_count: 38,
};

beforeEach(() => {
  get.mockReset();
});

describe("fetchSites", () => {
  it("maps the list payload and embeds per-site networks", async () => {
    get.mockImplementation((path: string) => {
      if (path === "/sites") return Promise.resolve({ items: [SITE] });
      return Promise.resolve({ items: [{ id: "n1", site_id: SITE.id, cidr: "192.168.1.0/24", exposure: "internal_only" }] });
    });
    const res = await fetchSites();
    expect(res.items).toHaveLength(1);
    expect(res.items[0]).toMatchObject({ id: SITE.id, name: "Default Site", kind: "lab", assets: 38 });
    expect(res.items[0].networks).toHaveLength(1);
    expect(res.items[0].networks[0].cidr).toBe("192.168.1.0/24");
    expect(get).toHaveBeenCalledTimes(2); // list + one fan-out
  });

  it("surfaces a contract violation instead of silently yielding an empty list", async () => {
    get.mockResolvedValue({}); // e.g. a proxy answered without the items array
    await expect(fetchSites()).rejects.toThrow(/unexpected response/);
  });

  it("rejects when the response is not an object at all", async () => {
    get.mockResolvedValue(undefined);
    await expect(fetchSites()).rejects.toThrow(/unexpected response/);
  });

  it("keeps the sites list when a networks fan-out fails", async () => {
    get.mockImplementation((path: string) => {
      if (path === "/sites") return Promise.resolve({ items: [SITE] });
      return Promise.reject(new Error("boom"));
    });
    const res = await fetchSites();
    expect(res.items).toHaveLength(1);
    expect(res.items[0].networks).toEqual([]);
  });

  it("degrades a malformed networks payload to an empty list", async () => {
    get.mockImplementation((path: string) => {
      if (path === "/sites") return Promise.resolve({ items: [SITE] });
      return Promise.resolve({}); // no items array in the networks response
    });
    const res = await fetchSites();
    expect(res.items[0].networks).toEqual([]);
  });
});
