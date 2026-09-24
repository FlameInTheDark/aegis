// mapInterfaces pins the asset-bundle interface contract for the Network
// tab: every recorded address (IPv4 AND IPv6) reaches the table, the
// hub-selected primary sorts first, and the flattened `ip` fallback chain
// survives payloads without addresses.
import { describe, expect, it, vi } from "vitest";

vi.mock("@/lib/api", () => ({ api: { get: vi.fn() } }));
vi.mock("@/lib/ws", () => ({
  ws: { connect: vi.fn(), disconnect: vi.fn(), subscribe: vi.fn(), unsubscribe: vi.fn(), on: vi.fn(), off: vi.fn() },
  useWSStatus: () => "connected",
}));

import { mapInterfaces } from "@/lib/queries";
import type { Interface } from "@/lib/api-types";

const NIC: Interface = {
  name: "Ethernet",
  mac: "b8:27:eb:aa:bb:cc",
  addresses: [
    // Windows enumeration order: IPv6 (link-local first) before IPv4, with
    // the hub having flagged the IPv4 as the primary.
    { ip: "fe80::1", is_primary: false },
    { ip: "2a02:6b8:c0e::1", is_primary: false },
    { ip: "192.168.1.80", is_primary: true },
  ],
};

describe("mapInterfaces", () => {
  it("keeps every address and puts the primary first", () => {
    const rows = mapInterfaces([NIC]);
    expect(rows).toHaveLength(1);
    expect(rows[0].addresses.map((a) => a.ip)).toEqual(["192.168.1.80", "fe80::1", "2a02:6b8:c0e::1"]);
    expect(rows[0].addresses.filter((a) => a.is_primary)).toHaveLength(1);
    expect(rows[0].ip).toBe("192.168.1.80");
    expect(rows[0].mac).toBe("b8:27:eb:aa:bb:cc");
  });

  it("falls back to the first address when no flag survived", () => {
    const rows = mapInterfaces([{ name: "wlan0", addresses: [{ ip: "10.0.0.5" }, { ip: "fd00::5" }] }]);
    expect(rows[0].ip).toBe("10.0.0.5");
    expect(rows[0].addresses).toHaveLength(2);
  });

  it("uses the backend-flattened ip when the addresses list is absent", () => {
    const rows = mapInterfaces([{ name: "eth0", ip: "172.16.0.9", vlan_id: 20 }]);
    expect(rows[0].ip).toBe("172.16.0.9");
    expect(rows[0].addresses).toEqual([]);
    expect(rows[0].vlan).toBe(20);
  });

  it("maps undefined and empty payloads to an empty table", () => {
    expect(mapInterfaces(undefined)).toEqual([]);
    expect(mapInterfaces([])).toEqual([]);
  });
});
