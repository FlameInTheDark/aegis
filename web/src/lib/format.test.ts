import { describe, expect, it } from "vitest";
import { fmtBps, fmtBytes } from "@/lib/format";

describe("fmtBytes", () => {
  it("formats byte sizes with binary units", () => {
    expect(fmtBytes(0)).toBe("0 B");
    expect(fmtBytes(512)).toBe("512 B");
    expect(fmtBytes(1024)).toBe("1.0 KiB");
    expect(fmtBytes(1536)).toBe("1.5 KiB");
    expect(fmtBytes(1024 * 1024)).toBe("1.0 MiB");
    expect(fmtBytes(3.5 * 1024 * 1024 * 1024)).toBe("3.5 GiB");
    expect(fmtBytes(2 * 1024 * 1024 * 1024 * 1024)).toBe("2.0 TiB");
  });

  it("handles missing and invalid values", () => {
    expect(fmtBytes(undefined)).toBe("—");
    expect(fmtBytes(null)).toBe("—");
    expect(fmtBytes(Number.NaN)).toBe("—");
  });

  it("rounds large values without decimals", () => {
    expect(fmtBytes(150 * 1024 * 1024 * 1024)).toBe("150 GiB");
  });
});

describe("fmtBps", () => {
  it("appends a per-second unit", () => {
    expect(fmtBps(1024)).toBe("1.0 KiB/s");
    expect(fmtBps(0)).toBe("0 B/s");
    expect(fmtBps(undefined)).toBe("—");
  });
});
