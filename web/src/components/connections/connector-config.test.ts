import { describe, expect, it } from "vitest";

import {
  connectionFunctions,
  defaultConnectorConfig,
  formatRate,
  DEFAULT_NMAP_PATH,
  DEFAULT_PROBE_RATE_MS,
  DEFAULT_PULL_RATE_MS,
} from "./connector-config";

describe("connectionFunctions", () => {
  it("defaults each function to the connection kind's own", () => {
    expect(connectionFunctions("agent", {})).toEqual(["agent"]);
    expect(connectionFunctions("scanner", {})).toEqual(["scanner"]);
    expect(connectionFunctions("collector", {})).toEqual([]);
  });

  it("explicit section toggles override the kind default (hybrid)", () => {
    expect(connectionFunctions("agent", { scanner: { enabled: true } })).toEqual(["agent", "scanner"]);
    expect(connectionFunctions("scanner", { agent: { enabled: true }, scanner: { enabled: false } })).toEqual(["agent"]);
  });
});

describe("defaultConnectorConfig", () => {
  it("fills kind defaults, section defaults and metrics cadence defaults", () => {
    const cfg = defaultConnectorConfig("agent", {});
    expect(cfg.heartbeat_secs).toBe(60);
    expect(cfg.agent?.enabled).toBe(true);
    expect(cfg.agent?.collection_level).toBe("basic");
    expect(cfg.agent?.probe_rate_ms).toBe(DEFAULT_PROBE_RATE_MS);
    expect(cfg.agent?.pull_rate_ms).toBe(DEFAULT_PULL_RATE_MS);
    expect(cfg.scanner?.enabled).toBe(false);
    expect(cfg.scanner?.engine).toBe("auto");
    expect(cfg.scanner?.nmap_path).toBe(DEFAULT_NMAP_PATH);
    expect(cfg.scanner?.ssh_timeout_secs).toBe(30);
    expect(cfg.scanner?.ssh_insecure).toBe(false);
  });

  it("keeps stored section values, including the metrics cadence", () => {
    const cfg = defaultConnectorConfig("scanner", {
      heartbeat_secs: 120,
      agent: { enabled: true, collection_level: "full", probe_rate_ms: 250, pull_rate_ms: 15000 },
      scanner: { enabled: true, engine: "nmap", ssh_user: "scan" },
    });
    expect(cfg.heartbeat_secs).toBe(120);
    expect(cfg.agent).toMatchObject({ enabled: true, collection_level: "full", probe_rate_ms: 250, pull_rate_ms: 15000 });
    expect(cfg.scanner).toMatchObject({ enabled: true, engine: "nmap", ssh_user: "scan" });
  });

  it("falls back to the legacy flat keys when the section is absent", () => {
    const cfg = defaultConnectorConfig("agent", {
      collection_level: "standard",
      engine: "simulated",
      probe_rate_ms: 1000,
    });
    expect(cfg.agent?.collection_level).toBe("standard");
    expect(cfg.agent?.probe_rate_ms).toBe(1000);
    expect(cfg.scanner?.engine).toBe("simulated");
  });

  it("ignores invalid cadence values and applies the defaults", () => {
    const cfg = defaultConnectorConfig("agent", {
      agent: { probe_rate_ms: 0, pull_rate_ms: -50 },
    });
    expect(cfg.agent?.probe_rate_ms).toBe(DEFAULT_PROBE_RATE_MS);
    expect(cfg.agent?.pull_rate_ms).toBe(DEFAULT_PULL_RATE_MS);
  });

  it("handles a connection with no stored config at all", () => {
    const cfg = defaultConnectorConfig("scanner");
    expect(cfg.agent?.enabled).toBe(false);
    expect(cfg.scanner?.enabled).toBe(true);
    expect(cfg.agent?.probe_rate_ms).toBe(DEFAULT_PROBE_RATE_MS);
  });
});

describe("formatRate", () => {
  it("renders milliseconds, seconds and minutes", () => {
    expect(formatRate(100)).toBe("100 ms");
    expect(formatRate(1000)).toBe("1 s");
    expect(formatRate(2500)).toBe("2.5 s");
    expect(formatRate(60000)).toBe("1 min");
    expect(formatRate(90000)).toBe("1.5 min");
  });

  it("falls back to 0 ms for absent or invalid values", () => {
    expect(formatRate(undefined)).toBe("0 ms");
    expect(formatRate(0)).toBe("0 ms");
    expect(formatRate(-5)).toBe("0 ms");
  });
});
