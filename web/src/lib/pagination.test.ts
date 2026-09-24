import { describe, expect, it, beforeEach, vi } from "vitest";

import {
  DEFAULT_PAGE_SIZE,
  PAGE_SIZE_OPTIONS,
  normalizePageSize,
  readStoredPageSize,
  storePageSize,
} from "./pagination";

const store = new Map<string, string>();

const localStorageStub = {
  getItem: (k: string) => store.get(k) ?? null,
  setItem: (k: string, v: string) => void store.set(k, v),
  removeItem: (k: string) => void store.delete(k),
  clear: () => store.clear(),
  key: (i: number) => Array.from(store.keys())[i] ?? null,
  get length() {
    return store.size;
  },
};

vi.stubGlobal("localStorage", localStorageStub);

describe("normalizePageSize", () => {
  it("accepts every advertised option", () => {
    for (const n of PAGE_SIZE_OPTIONS) expect(normalizePageSize(n)).toBe(n);
  });

  it("accepts numeric strings", () => {
    expect(normalizePageSize("50")).toBe(50);
    expect(normalizePageSize("200")).toBe(200);
  });

  it("falls back to 50 for junk, out-of-range and missing values", () => {
    expect(normalizePageSize(undefined)).toBe(DEFAULT_PAGE_SIZE);
    expect(normalizePageSize(null)).toBe(DEFAULT_PAGE_SIZE);
    expect(normalizePageSize("")).toBe(DEFAULT_PAGE_SIZE);
    expect(normalizePageSize("banana")).toBe(DEFAULT_PAGE_SIZE);
    expect(normalizePageSize(0)).toBe(DEFAULT_PAGE_SIZE);
    expect(normalizePageSize(-1)).toBe(DEFAULT_PAGE_SIZE);
    expect(normalizePageSize(17)).toBe(DEFAULT_PAGE_SIZE);
    expect(normalizePageSize(500)).toBe(DEFAULT_PAGE_SIZE);
    expect(normalizePageSize(50.5)).toBe(DEFAULT_PAGE_SIZE);
  });

  it("defaults to the product decision: 50 rows", () => {
    expect(DEFAULT_PAGE_SIZE).toBe(50);
  });
});

describe("stored page-size round-trip", () => {
  beforeEach(() => store.clear());

  it("stores and reads a per-table choice", () => {
    storePageSize("findings", 100);
    expect(readStoredPageSize("findings")).toBe(100);
    // other tables stay untouched
    expect(readStoredPageSize("assets")).toBe(DEFAULT_PAGE_SIZE);
  });

  it("keeps choices for different tables in one blob", () => {
    storePageSize("assets", 25);
    storePageSize("scans", 200);
    expect(readStoredPageSize("assets")).toBe(25);
    expect(readStoredPageSize("scans")).toBe(200);
  });

  it("survives a corrupted blob", () => {
    localStorageStub.setItem("aegis-page-size", "{not json");
    expect(readStoredPageSize("assets")).toBe(DEFAULT_PAGE_SIZE);
  });

  it("survives a hand-edited unknown value", () => {
    localStorageStub.setItem("aegis-page-size", JSON.stringify({ assets: 9999 }));
    expect(readStoredPageSize("assets")).toBe(DEFAULT_PAGE_SIZE);
  });
});
