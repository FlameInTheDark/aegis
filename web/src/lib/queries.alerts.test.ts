import { beforeEach, describe, expect, it, vi } from "vitest";

// Contract tests: pin the endpoint + request-body shape of the alerts
// data layer. The fetch transport is mocked; the factored request
// functions are the contract surface (same pattern as fetchSites).

const post = vi.fn();
const put = vi.fn();
const patch = vi.fn();
const del = vi.fn();

vi.mock("@/lib/api", () => ({
  api: {
    get: vi.fn(),
    post: (...a: unknown[]) => post(...a),
    put: (...a: unknown[]) => put(...a),
    patch: (...a: unknown[]) => patch(...a),
    del: (...a: unknown[]) => del(...a),
  },
}));

vi.mock("@/components/ui/toaster", () => ({ toast: vi.fn() }));

import {
  ackAlert, createDestination, createTrigger, deleteDestination, deleteTrigger,
  resolveAlert, replayDeadDeliveries, testDestination, testTrigger, toggleTrigger, updateDestination, updateTrigger,
} from "./queries.alerts";
import { draftToPayload, emptyDraft } from "./alert-draft";

describe("alerts API contracts", () => {
  beforeEach(() => {
    post.mockReset(); put.mockReset(); patch.mockReset(); del.mockReset();
    post.mockResolvedValue({});
    put.mockResolvedValue({});
    patch.mockResolvedValue({});
    del.mockResolvedValue(undefined);
  });

  it("createTrigger posts the serialized draft to /alerts/triggers", async () => {
    const d = emptyDraft();
    d.name = "cpu";
    await createTrigger(draftToPayload(d) as Record<string, unknown>);
    const [path, body] = post.mock.calls[0];
    expect(path).toBe("/alerts/triggers");
    expect(body.name).toBe("cpu");
    expect(body.kind).toBe("event");
  });

  it("updateTrigger puts the full payload with revision", async () => {
    await updateTrigger("t1", { name: "x", revision: 4 });
    const [path, body] = put.mock.calls[0];
    expect(path).toBe("/alerts/triggers/t1");
    expect(body.revision).toBe(4);
  });

  it("toggleTrigger patches the enabled endpoint", async () => {
    await toggleTrigger("t1", true);
    const [path, body] = patch.mock.calls[0];
    expect(path).toBe("/alerts/triggers/t1/enabled");
    expect(body).toEqual({ enabled: true });
  });

  it("deleteTrigger issues DELETE", async () => {
    await deleteTrigger("t2");
    expect(del.mock.calls[0][0]).toBe("/alerts/triggers/t2");
  });

  it("testDestination posts to the test endpoint", async () => {
    await testDestination("d1");
    expect(post.mock.calls[0][0]).toBe("/alerts/destinations/d1/test");
  });

  it("replay posts to the replay endpoint", async () => {
    await replayDeadDeliveries("d1");
    expect(post.mock.calls[0][0]).toBe("/alerts/destinations/d1/replay");
  });

  it("destination create posts the webhook body", async () => {
    await createDestination({ name: "relay", url: "https://x", kind: "webhook" });
    const [path, body] = post.mock.calls[0];
    expect(path).toBe("/alerts/destinations");
    expect(body.kind).toBe("webhook");
  });

  it("destination update patches", async () => {
    await updateDestination("d1", { enabled: false });
    expect(patch.mock.calls[0][0]).toBe("/alerts/destinations/d1");
  });

  it("ack and resolve post to the occurrence endpoints", async () => {
    await ackAlert("o1");
    await resolveAlert("o1");
    expect(post.mock.calls[0][0]).toBe("/alerts/o1/acknowledge");
    expect(post.mock.calls[1][0]).toBe("/alerts/o1/resolve");
  });

  it("testTrigger posts to the trigger test endpoint", async () => {
    await testTrigger("t1");
    expect(post.mock.calls[0][0]).toBe("/alerts/triggers/t1/test");
  });
});
