// deleteAsset is the useDeleteAsset mutation body — these tests pin the
// endpoint contract: the DELETE goes to /assets/{id}, a 204 (the api client
// maps it to undefined) resolves cleanly so onSuccess cleanup runs, and a
// rejection (404 for a foreign/unknown asset, 403 for a role without
// asset:write) propagates to the caller's toast.
import { beforeEach, describe, expect, it, vi, type Mock } from "vitest";

vi.mock("@/lib/api", () => ({ api: { get: vi.fn(), del: vi.fn() } }));
vi.mock("@/lib/ws", () => ({
  ws: { connect: vi.fn(), disconnect: vi.fn(), subscribe: vi.fn(), unsubscribe: vi.fn(), on: vi.fn(), off: vi.fn() },
  useWSStatus: () => "connected",
}));
vi.mock("@/components/ui/toaster", () => ({ toast: vi.fn() }));

import { api } from "@/lib/api";
import { deleteAsset } from "@/lib/queries";

const del = api.del as unknown as Mock;

beforeEach(() => {
  del.mockReset();
});

describe("deleteAsset", () => {
  it("issues DELETE /assets/{id} and resolves on the 204", async () => {
    del.mockResolvedValue(undefined);
    await expect(deleteAsset("01a0c55c-06f4-7b1f-a0fc-0910de2a0029")).resolves.toBeUndefined();
    expect(del).toHaveBeenCalledTimes(1);
    expect(del).toHaveBeenCalledWith("/assets/01a0c55c-06f4-7b1f-a0fc-0910de2a0029");
  });

  it("propagates a failure so the dialog can toast it", async () => {
    del.mockRejectedValue(new Error("asset not found"));
    await expect(deleteAsset("01a0c55c-06f4-7b1f-a0fc-0910de2a0029")).rejects.toThrow(/asset not found/);
  });
});
