import { describe, it, expect, vi, afterEach } from "vitest";
import { getRequests, ApiError } from "./api.js";

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("api client", () => {
  it("returns the parsed body on success", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(
        async () =>
          new Response(JSON.stringify({ items: [], next_before: null }), {
            status: 200,
            headers: { "content-type": "application/json" },
          }),
      ),
    );
    expect(await getRequests({})).toEqual({ items: [], next_before: null });
  });

  it("throws a typed ApiError carrying the server's code", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(
        async () =>
          new Response(JSON.stringify({ error: "no_session", message: "sign-in required" }), {
            status: 401,
            headers: { "content-type": "application/json" },
          }),
      ),
    );
    await expect(getRequests({})).rejects.toMatchObject({ code: "no_session", status: 401 });
    await expect(getRequests({})).rejects.toBeInstanceOf(ApiError);
  });

  it("does not throw a parse error when the body is not JSON", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response("<html>502</html>", { status: 502 })));
    await expect(getRequests({})).rejects.toMatchObject({ status: 502 });
  });

  it("sends credentials so the session cookie is included", async () => {
    // Params are declared so the `calls[0][1]` index below is typed as the
    // RequestInit it actually is, rather than as an empty tuple.
    const spy = vi.fn(
      async (_input: RequestInfo | URL, _init?: RequestInit) =>
        new Response("{}", {
          status: 200,
          headers: { "content-type": "application/json" },
        }),
    );
    vi.stubGlobal("fetch", spy);
    await getRequests({});
    expect(spy.mock.calls[0][1]).toMatchObject({ credentials: "same-origin" });
  });
});
