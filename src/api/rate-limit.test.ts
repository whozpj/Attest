// src/api/rate-limit.test.ts
import { describe, it, expect, beforeEach } from "vitest";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildServer } from "./server.js";

let app: Awaited<ReturnType<typeof buildServer>>;

beforeEach(async () => {
  app = await buildServer({
    dbPath: ":memory:",
    keyDir: mkdtempSync(join(tmpdir(), "ha-ratelimit-")),
  });
});

describe("rate limiting", () => {
  it("returns 429 after exceeding the principal-creation limit", async () => {
    let lastStatus = 200;
    for (let i = 0; i < 15; i++) {
      const res = await app.inject({
        method: "POST", url: "/v1/principals",
        payload: { email: `rl-${i}@test.local`, display_name: `RL ${i}` },
      });
      lastStatus = res.statusCode;
      if (lastStatus === 429) break;
    }
    expect(lastStatus).toBe(429);
  });

  it("does not rate-limit far below the configured threshold", async () => {
    const res = await app.inject({
      method: "POST", url: "/v1/principals",
      payload: { email: "rl-single@test.local", display_name: "Single" },
    });
    expect(res.statusCode).toBe(201);
  });
});
