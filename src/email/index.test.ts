import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadTransport } from "./index.js";

describe("loadTransport", () => {
  let dir: string;
  beforeEach(() => { dir = mkdtempSync(join(tmpdir(), "ha-sel-")); });
  afterEach(() => { rmSync(dir, { recursive: true, force: true }); });

  it("uses the file transport when no smtpUrl is configured", async () => {
    const t = loadTransport({ mailFrom: "no-reply@x", mailDir: dir });
    await t.send({ to: "a@e.com", subject: "S", text: "t", html: "<p>h</p>" });
    expect(readdirSync(dir).filter((f) => f.endsWith(".eml"))).toHaveLength(1);
  });

  it("uses the file transport when smtpUrl is an empty string", async () => {
    const t = loadTransport({ smtpUrl: "", mailFrom: "no-reply@x", mailDir: dir });
    await t.send({ to: "a@e.com", subject: "S", text: "t", html: "<p>h</p>" });
    expect(readdirSync(dir).filter((f) => f.endsWith(".eml"))).toHaveLength(1);
  });

  it("returns an SMTP transport when smtpUrl is set, without connecting at construction", () => {
    const t = loadTransport({
      smtpUrl: "smtp://user:pass@127.0.0.1:2525", mailFrom: "no-reply@x", mailDir: dir,
    });
    expect(typeof t.send).toBe("function");
    expect(readdirSync(dir).filter((f) => f.endsWith(".eml"))).toHaveLength(0);
  });
});
