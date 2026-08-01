import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createFileTransport } from "./file.js";

describe("file transport", () => {
  let dir: string;
  beforeEach(() => { dir = mkdtempSync(join(tmpdir(), "ha-mail-")); });
  afterEach(() => { rmSync(dir, { recursive: true, force: true }); });

  it("writes one .eml file per message, containing headers and both bodies", async () => {
    const t = createFileTransport(dir);
    await t.send({ to: "a@example.com", subject: "Hi", text: "plain body", html: "<p>rich body</p>" });

    const files = readdirSync(dir).filter((f) => f.endsWith(".eml"));
    expect(files).toHaveLength(1);
    const contents = readFileSync(join(dir, files[0]), "utf8");
    expect(contents).toContain("To: a@example.com");
    expect(contents).toContain("Subject: Hi");
    expect(contents).toContain("plain body");
    expect(contents).toContain("<p>rich body</p>");
  });

  it("creates the directory if it does not exist", async () => {
    const nested = join(dir, "deep", "deeper");
    await createFileTransport(nested).send({ to: "b@e.com", subject: "S", text: "t", html: "<p>h</p>" });
    expect(readdirSync(nested).filter((f) => f.endsWith(".eml"))).toHaveLength(1);
  });

  it("does not overwrite when two messages are sent in the same millisecond", async () => {
    const t = createFileTransport(dir);
    await Promise.all([
      t.send({ to: "a@e.com", subject: "One", text: "1", html: "<p>1</p>" }),
      t.send({ to: "b@e.com", subject: "Two", text: "2", html: "<p>2</p>" }),
    ]);
    expect(readdirSync(dir).filter((f) => f.endsWith(".eml"))).toHaveLength(2);
  });
});
