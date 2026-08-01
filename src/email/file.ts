import { mkdirSync, writeFileSync } from "node:fs";
import { randomUUID } from "node:crypto";
import { join } from "node:path";
import type { EmailMessage, EmailTransport } from "./transport.js";

/**
 * Writes each message to disk as an RFC-822-ish .eml instead of sending it.
 * This is what makes the whole notification path runnable and testable with
 * no SMTP account: the e2e suite reads these files, extracts the real link,
 * and drives the real approval flow. Deliberately not a no-op "null"
 * transport -- a channel you cannot observe is a channel you cannot test.
 *
 * The filename carries a UUID rather than only a timestamp because two
 * approvers on the same attestation are mailed in the same tick, and a
 * timestamp alone collides and silently drops one.
 */
export function createFileTransport(dir: string): EmailTransport {
  return {
    async send(msg: EmailMessage): Promise<void> {
      mkdirSync(dir, { recursive: true });
      const boundary = `----ha-${randomUUID()}`;
      const eml = [
        `Date: ${new Date().toUTCString()}`,
        `To: ${msg.to}`,
        `Subject: ${msg.subject}`,
        "MIME-Version: 1.0",
        `Content-Type: multipart/alternative; boundary="${boundary}"`,
        "",
        `--${boundary}`,
        'Content-Type: text/plain; charset="utf-8"',
        "",
        msg.text,
        "",
        `--${boundary}`,
        'Content-Type: text/html; charset="utf-8"',
        "",
        msg.html,
        "",
        `--${boundary}--`,
        "",
      ].join("\r\n");
      writeFileSync(join(dir, `${Date.now()}-${randomUUID()}.eml`), eml, "utf8");
    },
  };
}
