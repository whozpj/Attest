import { createFileTransport } from "./file.js";
import { createSmtpTransport } from "./smtp.js";
import type { EmailTransport } from "./transport.js";

export type { EmailMessage, EmailTransport } from "./transport.js";
export { renderApprovalEmail, renderEnrolmentEmail } from "./templates.js";

export interface EmailConfig {
  smtpUrl?: string;
  mailFrom: string;
  mailDir: string;
}

/**
 * SMTP when configured, files on disk otherwise. The fallback is deliberately
 * a real, inspectable artifact rather than a silent no-op: a developer running
 * `npm run dev` can open the .eml and click through, and the e2e suite drives
 * the genuine flow. src/config.ts refuses to boot in production without
 * SMTP_URL, so this fallback can never be the accidental production state.
 */
export function loadTransport(cfg: EmailConfig): EmailTransport {
  if (cfg.smtpUrl && cfg.smtpUrl.length > 0) {
    return createSmtpTransport(cfg.smtpUrl, cfg.mailFrom);
  }
  return createFileTransport(cfg.mailDir);
}
