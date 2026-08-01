import { createTransport } from "nodemailer";
import type { EmailMessage, EmailTransport } from "./transport.js";

/**
 * Constructing the nodemailer transport does not open a connection -- it
 * resolves one lazily, per send. That matters because the server builds its
 * transport at boot: a mail host that is briefly unreachable must not stop
 * the API from starting, when the only thing it degrades is a best-effort
 * notification channel.
 */
export function createSmtpTransport(url: string, from: string): EmailTransport {
  const transport = createTransport(url);
  return {
    async send(msg: EmailMessage): Promise<void> {
      await transport.sendMail({
        from, to: msg.to, subject: msg.subject, text: msg.text, html: msg.html,
      });
    },
  };
}
