import type { EmailMessage } from "./transport.js";

/**
 * Every interpolated value in these templates originates from
 * src/actions/render.ts's RenderedSummary -- which is itself derived from the
 * canonicalized, hashed payload, never from caller-supplied display text.
 * That is the project's central invariant (design doc §1) extended to a new
 * output medium: the agent cannot control one character the human reads.
 *
 * Escaping is still mandatory. The invariant says the agent doesn't choose
 * the *template*; it does still choose payload *values* (a recipient name, an
 * email subject), and those land inside HTML. An unescaped `recipient_name`
 * of `<script>...` would execute in whatever mail client renders it.
 */
function esc(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

const SHELL = (title: string, inner: string) => `<!doctype html>
<html><body style="margin:0;padding:24px;background:#f6f7f9;font-family:system-ui,-apple-system,'Segoe UI',sans-serif;color:#111827">
<div style="max-width:520px;margin:0 auto;background:#fff;border:1px solid #e5e7eb;border-radius:10px;padding:28px">
<div style="font-weight:650;font-size:15px;margin-bottom:18px">Human-Attest</div>
<h1 style="font-size:19px;line-height:1.35;margin:0 0 6px">${title}</h1>
${inner}
</div></body></html>`;

const BUTTON = (url: string, label: string) =>
  `<a href="${esc(url)}" style="display:inline-block;background:#4f46e5;color:#fff;text-decoration:none;padding:11px 20px;border-radius:7px;font-weight:600;font-size:14px">${esc(label)}</a>`;

export function renderApprovalEmail(a: {
  to: string;
  headline: string;
  fields: Array<{ label: string; value: string }>;
  requestedBy: string;
  expiresAt: string;
  linkUrl: string;
}): EmailMessage {
  const rows = a.fields
    .map(
      (f) =>
        `<tr><td style="padding:5px 16px 5px 0;color:#6b7280;font-size:13px">${esc(f.label)}</td>` +
        `<td style="padding:5px 0;font-size:13px;font-weight:550">${esc(f.value)}</td></tr>`,
    )
    .join("");

  const text = [
    a.headline,
    "",
    `Requested by ${a.requestedBy}.`,
    `Expires ${a.expiresAt}.`,
    "",
    ...a.fields.map((f) => `${f.label}: ${f.value}`),
    "",
    `Review this request: ${a.linkUrl}`,
    "",
    "You will confirm with your passkey. This link on its own cannot approve",
    "or deny anything -- only your authenticator can.",
  ].join("\n");

  const html = SHELL(
    esc(a.headline),
    `<p style="color:#6b7280;font-size:13px;margin:0 0 16px">Requested by ${esc(a.requestedBy)} &middot; expires ${esc(a.expiresAt)}</p>
     <table style="border-collapse:collapse;margin:0 0 22px">${rows}</table>
     <div>${BUTTON(a.linkUrl, "Review request")}</div>
     <p style="color:#6b7280;font-size:12px;margin:18px 0 0">You will confirm with your passkey. This link on its own cannot approve or deny anything &mdash; only your authenticator can.</p>`,
  );

  return { to: a.to, subject: `Approval needed: ${a.headline}`, text, html };
}

export function renderEnrolmentEmail(a: {
  to: string;
  displayName: string;
  linkUrl: string;
}): EmailMessage {
  const text = [
    `Hello ${a.displayName},`,
    "",
    "Set up your passkey so you can approve requests:",
    a.linkUrl,
    "",
    "This link is single-use and expires in 15 minutes.",
  ].join("\n");

  const html = SHELL(
    "Set up your passkey",
    `<p style="font-size:14px;margin:0 0 16px">Hello ${esc(a.displayName)}, set up your passkey so you can approve requests.</p>
     <div>${BUTTON(a.linkUrl, "Enrol passkey")}</div>
     <p style="color:#6b7280;font-size:12px;margin:18px 0 0">This link is single-use and expires in 15 minutes.</p>`,
  );

  return { to: a.to, subject: "Set up your Human-Attest passkey", text, html };
}
