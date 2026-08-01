import { describe, it, expect } from "vitest";
import { renderApprovalEmail, renderEnrolmentEmail } from "./templates.js";

const base = {
  to: "approver@acme.com",
  headline: "Wire $25,000.00 USD to Acme Corp",
  fields: [
    { label: "Amount", value: "$25,000.00 USD" },
    { label: "Recipient", value: "Acme Corp" },
  ],
  requestedBy: "agent-platform-7",
  expiresAt: "2026-08-01T12:15:00.000Z",
  linkUrl: "http://localhost:3000/a/tok123",
};

describe("renderApprovalEmail", () => {
  it("puts the server-rendered headline in the subject and both bodies", () => {
    const msg = renderApprovalEmail(base);
    expect(msg.to).toBe("approver@acme.com");
    expect(msg.subject).toContain("Wire $25,000.00 USD to Acme Corp");
    expect(msg.text).toContain("Wire $25,000.00 USD to Acme Corp");
    expect(msg.html).toContain("Wire $25,000.00 USD to Acme Corp");
  });

  it("includes every rendered field and the link in both bodies", () => {
    const msg = renderApprovalEmail(base);
    for (const body of [msg.text, msg.html]) {
      expect(body).toContain("Amount");
      expect(body).toContain("$25,000.00 USD");
      expect(body).toContain("Recipient");
      expect(body).toContain("Acme Corp");
      expect(body).toContain("http://localhost:3000/a/tok123");
    }
  });

  it("escapes HTML in rendered values so a payload string cannot inject markup", () => {
    const msg = renderApprovalEmail({
      ...base,
      headline: 'Send email to <script>alert(1)</script>',
      fields: [{ label: "To", value: '"><img src=x onerror=alert(1)>' }],
    });
    expect(msg.html).not.toContain("<script>");
    expect(msg.html).not.toContain("<img src=x");
    expect(msg.html).toContain("&lt;script&gt;");
  });

  it("states that a passkey is required, so the link alone reads as non-authorizing", () => {
    expect(renderApprovalEmail(base).text.toLowerCase()).toContain("passkey");
  });
});

describe("renderEnrolmentEmail", () => {
  it("addresses the principal and carries the enrolment link", () => {
    const msg = renderEnrolmentEmail({
      to: "new@acme.com", displayName: "New User",
      linkUrl: "http://localhost:3000/enrol?principal=prin_1&token=abc",
    });
    expect(msg.to).toBe("new@acme.com");
    expect(msg.text).toContain("New User");
    expect(msg.text).toContain("http://localhost:3000/enrol?principal=prin_1&token=abc");
    expect(msg.html).toContain("http://localhost:3000/enrol?principal=prin_1&amp;token=abc");
  });

  it("escapes the display name", () => {
    const msg = renderEnrolmentEmail({
      to: "x@e.com", displayName: "<b>Bold</b>", linkUrl: "http://localhost:3000/enrol",
    });
    expect(msg.html).not.toContain("<b>Bold</b>");
    expect(msg.html).toContain("&lt;b&gt;Bold&lt;/b&gt;");
  });
});
