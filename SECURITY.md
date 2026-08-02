# Security

Human-Attest exists to make one specific claim trustworthy: *a specific
human, using a registered passkey, signed off on this exact structured
action.* Its threat model is documented in detail, not just claimed —
`docs/human-attest-mvp.md` §4 states plainly both what this design defends
against and what it explicitly does not, and `tests/security/` (12 suites)
and `tests/e2e/*-attack.spec.ts` exist to keep those claims honest against
real signatures and real HTTP traffic, not just unit-level assertions.

## Reporting a vulnerability

This is an individually maintained portfolio project, not a funded product
with a security team or a bug bounty program — but a report against the
core claim above (the WebAuthn challenge binding, the closed-world action
schema, token verification, or anything that lets a human's signature be
replayed against an action they didn't see) will get a real, prompt
response.

Please report privately rather than opening a public issue:
**raprithvi@gmail.com**

Include what you found, how to reproduce it, and — if you have one — which
specific guarantee in `docs/human-attest-mvp.md` §4 it breaks. There's no
formal SLA, but expect an acknowledgment within a few days.

## Known, documented limitations

Stated here as plainly as they're stated in the code and docs, because an
honest "not defended" is worth more than a claim that doesn't hold up:

- **The signing key sits on disk unencrypted** (`keys/signing-key.json`) —
  see `docs/PRODUCTION.md` §2 for the portable-secret alternative
  (`SIGNING_KEY_JSON`).
- **No device-loss recovery.** A principal who loses their authenticator
  has no re-enrolment path today.
- **`/mcp` requires no caller authentication**, matching `/v1/*`'s existing
  posture — see `docs/PRODUCTION.md` §5. Since `POST /v1/attestations/verify`
  and the `consume_approval` MCP tool are single-use, anyone who can reach
  either endpoint *and* obtain a resolved attestation's token (also
  unauthenticated, via `GET /v1/attestations/:id`) can permanently deny the
  legitimate agent's ability to execute a real, human-approved action — not
  just read it. Put both surfaces behind a real network boundary; see
  `docs/PRODUCTION.md` §5 for detail.
- **A small number of MCP-layer rejections aren't audited.** Zod input
  validation failures, unknown tool names, and malformed JSON-RPC envelopes
  are answered by the MCP SDK itself before any application handler runs,
  so they don't reach this app's audit log — see `docs/PRODUCTION.md` §7 for
  the precise scope of this gap. None of these represent an authorization
  bypass; every rejection still rejects.
- **A compromised principal device, or a genuinely deceived human,** are
  both explicitly out of scope — no passkey-based system can fix either,
  and `docs/human-attest-mvp.md` §4 says so rather than implying otherwise.

If you're evaluating this project and want the fuller picture: the git
history itself is part of the record — commit messages document real
findings from real reviews (including a couple of genuine bugs a reviewing
agent found and I fixed), not just feature additions.
