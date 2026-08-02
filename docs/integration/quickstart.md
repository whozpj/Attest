# Integration quickstart

This is the path a design partner follows to go from nothing to a verified,
offline-checkable attestation: create a principal, enrol a passkey, request
an attestation, poll it, and verify the resulting token against the
published key — without ever calling back into this service at verify time.

Run every command below from the project root, in the shell where you ran
`npm install`, so `node`'s module resolution finds this project's
`node_modules` (needed for the offline-verification step, which imports
`jose`). Prerequisite: the server is running (`npm run dev`) in another
terminal.

## 1. Create a principal

```bash
CREATED_PRINCIPAL=$(curl -s -X POST http://localhost:3000/v1/principals \
  -H 'content-type: application/json' \
  -d '{"email":"partner@example.com","display_name":"Design Partner"}')

echo "$CREATED_PRINCIPAL" | jq .

PRINCIPAL_ID=$(echo "$CREATED_PRINCIPAL" | jq -r .principal_id)
ENROLMENT_TOKEN=$(echo "$CREATED_PRINCIPAL" | jq -r .enrolment_token)
```

Hold onto `ENROLMENT_TOKEN` alongside `PRINCIPAL_ID` — it's single-use and
expires in 15 minutes, and it's what proves the next step is really being
done by (or for) this principal rather than by anyone who merely learned the
id. `principal_id` alone is not secret: it turns up in this same response's
enrolment email, and in `approve_url` a few steps from now.

That call also sent an enrolment email to `partner@example.com`. With
`SMTP_URL` unset (the default outside `NODE_ENV=production`), nothing leaves
the machine — instead, find the newest file in `mail/`:

```bash
ENROL_LINK=$(ls -t mail/*.eml | head -1 | xargs grep -o 'http://[^ ]*/enrol[^ "]*')
echo "$ENROL_LINK"
```

That link already contains both `PRINCIPAL_ID` and `ENROLMENT_TOKEN` — no
need to reconstruct it by hand, though you still can (see step 2).

## 2. Enrol a passkey

This step is not scriptable from a shell — it's a WebAuthn ceremony and
needs a real (or virtual) authenticator. With a platform authenticator
available (Touch ID, Windows Hello, or a security key), open the link you
just extracted from `mail/`, or construct it yourself:

```
http://localhost:3000/enrol?principal=<PRINCIPAL_ID>&token=<ENROLMENT_TOKEN>
```

substituting both values printed above, and click **Enrol passkey**. Missing
the token, or reusing one that's already enrolled a credential, fails the
same way an unknown principal would — there's no separate error to
distinguish "wrong token" from "principal doesn't exist" (see
`docs/api/reference.md`).

## 3. Create an attestation

```bash
CREATED=$(curl -s -X POST http://localhost:3000/v1/attestations \
  -H 'content-type: application/json' \
  -d "{
    \"requested_by\": \"quickstart\",
    \"approver_ids\": [\"$PRINCIPAL_ID\"],
    \"required_approvals\": 1,
    \"action\": {
      \"type\": \"wire_transfer\",
      \"risk_tier\": \"high\",
      \"payload\": {
        \"amount\": 2500000,
        \"currency\": \"USD\",
        \"recipient_name\": \"Acme Corp\",
        \"account_last4\": \"4821\"
      }
    }
  }")

echo "$CREATED" | jq .

ATTESTATION_ID=$(echo "$CREATED" | jq -r .attestation_id)
PAYLOAD_HASH=$(echo "$CREATED" | jq -r .payload_hash)
APPROVE_URL=$(echo "$CREATED" | jq -r .approve_url)
```

`PAYLOAD_HASH` is the value you will check the resolved token against in
step 6. Hold onto it — it is the hash of the *exact* action you asked to be
authorized.

`APPROVE_URL` points at `/requests/$ATTESTATION_ID` — useful to print or
log, but it requires the approver to already be signed in (see
`docs/api/reference.md`'s note on `POST /v1/attestations`). The approver's
actual, first-contact path is the email this same call sent them, same as
step 1's enrolment email:

```bash
sleep 1  # let the fire-and-forget send land
LINK=$(ls -t mail/*.eml | head -1 | xargs grep -o 'http://[^ ]*/a/[^ "]*')
echo "$LINK"
```

## 4. Approve it

Open the link you just extracted (or `APPROVE_URL`, if you're already signed
in) in the same browser you enrolled with, and click **Approve**. The
headline rendered on that page is derived server-side from the payload you
sent in step 3 — it is what the human actually saw before signing.

## 5. Poll for resolution

```bash
while true; do
  STATUS=$(curl -s "http://localhost:3000/v1/attestations/$ATTESTATION_ID" | jq -r .status)
  echo "status: $STATUS"
  [ "$STATUS" != "pending" ] && break
  sleep 1
done

TOKEN=$(curl -s "http://localhost:3000/v1/attestations/$ATTESTATION_ID" | jq -r .token)
```

If `STATUS` comes back `denied` or `expired`, `TOKEN` will be `null` — stop
here; there is nothing to verify.

## 6. Verify the token offline — and check it against *this* action

Fetch the published key and verify the token's signature and expiry locally,
using a JWT library (`jose`, already a dependency of this project) — no call
back to the Human-Attest service is required for this step:

```bash
TOKEN="$TOKEN" HASH="$PAYLOAD_HASH" node --input-type=module -e '
import { importJWK, jwtVerify } from "jose";

const jwks = await fetch("http://localhost:3000/.well-known/jwks.json").then((r) => r.json());
const key = await importJWK(jwks.keys[0], "ES256");
const { payload } = await jwtVerify(process.env.TOKEN, key, { algorithms: ["ES256"] });

console.log("token signature and expiry are valid");
console.log("act claim:     ", payload.act);
console.log("expected hash: ", process.env.HASH);

if (payload.act !== process.env.HASH) {
  console.error("MISMATCH — refuse to execute. This token does not cover this action.");
  process.exit(1);
}
console.log("MATCH — safe to execute.");
'
```

**This comparison — `payload.act` against the hash of the action you are
about to execute — is a hard requirement, not a suggestion.** A valid
signature only proves that some human approved some action through this
service; it says nothing about which action, unless the caller checks. If
you re-derive the action you're about to execute independently (for example,
re-reading it from your own ledger right before execution, rather than
reusing a cached `payload_hash`), you must canonicalize and hash that data
yourself and compare it here — the token by itself carries no assurance
that the action hasn't changed between creation and execution. This is the
one part of the security model the service cannot enforce: it has no way to
know what you are about to do with the approval, so it cannot check this for
you. **Skipping this comparison — accepting any token with `valid: true`
regardless of which action it names — voids the guarantee this service
exists to provide.**

## Equivalent: calling `/verify` instead

`POST /v1/attestations/verify` performs the same signature and expiry check
server-side and returns `{ "valid": true, "action_hash": "...", ... }` or
`{ "valid": false, "reason": "..." }` — always with HTTP `200`. It is
convenient, but it is not "offline": it requires trusting this service to be
reachable and honest at verify time. The offline path in step 6 above needs
only the JWKS, which you can cache. Either way, the hard requirement in step
6 still applies: check `action_hash` (or `act`) against the specific action
you are about to execute, not just `valid`.
