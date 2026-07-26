const API = "http://localhost:3000";

async function main(): Promise<void> {
  const principalId = process.argv[2];
  if (!principalId) throw new Error("usage: npm run demo -- <principal_id>");

  const created = await fetch(`${API}/v1/attestations`, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({
      requested_by: "demo-agent",
      approver_ids: [principalId],
      required_approvals: 1,
      action: {
        type: "wire_transfer",
        risk_tier: "high",
        payload: {
          amount: 2500000, currency: "USD",
          recipient_name: "Acme Corp", account_last4: "4821",
        },
      },
    }),
  }).then((r) => r.json());

  console.log(`\nAction requires human approval.`);
  console.log(`  ${created.summary.headline}`);
  console.log(`\nApprove at:\n  ${created.approve_url}&principal=${principalId}\n`);

  // Block until the human resolves it.
  for (;;) {
    const att = await fetch(`${API}/v1/attestations/${created.attestation_id}`).then((r) => r.json());
    if (att.status !== "pending") {
      if (att.status !== "approved") {
        console.log(`Refusing to execute: attestation ${att.status}.`);
        return;
      }
      const verified = await fetch(`${API}/v1/attestations/verify`, {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ token: att.token }),
      }).then((r) => r.json());

      if (!verified.valid || verified.action_hash !== created.payload_hash) {
        console.log("Refusing to execute: token did not verify against this action.");
        return;
      }
      console.log("Verified. Executing wire transfer.");
      return;
    }
    await new Promise((r) => setTimeout(r, 1000));
  }
}

await main();
