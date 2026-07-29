  const params = new URLSearchParams(location.search);
  const attestationId = params.get("attestation");
  const principalId = params.get("principal");
  const status = document.getElementById("status");

  const res = await fetch(`/v1/attestations/${attestationId}`);
  const att = await res.json();

  document.getElementById("headline").textContent =
    att.summary ? att.summary.headline : `Attestation is ${att.status}`;

  // f.label and f.value are caller-controlled payload text (recipient_name,
  // subject, title, detail, document_name, ...). The closed-world validator
  // only constrains which *fields* exist, never the contents of a legitimate
  // string field, so this data must be treated as hostile. String-building
  // HTML and assigning it via innerHTML would let a crafted field turn into
  // markup the human reads instead of the value that was actually hashed and
  // signed -- textContent is the only assignment that cannot be interpreted
  // as markup, no matter what the string contains.
  const fieldsList = document.getElementById("fields");
  fieldsList.replaceChildren();
  for (const f of att.summary?.fields ?? []) {
    const dt = document.createElement("dt");
    dt.textContent = f.label;
    const dd = document.createElement("dd");
    dd.textContent = f.value;
    fieldsList.append(dt, dd);
  }

  // Approve and deny both require a signed WebAuthn assertion: the challenge
  // is bound to (action hash, decision), so a signature captured for one
  // decision can never be replayed as the other. Deny is not a free,
  // unauthenticated action -- it authorises stopping this specific action
  // exactly as much as approve authorises running it.
  async function signAndDecide(decisionValue) {
    status.textContent = "Requesting signature…";
    const optsRes = await fetch(`/v1/attestations/${attestationId}/options`, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ principal_id: principalId, decision: decisionValue }),
    });
    const response = await SimpleWebAuthnBrowser.startAuthentication({
      optionsJSON: await optsRes.json(),
    });
    const decisionRes = await fetch(`/v1/attestations/${attestationId}/decision`, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ principal_id: principalId, decision: decisionValue, response }),
    });
    status.textContent = JSON.stringify(await decisionRes.json());
  }

  document.getElementById("approve").onclick = () => signAndDecide("approve");
  document.getElementById("deny").onclick = () => signAndDecide("deny");
