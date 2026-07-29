  if ("serviceWorker" in navigator) {
    navigator.serviceWorker.register("/approve/sw.js").catch(() => {});
  }

  const params = new URLSearchParams(location.search);
  const attestationId = params.get("attestation");
  const principalId = params.get("principal");
  const status = document.getElementById("status");
  const approveBtn = document.getElementById("approve");
  const denyBtn = document.getElementById("deny");

  // A cold launch of the installed PWA (tapping the home-screen icon) opens
  // this page with no query string at all — manifest.json's start_url is
  // `/approve/app.html` with no attestation/principal, since the manifest
  // can't know which attestation in advance. Fetching `/v1/attestations/null`
  // would 404 and leave the page in a broken state, so render an honest
  // empty state instead of attempting the fetch.
  if (!attestationId || !principalId) {
    document.getElementById("headline").textContent = "No pending approval";
    status.textContent = "Open this page from an approval link or notification to review a request.";
    approveBtn.disabled = true;
    denyBtn.disabled = true;
  } else {
    const res = await fetch(`/v1/attestations/${attestationId}`);
    const att = await res.json();

    document.getElementById("headline").textContent =
      att.summary ? att.summary.headline : `Attestation is ${att.status}`;

    // Same rule as index.html: caller-controlled payload text is rendered via
    // textContent only, never innerHTML.
    const fieldsList = document.getElementById("fields");
    fieldsList.replaceChildren();
    for (const f of att.summary?.fields ?? []) {
      const dt = document.createElement("dt");
      dt.textContent = f.label;
      const dd = document.createElement("dd");
      dd.textContent = f.value;
      fieldsList.append(dt, dd);
    }

    if (att.status !== "pending") {
      approveBtn.disabled = true;
      denyBtn.disabled = true;
      status.textContent = `already ${att.status}`;
    }

    async function signAndDecide(decisionValue) {
      approveBtn.disabled = true;
      denyBtn.disabled = true;
      status.textContent = "Requesting signature…";
      try {
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
      } catch (err) {
        // Cancelling/dismissing the Face ID / Touch ID prompt is a routine,
        // expected way for startAuthentication to reject — not an edge case.
        // Without this catch, #status froze on "Requesting signature…" and
        // both buttons stayed disabled forever, with no way to retry short
        // of reloading the page. The attestation is still pending after a
        // failed ceremony, so it's safe to just re-enable both buttons.
        status.textContent = `Cancelled or failed: ${err.message}`;
        approveBtn.disabled = false;
        denyBtn.disabled = false;
      }
    }

    approveBtn.onclick = () => signAndDecide("approve");
    denyBtn.onclick = () => signAndDecide("deny");
  }
