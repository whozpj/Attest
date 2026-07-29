  const params = new URLSearchParams(location.search);
  const principalId = params.get("principal");
  const token = params.get("token");

  function urlBase64ToUint8Array(base64String) {
    const padding = "=".repeat((4 - (base64String.length % 4)) % 4);
    const base64 = (base64String + padding).replace(/-/g, "+").replace(/_/g, "/");
    const raw = atob(base64);
    return Uint8Array.from([...raw].map((c) => c.charCodeAt(0)));
  }

  // Best-effort: registering for push must never block passkey enrolment.
  // Run before the WebAuthn ceremony below, because the enrolment token is
  // single-use and only burned once that ceremony finishes successfully —
  // this registration needs the token to still be live (see routes.push.ts).
  async function subscribeToPush() {
    if (!("serviceWorker" in navigator) || !("PushManager" in window)) return;
    const reg = await navigator.serviceWorker.register("/approve/sw.js");
    const permission = await Notification.requestPermission();
    if (permission !== "granted") return;
    const { publicKey } = await fetch("/v1/push/vapid-public-key").then((r) => r.json());
    const subscription = await reg.pushManager.subscribe({
      userVisibleOnly: true,
      applicationServerKey: urlBase64ToUint8Array(publicKey),
    });
    await fetch(`/v1/principals/${principalId}/push-subscription?token=${token}`, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ subscription: subscription.toJSON() }),
    });
  }

  document.getElementById("enrol").onclick = async () => {
    // subscribeToPush() awaits Notification.requestPermission() and
    // pushManager.subscribe(), neither of which has a timeout — if a real
    // user sees the permission prompt and just walks away without clicking
    // it, those promises never resolve or reject, and the existing
    // .catch(() => {}) below only handles rejection, not a stall. Race it
    // against a 15s timer so it can never block the WebAuthn ceremony that
    // follows indefinitely; a real permission-prompt decision is fast, this
    // only guards the pathological "never decided" case.
    await Promise.race([
      subscribeToPush(),
      new Promise((resolve) => setTimeout(resolve, 15000)),
    ]).catch(() => {});
    const optionsJSON = await fetch(`/v1/principals/${principalId}/credentials/options?token=${token}`, {
      method: "POST",
    }).then((r) => r.json());
    const response = await SimpleWebAuthnBrowser.startRegistration({ optionsJSON });
    const res = await fetch(`/v1/principals/${principalId}/credentials?token=${token}`, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify(response),
    });
    document.getElementById("status").textContent =
      res.ok ? "enrolled" : "failed";
  };
