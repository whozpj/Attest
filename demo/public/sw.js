self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", (event) => event.waitUntil(self.clients.claim()));

// Shows a system notification for every push, and separately forwards the
// same payload to any already-open client tabs via postMessage — a real
// open tab can react live to a push without waiting for a reload, and it
// also gives tests a way to observe genuine end-to-end delivery.
self.addEventListener("push", (event) => {
  let data = { title: "Approval requested", body: "You have a pending approval.", url: "/approve/app.html" };
  try {
    if (event.data) data = { ...data, ...event.data.json() };
  } catch {
    // Malformed or missing push payload: fall back to the generic message
    // above rather than dropping the notification entirely.
  }

  event.waitUntil(Promise.all([
    self.registration.showNotification(data.title, {
      body: data.body,
      data: { url: data.url },
      tag: data.attestation_id ?? "human-attest",
    }),
    self.clients.matchAll({ type: "window", includeUncontrolled: true }).then((clients) => {
      for (const client of clients) client.postMessage({ type: "push-received", ...data });
    }),
  ]));
});

self.addEventListener("notificationclick", (event) => {
  event.notification.close();
  const url = event.notification.data?.url ?? "/approve/app.html";
  event.waitUntil(
    self.clients.matchAll({ type: "window", includeUncontrolled: true }).then((clients) => {
      for (const client of clients) {
        if (client.url === url && "focus" in client) return client.focus();
      }
      return self.clients.openWindow(url);
    }),
  );
});
