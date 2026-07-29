import SwiftUI

/// There is no APNs push in this app (Apple Push Notification service needs
/// a paid Apple Developer Program membership and real provisioning, neither
/// of which exists in this build environment — the same reasoning that led
/// the web companion to use VAPID Web Push instead of a native equivalent).
/// This view is the honest fallback: the agent's terminal output already
/// prints the attestation id in `approve_url`; paste it here to load and
/// decide on the real, pending attestation.
struct ApprovalView: View {
    let principalId: String

    @State private var attestationId = ""
    @State private var summary: AttestationSummary?
    @State private var status = ""
    @State private var isWorking = false

    private let api = APIClient()
    private let webAuthn = WebAuthnClient(rpId: relyingPartyID)

    var body: some View {
        Form {
            Section("Attestation") {
                TextField("Attestation ID", text: $attestationId)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                Button("Load") { Task { await load() } }
                    .disabled(attestationId.isEmpty || isWorking)
            }

            if let summary {
                Section(summary.summary?.headline ?? "Attestation \(summary.status)") {
                    ForEach(summary.summary?.fields ?? [], id: \.label) { field in
                        LabeledContent(field.label, value: field.value)
                    }
                }
                if summary.status == "pending" {
                    Section {
                        Button {
                            Task { await decide("approve") }
                        } label: {
                            Label("Approve", systemImage: "faceid")
                        }
                        .disabled(isWorking)

                        Button(role: .destructive) {
                            Task { await decide("deny") }
                        } label: {
                            Label("Deny", systemImage: "hand.raised")
                        }
                        .disabled(isWorking)
                    }
                }
            }

            if !status.isEmpty {
                Section("Status") {
                    Text(status).font(.system(.body, design: .monospaced))
                }
            }
        }
        .navigationTitle("Pending Approval")
    }

    private func load() async {
        isWorking = true
        defer { isWorking = false }
        do {
            summary = try await api.getAttestation(attestationId)
            status = ""
        } catch {
            status = "Failed to load: \(error.localizedDescription)"
        }
    }

    private func decide(_ decision: String) async {
        isWorking = true
        defer { isWorking = false }
        do {
            status = "Requesting signature…"
            let options = try await api.attestationOptions(
                id: attestationId, principalId: principalId, decision: decision,
            )
            guard let challenge = Base64URL.decode(options.challenge) else {
                status = "Failed: malformed options"
                return
            }
            let allowedIds = (options.allowCredentials ?? []).compactMap { Base64URL.decode($0.id) }

            status = "Waiting for Face ID…"
            let assertion = try await webAuthn.assert(challenge: challenge, allowedCredentialIDs: allowedIds)
            let responseJSON = AssertionResponseBuilder.build(from: assertion)

            status = "Submitting decision…"
            let result = try await api.submitDecision(
                id: attestationId, principalId: principalId, decision: decision, responseJSON: responseJSON,
            )
            status = result.status
            summary = try? await api.getAttestation(attestationId)
        } catch {
            status = "Failed: \(error.localizedDescription)"
        }
    }
}

#Preview {
    ApprovalView(principalId: "prin_preview")
}
