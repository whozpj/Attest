import SwiftUI

/// The relying party id this app's associated-domains entitlement and every
/// WebAuthn ceremony use — must match the real server's RP.id
/// (src/webauthn/config.ts, "localhost" by default). See
/// project.yml's `?mode=developer` comment for why "localhost" works here
/// without a publicly hosted apple-app-site-association file.
let relyingPartyID = "localhost"

struct EnrollView: View {
    @State private var email = "cfo@acme-demo.test"
    @State private var displayName = "Amara Chen, CFO"
    @State private var status = "Not enrolled"
    @State private var principalId: String?
    @State private var isWorking = false

    private let api = APIClient()
    private let webAuthn = WebAuthnClient(rpId: relyingPartyID)

    var body: some View {
        NavigationStack {
            Form {
                Section("New principal") {
                    TextField("Email", text: $email)
                        .textInputAutocapitalization(.never)
                        .keyboardType(.emailAddress)
                    TextField("Display name", text: $displayName)
                }
                Section {
                    Button {
                        Task { await enroll() }
                    } label: {
                        if isWorking {
                            ProgressView()
                        } else {
                            Label("Enrol with Face ID", systemImage: "faceid")
                        }
                    }
                    .disabled(isWorking)
                }
                Section("Status") {
                    Text(status)
                        .font(.system(.body, design: .monospaced))
                    if let principalId {
                        Text(principalId)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .textSelection(.enabled)
                    }
                }
                if let principalId, status == "enrolled" {
                    Section {
                        NavigationLink("Check for a pending approval") {
                            ApprovalView(principalId: principalId)
                        }
                    }
                }
            }
            .navigationTitle("Human-Attest")
        }
    }

    private func enroll() async {
        isWorking = true
        defer { isWorking = false }
        do {
            status = "Creating principal…"
            let created = try await api.createPrincipal(email: email, displayName: displayName)
            principalId = created.principal_id

            status = "Requesting registration options…"
            let options = try await api.registrationOptions(
                principalId: created.principal_id, token: created.enrolment_token,
            )
            guard let challenge = Base64URL.decode(options.challenge),
                  let userId = Base64URL.decode(options.user.id) else {
                status = "Failed: malformed options from server"
                return
            }

            status = "Waiting for Face ID…"
            let credential = try await webAuthn.register(
                challenge: challenge, userId: userId, userName: options.user.name,
            )
            let credentialJSON = RegistrationResponseBuilder.build(from: credential)

            status = "Verifying with server…"
            _ = try await api.finishRegistration(
                principalId: created.principal_id, token: created.enrolment_token, credentialJSON: credentialJSON,
            )

            status = "enrolled"
        } catch {
            status = "Failed: \(error.localizedDescription)"
        }
    }
}

#Preview {
    EnrollView()
}
