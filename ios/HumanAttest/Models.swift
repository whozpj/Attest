import Foundation

// Every type below mirrors the exact JSON the real server
// (src/api/routes.principals.ts, routes.attestations.ts) sends and expects —
// the same wire format demo/public/enrol.js and app.js already speak, just
// decoded natively instead of via the browser's WebAuthn API.

struct PrincipalCreated: Codable {
    let principal_id: String
    let enrolment_token: String
}

struct RegistrationOptionsResponse: Codable {
    let challenge: String
    let rp: RelyingParty
    let user: UserEntity
    let excludeCredentials: [CredentialDescriptor]?

    struct RelyingParty: Codable { let name: String; let id: String? }
    struct UserEntity: Codable { let id: String; let name: String; let displayName: String }
    struct CredentialDescriptor: Codable { let id: String; let type: String }
}

struct CredentialCreated: Codable {
    let credential_id: String
}

struct AuthenticationOptionsResponse: Codable {
    let challenge: String
    let rpId: String?
    let allowCredentials: [CredentialDescriptor]?

    struct CredentialDescriptor: Codable { let id: String; let type: String }
}

struct AttestationSummary: Codable {
    let attestation_id: String
    let status: String
    let payload_hash: String
    let summary: RenderedSummary?
    let token: String?

    struct RenderedSummary: Codable {
        let headline: String
        let fields: [Field]
        struct Field: Codable { let label: String; let value: String }
    }
}

struct DecisionResult: Codable {
    let status: String
    let token: String?
}
