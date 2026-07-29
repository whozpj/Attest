import Foundation

enum APIError: Error, LocalizedError {
    case http(Int, String)

    var errorDescription: String? {
        switch self {
        case .http(let code, let body): return "HTTP \(code): \(body)"
        }
    }
}

/// A thin native client for the real Human-Attest HTTP API — no mocking,
/// same endpoints and same JSON shapes demo/public/{enrol,app}.js already
/// use from the browser.
final class APIClient {
    private let baseURLString: String
    private let decoder = JSONDecoder()

    init(baseURLString: String = "http://localhost:3000") {
        self.baseURLString = baseURLString
    }

    // `URL.appendingPathComponent` percent-encodes "?", which breaks the
    // `?token=...` query strings several endpoints require — build the full
    // path+query as one string instead.
    private func send<T: Decodable>(_ pathWithQuery: String, method: String, jsonBody: Data? = nil) async throws -> T {
        guard let url = URL(string: baseURLString + pathWithQuery) else {
            throw APIError.http(-1, "malformed URL: \(pathWithQuery)")
        }
        var request = URLRequest(url: url)
        request.httpMethod = method
        if let jsonBody {
            request.httpBody = jsonBody
            request.setValue("application/json", forHTTPHeaderField: "content-type")
        }

        let (data, response) = try await URLSession.shared.data(for: request)
        guard let http = response as? HTTPURLResponse else {
            throw APIError.http(-1, "no HTTP response")
        }
        guard (200...299).contains(http.statusCode) else {
            throw APIError.http(http.statusCode, String(data: data, encoding: .utf8) ?? "")
        }
        return try decoder.decode(T.self, from: data)
    }

    func createPrincipal(email: String, displayName: String) async throws -> PrincipalCreated {
        let body = try JSONSerialization.data(withJSONObject: [
            "email": email, "display_name": displayName,
        ])
        return try await send("/v1/principals", method: "POST", jsonBody: body)
    }

    func registrationOptions(principalId: String, token: String) async throws -> RegistrationOptionsResponse {
        try await send(
            "/v1/principals/\(principalId)/credentials/options?token=\(token)",
            method: "POST",
        )
    }

    func finishRegistration(principalId: String, token: String, credentialJSON: Data) async throws -> CredentialCreated {
        try await send(
            "/v1/principals/\(principalId)/credentials?token=\(token)",
            method: "POST", jsonBody: credentialJSON,
        )
    }

    func getAttestation(_ id: String) async throws -> AttestationSummary {
        try await send("/v1/attestations/\(id)", method: "GET")
    }

    func attestationOptions(id: String, principalId: String, decision: String) async throws -> AuthenticationOptionsResponse {
        let body = try JSONSerialization.data(withJSONObject: [
            "principal_id": principalId, "decision": decision,
        ])
        return try await send("/v1/attestations/\(id)/options", method: "POST", jsonBody: body)
    }

    func submitDecision(id: String, principalId: String, decision: String, responseJSON: [String: Any]) async throws -> DecisionResult {
        let payload: [String: Any] = [
            "principal_id": principalId, "decision": decision, "response": responseJSON,
        ]
        let body = try JSONSerialization.data(withJSONObject: payload)
        return try await send("/v1/attestations/\(id)/decision", method: "POST", jsonBody: body)
    }
}
