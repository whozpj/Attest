import AuthenticationServices
import UIKit

enum WebAuthnClientError: Error, LocalizedError {
    case unexpectedCredentialType

    var errorDescription: String? {
        "The authenticator returned an unexpected credential type"
    }
}

/// Wraps Apple's native platform-passkey APIs
/// (`ASAuthorizationPlatformPublicKeyCredentialProvider`) — the same
/// underlying Face ID / Touch ID ceremony the server's WebAuthn endpoints
/// already expect, since WebAuthn is a standard, not a browser API. No
/// server-side change was needed to support this client.
final class WebAuthnClient: NSObject {
    private let rpId: String
    private var continuation: CheckedContinuation<ASAuthorization, Error>?

    init(rpId: String) {
        self.rpId = rpId
    }

    func register(challenge: Data, userId: Data, userName: String) async throws -> ASAuthorizationPlatformPublicKeyCredentialRegistration {
        let provider = ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier: rpId)
        let request = provider.createCredentialRegistrationRequest(
            challenge: challenge, name: userName, userID: userId,
        )
        let authorization = try await perform(request)
        guard let credential = authorization.credential as? ASAuthorizationPlatformPublicKeyCredentialRegistration else {
            throw WebAuthnClientError.unexpectedCredentialType
        }
        return credential
    }

    func assert(challenge: Data, allowedCredentialIDs: [Data]) async throws -> ASAuthorizationPlatformPublicKeyCredentialAssertion {
        let provider = ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier: rpId)
        let request = provider.createCredentialAssertionRequest(challenge: challenge)
        request.allowedCredentials = allowedCredentialIDs.map {
            ASAuthorizationPlatformPublicKeyCredentialDescriptor(credentialID: $0)
        }
        let authorization = try await perform(request)
        guard let credential = authorization.credential as? ASAuthorizationPlatformPublicKeyCredentialAssertion else {
            throw WebAuthnClientError.unexpectedCredentialType
        }
        return credential
    }

    private func perform(_ request: ASAuthorizationRequest) async throws -> ASAuthorization {
        try await withCheckedThrowingContinuation { continuation in
            self.continuation = continuation
            let controller = ASAuthorizationController(authorizationRequests: [request])
            controller.delegate = self
            controller.presentationContextProvider = self
            controller.performRequests()
        }
    }
}

extension WebAuthnClient: ASAuthorizationControllerDelegate {
    func authorizationController(controller: ASAuthorizationController, didCompleteWithAuthorization authorization: ASAuthorization) {
        continuation?.resume(returning: authorization)
        continuation = nil
    }

    func authorizationController(controller: ASAuthorizationController, didCompleteWithError error: Error) {
        continuation?.resume(throwing: error)
        continuation = nil
    }
}

extension WebAuthnClient: ASAuthorizationControllerPresentationContextProviding {
    func presentationAnchor(for controller: ASAuthorizationController) -> ASPresentationAnchor {
        for scene in UIApplication.shared.connectedScenes {
            if let windowScene = scene as? UIWindowScene, let window = windowScene.windows.first {
                return window
            }
        }
        return ASPresentationAnchor()
    }
}

/// Builds the exact RegistrationResponseJSON shape @simplewebauthn/server's
/// verifyRegistrationResponse expects (src/webauthn/registration.ts) from
/// Apple's native registration result.
enum RegistrationResponseBuilder {
    static func build(from credential: ASAuthorizationPlatformPublicKeyCredentialRegistration) -> Data {
        let id = Base64URL.encode(credential.credentialID)
        var response: [String: Any] = [
            "clientDataJSON": Base64URL.encode(credential.rawClientDataJSON),
        ]
        if let attestationObject = credential.rawAttestationObject {
            response["attestationObject"] = Base64URL.encode(attestationObject)
        }
        let dict: [String: Any] = [
            "id": id,
            "rawId": id,
            "type": "public-key",
            "response": response,
            "clientExtensionResults": [String: Any](),
        ]
        // Every field above is either our own base64url encoding or a fixed
        // literal, so this can only fail on a JSONSerialization programmer
        // error, not on caller input — an unrecoverable state, not a
        // reportable error.
        return try! JSONSerialization.data(withJSONObject: dict)
    }
}

/// Builds the exact AuthenticationResponseJSON shape
/// @simplewebauthn/server's verifyAuthenticationResponse expects
/// (src/webauthn/authentication.ts) from Apple's native assertion result.
enum AssertionResponseBuilder {
    static func build(from credential: ASAuthorizationPlatformPublicKeyCredentialAssertion) -> [String: Any] {
        let id = Base64URL.encode(credential.credentialID)
        var response: [String: Any] = [
            "clientDataJSON": Base64URL.encode(credential.rawClientDataJSON),
            "authenticatorData": Base64URL.encode(credential.rawAuthenticatorData),
            "signature": Base64URL.encode(credential.signature),
        ]
        if let userId = credential.userID {
            response["userHandle"] = Base64URL.encode(userId)
        }
        return [
            "id": id,
            "rawId": id,
            "type": "public-key",
            "response": response,
            "clientExtensionResults": [String: Any](),
        ]
    }
}
