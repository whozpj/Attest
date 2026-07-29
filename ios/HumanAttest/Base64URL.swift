import Foundation

/// WebAuthn's JSON serialization (RFC 4648 §5, no padding) for every binary
/// field the server exchanges: challenges, credential ids, client data,
/// attestation objects, authenticator data, signatures. Apple's
/// AuthenticationServices APIs hand back raw `Data`; @simplewebauthn/server
/// on the other end expects these exact base64url strings.
enum Base64URL {
    static func encode(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    static func decode(_ string: String) -> Data? {
        var padded = string
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        while padded.count % 4 != 0 { padded += "=" }
        return Data(base64Encoded: padded)
    }
}
