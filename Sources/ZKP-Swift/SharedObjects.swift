import SwiftECC

public enum ZKPProverError: Error {
    case invalidHeaderAndPayload
    case invalidJWT
}

public enum ZKPVerifierError: Error {
    case invalidBase64URLEncoding
}

public struct ChallengeRequestData {
    public let digest: String
    public let r: String
}

public enum VpTokenFormat {
    case sdJWT
    case msoMdoc
}

public struct ECDSASignature {
    public let r: Bytes
    public let s: Bytes
}
