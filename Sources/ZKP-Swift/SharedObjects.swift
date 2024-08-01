public enum ZKPProverError: Error {
    case invalidHeaderAndPayload
    case invalidJWT
}

public enum ZKPVerifierError: Error {
    case invalidBase64URLEncoding
}

public struct ChallengeRequestData {
    let digest: String
    let r: String
}

public enum VpTokenFormat {
    case sdJWT
    case msoMdoc
}
