enum ZKPProverError: Error {
    case invalidHeaderAndPayload
    case invalidJWT
}

enum ZKPVerifierError: Error {
    case invalidBase64URLEncoding
}

struct ChallengeRequestData {
    let digest: String
    let r: String
}

enum VpTokenFormat {
    case sdJWT
    case msoMdoc
}
