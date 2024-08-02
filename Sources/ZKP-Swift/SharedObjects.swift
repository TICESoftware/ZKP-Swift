import SwiftECC
import MdocDataModel18013

public enum ZKPError: Error {
    case invalidBase64URLEncoding
    case invalidHeaderAndPayload
    case invalidJWT
    case notBase64Decodable
    case invalidCBOR
    case invalidCBORDocument
    case unsupportedVerificationAlgorithm(Cose.VerifyAlgorithm)
    case invalidSignatureLength
}

public struct ChallengeRequestData {
    public let digest: String
    public let r: String
}

public typealias JWT = String

public enum VpTokenFormat {
    case sdJWT
    case msoMdoc
}

public struct ECDSASignature {
    public let r: Bytes
    public let s: Bytes
}

internal struct SignatureRelatedParts {
    let digest: Bytes
    let r: Bytes
    let s: Bytes
}
