import BigInt
import CryptoKit
import Foundation
import SwiftECC

class ZKPProver {
    let issuerPublicKeyECPoint: Point
    let secp256r1Spec: Domain

    init(issuerPublicKey: ECPublicKey) {
        secp256r1Spec = Domain.instance(curve: .EC256r1)
        issuerPublicKeyECPoint = issuerPublicKey.w
    }

    public func createChallengeRequest(vpTokenFormat: VpTokenFormat, data: String) throws -> ChallengeRequestData {
        return switch vpTokenFormat {
        case .msoMdoc: fatalError("not implemented yet")
        case .sdJWT: try createChallengeRequestDataSDJWT(jwt: data)
        }
    }

    func createChallengeRequestDataSDJWT(jwt: String) throws -> ChallengeRequestData {
        let parsedSDJWT = try parseSDJWT(jwt: jwt)
        let digest = Data(parsedSDJWT.digest).base64URLEncoded
        let r = Data(parsedSDJWT.r).base64URLEncoded
        return ChallengeRequestData(digest: digest, r: r)
    }

    public func answerChallenge(ephemeralPublicKey: ECPublicKey, vpTokenFormat: VpTokenFormat, data: String) throws -> String {
        return switch vpTokenFormat {
        case .msoMdoc: fatalError("not implemented yet")
        case .sdJWT: try answerChallengeSDJWT(ephemeralPublicKey: ephemeralPublicKey, jwt: data)
        }
    }

    func answerChallengeSDJWT(ephemeralPublicKey: ECPublicKey, jwt: String) throws -> String {
        let parsedSDJWT = try parseSDJWT(jwt: jwt)
        let (R, S) = try answerChallenge(ephemeralPublicKey: ephemeralPublicKey, digest: parsedSDJWT.digest, signatureR: parsedSDJWT.r, signatureS: parsedSDJWT.s)
        let signature = Data(R + S).base64URLEncoded
        let parts = jwt.split(separator: ".")
        return "\(parts[0]).\(parts[1]).\(signature)"
    }

    func answerChallenge(ephemeralPublicKey: ECPublicKey, digest: Bytes, signatureR: Bytes, signatureS: Bytes) throws -> (Bytes, Bytes) {
        let s = BInt(magnitude: signatureS)
        let sInv = s.modInverse(secp256r1Spec.p)

        let r = BInt(magnitude: signatureR)
        let z = BInt(magnitude: digest)

        let Gnew_1 = try secp256r1Spec.multiplyPoint(secp256r1Spec.g, z)
        let Gnew_2 = try secp256r1Spec.multiplyPoint(issuerPublicKeyECPoint, r)
        let Gnew = try secp256r1Spec.addPoints(Gnew_1, Gnew_2)
        let R_unencoded = try secp256r1Spec.multiplyPoint(Gnew, sInv)
        let R = try secp256r1Spec.encodePoint(R_unencoded, true)

        let ephemeralPublicKeyPoint = ephemeralPublicKey.w
        let S_unencoded = try secp256r1Spec.multiplyPoint(ephemeralPublicKeyPoint, sInv)
        let S = try secp256r1Spec.encodePoint(S_unencoded, true)
        return (R, S)
    }

    private struct ParsedSDJWT {
        let digest: Bytes
        let r: Bytes
        let s: Bytes
    }

    private func parseSDJWT(jwt: String) throws -> ParsedSDJWT {
        let parts = jwt.split(separator: ".")

        guard parts.count == 3 else {
            throw ZKPProverError.invalidJWT
        }

        let headerAndPayload = "\(parts[0]).\(parts[1])"

        guard let headerAndPayloadData = headerAndPayload.data(using: .utf8) else {
            throw ZKPProverError.invalidHeaderAndPayload
        }

        let digest = SHA256.hash(data: headerAndPayloadData)
        let signaturePart = String(parts[2])
        let signature = decodeConcatSignature(signature: signaturePart)

        return ParsedSDJWT(digest: Bytes(digest), r: signature.r, s: signature.s)
    }
}
