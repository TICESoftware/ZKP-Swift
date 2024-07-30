import SwiftECC
import Foundation
import BigInt
import CryptoKit

enum ZKPProverError: Error {
    case invalidHeaderAndPayload
    case invalidJWT
}

class ZKPProver {
    
    let issuerPublicKeyECPoint: Point
    let secp256r1Spec: Domain
    
    init(issuerPublicKey: ECPublicKey) {
        secp256r1Spec = Domain.instance(curve: .EC256r1)
        issuerPublicKeyECPoint = issuerPublicKey.w
    }
    
    public func createChallengeRequestData(jwt: String) throws -> ChallengeRequestData {
        let parsedSDJWT = try parseSdJwt(jwt: jwt)
        let digest = Data(parsedSDJWT.digest).base64URLEncoded
        let r = Data(parsedSDJWT.r).base64URLEncoded
        return ChallengeRequestData(digest: digest, r: r)
    }
    
    public func answerChallenge(ephemeralPublicKey: ECPublicKey, jwt: String) throws -> String {
        let parsedSDJWT = try parseSdJwt(jwt: jwt)
        let (R, S) = try answerChallenge(ephemeralPublicKey: ephemeralPublicKey, digest: parsedSDJWT.digest, signatureR: parsedSDJWT.r, signatureS: parsedSDJWT.s)
        let signature = Data(R + S).base64URLEncoded
        let parts = jwt.split(separator: ".")
        return "\(parts[0]).\(parts[1]).\(signature)"
    }
    
    internal func answerChallenge(ephemeralPublicKey: ECPublicKey, digest: Bytes, signatureR: Bytes, signatureS: Bytes) throws -> (Bytes, Bytes) {
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
}

struct ChallengeRequestData {
    let digest: String
    let r: String
}

struct ParsedSdJwt {
    let digest: Bytes
    let r: Bytes
    let s: Bytes
}

func parseSdJwt(jwt: String) throws -> ParsedSdJwt {
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
    let (r, s) = decodeConcatSignature(signature: signaturePart)
    
    return ParsedSdJwt(digest: Bytes(digest), r: Bytes(r), s: Bytes(s))
}

func decodeConcatSignature(signature: String) -> (Data, Data) {
    // Decoding logic for the signature (implement this based on how the signature is concatenated)
    // This is a placeholder implementation
    let signatureData = Data(base64URLEncoded: signature)!
    
    let r = signatureData.subdata(in: 0..<signatureData.count/2)
    let s = signatureData.subdata(in: signatureData.count/2..<signatureData.count)
    
    return (r, s)
}
