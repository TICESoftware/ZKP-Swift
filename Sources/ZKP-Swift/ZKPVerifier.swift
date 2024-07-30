import SwiftECC
import Foundation
import BigInt
import CryptoKit

class ZKPVerifier {
    let issuerPublicKeyECPoint: Point
    let secp256r1Spec: Domain
    
    init(issuerPublicKey: ECPublicKey) {
        secp256r1Spec = Domain.instance(curve: .EC256r1)
        issuerPublicKeyECPoint = issuerPublicKey.w
    }
    
    func createChallenge(requestData: ChallengeRequestData) throws -> (ECPublicKey, ECPrivateKey) {
        guard let digest = Data(base64URLEncoded: requestData.digest),
              let rData = Data(base64URLEncoded: requestData.r) else {
            throw ZKPVerifierError.invalidBase64URLEncoding
        }
        
        let z = BInt(magnitude: Bytes(digest))
        let r = BInt(magnitude: Bytes(rData))
        
        let Gnew_1 = try secp256r1Spec.multiplyPoint(issuerPublicKeyECPoint, r)
        let Gnew_2 = try secp256r1Spec.multiplyPoint(secp256r1Spec.g, z)
        let Gnew = try secp256r1Spec.addPoints(Gnew_1, Gnew_2)
        
        let ephemeralPrivateKeyScalar = (secp256r1Spec.order - BInt.ONE).randomLessThan() + BInt.ONE
        let ephemeralPrivateKey = try ECPrivateKey(domain: secp256r1Spec, s: ephemeralPrivateKeyScalar)
        let ephemeralPublicKeyPoint = try secp256r1Spec.multiplyPoint(Gnew, ephemeralPrivateKeyScalar)
        let ephemeralPublicKey = try ECPublicKey(domain: secp256r1Spec, w: ephemeralPublicKeyPoint)
        
        return (ephemeralPublicKey, ephemeralPrivateKey)
    }
    
    func verifyChallenge(vpTokenFormat: VpTokenFormat, data: String, key: ECPrivateKey) throws -> Bool {
        return switch vpTokenFormat {
        case .sdJWT: try verifyChallengeSDJWT(jwt: data, key: key)
        case .msoMdoc: fatalError("not yet implemented")
        }
    }
    
    func verifyChallengeSDJWT(jwt: String, key: ECPrivateKey) throws -> Bool {
        let parts = jwt.split(separator: ".")
        let signature = decodeConcatSignature(signature: String(parts[2]))
        let decodedR = try secp256r1Spec.decodePoint(signature.r)
        let ourS = try secp256r1Spec.multiplyPoint(decodedR, key.s)
        let decodedS = try secp256r1Spec.decodePoint(signature.s)
        return ourS == decodedS
    }
}
