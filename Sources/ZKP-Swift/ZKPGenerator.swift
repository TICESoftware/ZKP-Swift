import BigInt
import SwiftECC

struct ZKPGenerator {
    
    let issuerPublicKeyECPoint: Point
    let secp256r1Spec: Domain
    
    init(issuerPublicKey: ECPublicKey, domain: Domain = Domain.instance(curve: .EC256r1)) {
        self.issuerPublicKeyECPoint = issuerPublicKey.w
        self.secp256r1Spec = domain
    }
    
    func replaceSignatureWithZKP(ephemeralPublicKey: ECPublicKey, digest: Bytes, signatureR: Bytes, signatureS: Bytes) throws -> (Bytes, Bytes) {
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
