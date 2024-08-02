import BigInt
import SwiftECC

struct ZKPGenerator {
    
    let issuerPublicKeyECPoint: Point
    let domain: Domain
    
    init(issuerPublicKey: ECPublicKey, domain: Domain = Domain.instance(curve: .EC256r1)) {
        self.issuerPublicKeyECPoint = issuerPublicKey.w
        self.domain = domain
    }
    
    func zeroKnowledgeProofFromSignature(ephemeralPublicKey: ECPublicKey, digest: Bytes, signatureR: Bytes, signatureS: Bytes) throws -> Signature {
        let s = BInt(magnitude: signatureS)
        let sInv = s.modInverse(domain.p)
        
        let r = BInt(magnitude: signatureR)
        let z = BInt(magnitude: digest)
        
        let Gnew_1 = try domain.multiplyPoint(domain.g, z)
        let Gnew_2 = try domain.multiplyPoint(issuerPublicKeyECPoint, r)
        let Gnew = try domain.addPoints(Gnew_1, Gnew_2)
        let R_unencoded = try domain.multiplyPoint(Gnew, sInv)
        let R = try domain.encodePoint(R_unencoded, true)
        
        let ephemeralPublicKeyPoint = ephemeralPublicKey.w
        let S_unencoded = try domain.multiplyPoint(ephemeralPublicKeyPoint, sInv)
        let S = try domain.encodePoint(S_unencoded, true)
        return Signature(r: R, s: S)
    }
}
