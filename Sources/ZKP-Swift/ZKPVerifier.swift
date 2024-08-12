import BigInt
import CryptoKit
import Foundation
import SwiftECC
import MdocDataModel18013
import SwiftCBOR

class ZKPVerifier {
    let issuerPublicKeyECPoint: Point
    let domain: Domain

    init(issuerPublicKey: ECPublicKey, domain: Domain = Domain.instance(curve: .EC256r1)) {
        issuerPublicKeyECPoint = issuerPublicKey.w
        self.domain = domain
    }

    func createChallenge(requestData: ChallengeRequestData) throws -> (ECPublicKey, ECPrivateKey) {
        guard let digest = Data(base64URLEncoded: requestData.digest),
              let rData = Data(base64URLEncoded: requestData.r)
        else {
            throw ZKPError.invalidBase64URLEncoding
        }

        let z = BInt(magnitude: Bytes(digest))
        let r = BInt(magnitude: Bytes(rData))

        let Gnew_1 = try domain.multiplyPoint(issuerPublicKeyECPoint, r)
        let Gnew_2 = try domain.multiplyPoint(domain.g, z)
        let Gnew = try domain.addPoints(Gnew_1, Gnew_2)

        let ephemeralPrivateKeyScalar = (domain.order - BInt.ONE).randomLessThan() + BInt.ONE
        let ephemeralPrivateKey = try ECPrivateKey(domain: domain, s: ephemeralPrivateKeyScalar)
        let ephemeralPublicKeyPoint = try domain.multiplyPoint(Gnew, ephemeralPrivateKeyScalar)
        let ephemeralPublicKey = try ECPublicKey(domain: domain, w: ephemeralPublicKeyPoint)

        return (ephemeralPublicKey, ephemeralPrivateKey)
    }

    func verifyChallengeSDJWT(jwt: String, key: ECPrivateKey) throws -> Bool {
        let parts = jwt.split(separator: ".")
        let signature = try decodeConcatSignature(signature: String(parts[2]))
        let decodedR = try domain.decodePoint(signature.r)
        let ourS = try domain.multiplyPoint(decodedR, key.s)
        let decodedS = try domain.decodePoint(signature.s)
        return ourS == decodedS
    }
    
    func verifyChallengeMDOC(mdoc: String, key: ECPrivateKey) throws -> Bool {
        guard let data = Data(base64URLEncoded: mdoc) else {
            throw ZKPError.notBase64Decodable
        }
        
        guard let cbor = try CBOR.decode([UInt8](data)) else {
            throw ZKPError.invalidCBOR
        }
        
        guard let document = Document(cbor: cbor) else {
            throw ZKPError.invalidCBORDocument
        }
        
        return try verifyChallengeMDOC(issuerAuth: document.issuerSigned.issuerAuth, key: key)
    }
    
    func verifyChallengeMDOC(issuerAuth: IssuerAuth, key: ECPrivateKey) throws -> Bool {
        let signatureData = issuerAuth.signature
        let r = signatureData.subdata(in: 0 ..< signatureData.count / 2)
        let s = signatureData.subdata(in: signatureData.count / 2 ..< signatureData.count)
        let signature = Signature(r: Bytes(r), s: Bytes(s))
        
        let decodedR = try domain.decodePoint(signature.r)
        let ourS = try domain.multiplyPoint(decodedR, key.s)
        let decodedS = try domain.decodePoint(signature.s)
        return ourS == decodedS
    }
}
