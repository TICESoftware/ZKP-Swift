import Foundation
import MdocDataModel18013
import SwiftECC
import SwiftCBOR

class ZKPProverMDOC {
    
    let zkpGenerator: ZKPGenerator
    
    init(zkpGenerator: ZKPGenerator) {
        self.zkpGenerator = zkpGenerator
    }
    
    public func createChallengeRequestData(mdoc: String) throws -> ChallengeRequestData {
        guard let data = Data(base64URLEncoded: mdoc) else {
            throw ZKPError.notBase64Decodable
        }
        
        guard let cbor = try CBOR.decode([UInt8](data)) else {
            throw ZKPError.invalidCBOR
        }
        
        guard let document = Document(cbor: cbor) else {
            throw ZKPError.invalidCBORDocument
        }
        
        return try createChallengeRequestData(issuerAuth: document.issuerSigned.issuerAuth)
    }
    
    public func createChallengeRequestData(issuerAuth: IssuerAuth) throws -> ChallengeRequestData {
        guard issuerAuth.verifyAlgorithm == .es256 else {
            throw ZKPError.unsupportedVerificationAlgorithm(issuerAuth.verifyAlgorithm)
        }
        
        let signatureRelatedParts = issuerAuth.signatureRelatedParts
        
        let digest = Data(signatureRelatedParts.digest).base64URLEncoded
        let r = Data(signatureRelatedParts.r).base64URLEncoded
        
        return ChallengeRequestData(digest: digest, r: r)
    }
    
    public func answerChallenge(ephemeralPublicKey: ECPublicKey, mdoc: String) throws -> String {
        guard let data = Data(base64URLEncoded: mdoc) else {
            throw ZKPError.notBase64Decodable
        }
        
        guard let cbor = try CBOR.decode([UInt8](data)) else {
            throw ZKPError.invalidCBOR
        }
        
        guard let document = Document(cbor: cbor) else {
            throw ZKPError.invalidCBORDocument
        }
        
        let newIssuerAuth = try answerChallenge(ephemeralPublicKey: ephemeralPublicKey, issuerAuth: document.issuerSigned.issuerAuth)
        
        let newIssuerSigned = IssuerSigned(issuerNameSpaces: document.issuerSigned.issuerNameSpaces, issuerAuth: newIssuerAuth)
        let newDocument = Document(docType: document.docType, issuerSigned: newIssuerSigned, deviceSigned: document.deviceSigned, errors: document.errors)
        
        return newDocument.toCBOR(options: .init()).asData().base64URLEncoded
    }
    
    public func answerChallenge(ephemeralPublicKey: ECPublicKey, issuerAuth: IssuerAuth) throws -> IssuerAuth {
        guard issuerAuth.verifyAlgorithm == .es256 else {
            throw ZKPError.unsupportedVerificationAlgorithm(issuerAuth.verifyAlgorithm)
        }
        
        let signatureRelatedParts = issuerAuth.signatureRelatedParts
        
        let zkpSignature = try zkpGenerator.zeroKnowledgeProofFromSignature(ephemeralPublicKey: ephemeralPublicKey, digest: signatureRelatedParts.digest, signatureR: signatureRelatedParts.r, signatureS: signatureRelatedParts.s)
        
        let zkpSignatureData = Data(zkpSignature.r + zkpSignature.s)
        
        let newIssuerAuth = IssuerAuth(
            mso: issuerAuth.mso,
            msoRawData: issuerAuth.msoRawData,
            verifyAlgorithm: issuerAuth.verifyAlgorithm,
            signature: zkpSignatureData,
            iaca: issuerAuth.iaca
        )
        return newIssuerAuth
    }
}

extension IssuerAuth {
    var signatureRelatedParts: SignatureRelatedParts {
        let digest = Bytes(msoRawData)
        let signatureRelatedParts = signatureFromIssuerAuthSignature(signatureData: signature)
        return SignatureRelatedParts(digest: digest, r: signatureRelatedParts.r, s: signatureRelatedParts.s)
    }
    
    func signatureFromIssuerAuthSignature(signatureData: Data) -> Signature {
        precondition(signatureData.count % 2 == 0)
        let r = signatureData.subdata(in: 0 ..< signatureData.count / 2)
        let s = signatureData.subdata(in: signatureData.count / 2 ..< signatureData.count)
        
        return Signature(r: Bytes(r), s: Bytes(s))
    }
}
