import Foundation
import MdocDataModel18013
import SwiftECC
import SwiftCBOR

enum ZKPProverMDOCError: Error {
    case invalidCBOR
    case unsupportedVerificationAlgorithm(Cose.VerifyAlgorithm)
}

class ZKPProverMDOC {
    
    let zkpGenerator: ZKPGenerator
    
    init(zkpGenerator: ZKPGenerator) {
        self.zkpGenerator = zkpGenerator
    }
    
    public func createChallengeRequestData(mdoc: String) throws -> ChallengeRequestData {
        let cbor = mdoc.toCBOR()
        
        guard let document = Document(cbor: cbor) else { throw ZKPProverMDOCError.invalidCBOR }
        
        guard document.issuerSigned.issuerAuth.verifyAlgorithm == .es256 else {
            throw ZKPProverMDOCError.unsupportedVerificationAlgorithm(document.issuerSigned.issuerAuth.verifyAlgorithm)
        }
        
        let signatureRelatedParts = document.issuerSigned.issuerAuth.signatureRelatedParts
        
        let digest = Data(signatureRelatedParts.digest).base64URLEncoded
        let r = Data(signatureRelatedParts.r).base64URLEncoded
        
        return ChallengeRequestData(digest: digest, r: r)
    }
    
    public func answerChallenge(ephemeralPublicKey: ECPublicKey, document: Document) throws -> Document {
        guard document.issuerSigned.issuerAuth.verifyAlgorithm == .es256 else {
            throw ZKPProverMDOCError.unsupportedVerificationAlgorithm(document.issuerSigned.issuerAuth.verifyAlgorithm)
        }
        
        let signatureRelatedParts = document.issuerSigned.issuerAuth.signatureRelatedParts
        
        let zkpSignature = try zkpGenerator.zeroKnowledgeProofFromSignature(ephemeralPublicKey: ephemeralPublicKey, digest: signatureRelatedParts.digest, signatureR: signatureRelatedParts.r, signatureS: signatureRelatedParts.s)
        
        let zkpSignatureData = Data(zkpSignature.r + zkpSignature.s)
        
        let newIssuerAuth = IssuerAuth(
            mso: document.issuerSigned.issuerAuth.mso,
            msoRawData: document.issuerSigned.issuerAuth.msoRawData,
            verifyAlgorithm: document.issuerSigned.issuerAuth.verifyAlgorithm,
            signature: zkpSignatureData,
            iaca: document.issuerSigned.issuerAuth.iaca
        )
        let newIssuerSigned = IssuerSigned(
            issuerNameSpaces: document.issuerSigned.issuerNameSpaces,
            issuerAuth: newIssuerAuth
        )
        let newDocument = Document(docType: document.docType, issuerSigned: newIssuerSigned, deviceSigned: document.deviceSigned, errors: document.errors)
        
        return newDocument
    }
    
    public func answerChallenge(ephemeralPublicKey: ECPublicKey, mdoc: String) throws -> String {
        let cbor = mdoc.toCBOR()
        
        guard let document = Document(cbor: cbor) else { throw ZKPProverMDOCError.invalidCBOR }
        
        let newDocument = try answerChallenge(ephemeralPublicKey: ephemeralPublicKey, document: document)
        
        let newCBOR = newDocument.toCBOR(options: CBOROptions())
        let newDocumentData = newCBOR.asData()
        return String(decoding: newDocumentData, as: UTF8.self)
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
