import CryptoKit
import Foundation
import SwiftECC

class ZKPProverSDJWT {
    
    let zkpGenerator: ZKPGenerator
    
    init(zkpGenerator: ZKPGenerator) {
        self.zkpGenerator = zkpGenerator
    }
    
    func createChallengeRequestData(jwt: String) throws -> ChallengeRequestData {
        let parsedSDJWT = try parseSDJWT(jwt: jwt)
        let digest = Data(parsedSDJWT.digest).base64URLEncoded
        let r = Data(parsedSDJWT.r).base64URLEncoded
        return ChallengeRequestData(digest: digest, r: r)
    }
    
    func answerChallenge(ephemeralPublicKey: ECPublicKey, jwt: String) throws -> String {
        let parsedSDJWT = try parseSDJWT(jwt: jwt)
        let (R, S) = try zkpGenerator.replaceSignatureWithZKP(ephemeralPublicKey: ephemeralPublicKey, digest: parsedSDJWT.digest, signatureR: parsedSDJWT.r, signatureS: parsedSDJWT.s)
        let signature = Data(R + S).base64URLEncoded
        let parts = jwt.split(separator: ".")
        return "\(parts[0]).\(parts[1]).\(signature)"
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