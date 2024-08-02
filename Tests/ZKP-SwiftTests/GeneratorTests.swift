import CryptoKit
import Digest
import SwiftECC
import XCTest
@testable import ZKP_Swift

final class GeneratorTests: XCTestCase {
    
    let issuerPublicKey = try! ECPublicKey(pem: publicKeyPEM)
    let issuerPrivateKey = try! ECPrivateKey(pem: privateKeyPEM)
    
    func testDeterministicSignature() throws {
        let generator = ZKPGenerator(issuerPublicKey: issuerPublicKey, domain: .instance(curve: .EC256r1))
        
        let ephPubKey = try ECPublicKey(pem: ephPublicKeyPEM)
        
        let payloadData = Data("Some raw string".utf8)
        let sha256 = SHA256.hash(data: payloadData)
        let sha256Bytes = Bytes(sha256)
        
        let signature = issuerPrivateKey.sign(msg: sha256Bytes, deterministic: true)
        
        let zkpSignature = try generator.zeroKnowledgeProofFromSignature(ephemeralPublicKey: ephPubKey, digest: sha256Bytes, signatureR: signature.r, signatureS: signature.s)
        let base64EncodedSignature = zkpSignature.base64URLEncoded()
        
        XCTAssertEqual(base64EncodedSignature, "Am1Q-qb0kPPSZu8SyY44FK0EgBcFMPb0C6LCsIl6qjSbA45_2zadsTAEl8HDWIJWMK-EJNyV95_YL9V2rXuGj4y1")
    }
}
