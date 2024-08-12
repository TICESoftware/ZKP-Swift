import CryptoKit
import Digest
import SwiftECC
import SwiftCBOR
import XCTest
import MdocDataModel18013
@testable import ZKP_Swift

final class MDOCTests: XCTestCase {
    
    let issuerPublicKey = try! ECPublicKey(pem: publicKeyPEM)
    let issuerPrivateKey = try! ECPrivateKey(pem: privateKeyPEM)
    
    func testWholeFlow() throws {
        let generator = ZKPGenerator(issuerPublicKey: issuerPublicKey, domain: .instance(curve: .EC256r1))
        let prover = ZKPProverMDOC(zkpGenerator: generator)
        let verifier = ZKPVerifier(issuerPublicKey: issuerPublicKey)
        
        let cbor = try CBOR(base64URLEncoded: cbor_sample_device_response)
        let deviceResponse = DeviceResponse(cbor: cbor)!
        let issuerAuth = deviceResponse.documents![0].issuerSigned.issuerAuth
        
        let request = try prover.createChallengeRequestData(issuerAuth: issuerAuth)
        
        let (challengePublicKey, challengePrivateKey) = try verifier.createChallenge(requestData: request)
        
        let issuerAuthWithZKP = try prover.answerChallenge(ephemeralPublicKey: challengePublicKey, issuerAuth: issuerAuth)
        
        let result = try verifier.verifyChallengeMDOC(issuerAuth: issuerAuthWithZKP, key: challengePrivateKey)
        
        XCTAssertTrue(result)
    }
    
    func testLoadIssuerAuthFromKotlin() throws {
        let cbor = try CBOR(base64URLEncoded: documentWithZKPFromKotlin)
        let document = Document(cbor: cbor)!
        let issuerAuthWithZKP = document.issuerSigned.issuerAuth
        
        let kotlinChallengePrivateKeyPEM = """
        -----BEGIN PRIVATE KEY-----
        MEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCCqy0kOpeA+h+SZ4AhO
        /IteRgaYGvyVeAKBG2KK1eRUAg==
        -----END PRIVATE KEY-----
        """
        
        let challengePrivateKey = try ECPrivateKey(pem: kotlinChallengePrivateKeyPEM)
        
        let verifier = ZKPVerifier(issuerPublicKey: issuerPublicKey)
        let result = try verifier.verifyChallengeMDOC(issuerAuth: issuerAuthWithZKP, key: challengePrivateKey)
        
        XCTAssertTrue(result)
    }
}
