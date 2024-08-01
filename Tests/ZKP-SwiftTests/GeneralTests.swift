import CryptoKit
import Digest
import SwiftECC
import XCTest
@testable import ZKP_Swift

final class SDJWTTests: XCTestCase {
    
    let issuerPublicKey = try! ECPublicKey(pem: publicKeyPEM)
    let issuerPrivateKey = try! ECPrivateKey(pem: privateKeyPEM)
    
    func testWholeFlow() throws {
        let generator = ZKPGenerator(issuerPublicKey: issuerPublicKey, domain: .instance(curve: .EC256r1))
        let proverSDJWT = ZKPProverSDJWT(zkpGenerator: generator)
        let prover = ZKPProver(zkpProverSDJWT: proverSDJWT)
        let verifier = ZKPVerifier(issuerPublicKey: issuerPublicKey)

        let someJwt = "eyJhbGciOiJFUzI1NiJ9.U29tZSByYXcgbWVzc2FnZQ.Zh2GRwhm36gpV1TZc_j5E74P4taykE0CxKICGPxVP-bsP1BQIKKixBJe6CQpAt0dizITTHQnLujDNFAMixcT-w"
        let request = try prover.createChallengeRequest(vpTokenFormat: .sdJWT, data: someJwt)

        let (challengePublicKey, challengePrivateKey) = try verifier.createChallenge(requestData: request)

        let answer = try prover.answerChallenge(ephemeralPublicKey: challengePublicKey, vpTokenFormat: .sdJWT, data: someJwt)

        let result = try verifier.verifyChallenge(vpTokenFormat: .sdJWT, data: answer, key: challengePrivateKey)

        XCTAssertTrue(result)
    }

    func testAnswerChallengeFromKotlin() throws {
        let generator = ZKPGenerator(issuerPublicKey: issuerPublicKey, domain: .instance(curve: .EC256r1))
        let proverSDJWT = ZKPProverSDJWT(zkpGenerator: generator)
        let prover = ZKPProver(zkpProverSDJWT: proverSDJWT)

        let ephPubKey = try ECPublicKey(pem: challengePublicKeyPEM)
        let jwtFromKotlin = "eyJhbGciOiJFUzI1NiJ9.U29tZSByYXcgbWVzc2FnZQ.Zh2GRwhm36gpV1TZc_j5E74P4taykE0CxKICGPxVP-bsP1BQIKKixBJe6CQpAt0dizITTHQnLujDNFAMixcT-w"
        let zkpJwt = try prover.answerChallenge(ephemeralPublicKey: ephPubKey, vpTokenFormat: .sdJWT, data: jwtFromKotlin)

        let jwtParts = jwtFromKotlin.split(separator: ".")
        let zkpJwtParts = zkpJwt.split(separator: ".")

        XCTAssertEqual(jwtParts[0], zkpJwtParts[0])
        XCTAssertEqual(jwtParts[1], zkpJwtParts[1])
        XCTAssertNotEqual(jwtParts[2], zkpJwtParts[2])

        // There is a test on kotlin side that verifies that this answer is a valid zkp proof
        XCTAssertEqual(zkpJwtParts[2], "AjeYqOQOhFykHYcZaZ2Xa-M7CjM1XVXFYZ9pPXQBWdLvA5xBdYSr9aI_8ak0cosZj5qW-Bc4RUeeVN7BqUoggzJ5")
    }

    func testCreateChallengeRequestSDJWT() throws {
        let generator = ZKPGenerator(issuerPublicKey: issuerPublicKey, domain: .instance(curve: .EC256r1))
        let proverSDJWT = ZKPProverSDJWT(zkpGenerator: generator)
        let prover = ZKPProver(zkpProverSDJWT: proverSDJWT)

        let jwt = "eyJhbGciOiJFUzI1NiJ9.U29tZSByYXcgbWVzc2FnZQ.Zh2GRwhm36gpV1TZc_j5E74P4taykE0CxKICGPxVP-bsP1BQIKKixBJe6CQpAt0dizITTHQnLujDNFAMixcT-w"
        let challengeRequestData = try prover.createChallengeRequest(vpTokenFormat: .sdJWT, data: jwt)

        XCTAssertEqual(challengeRequestData.digest, "nLT2lz465dAnKWRSfjsImppvJ4gun1Rzy2_RPYH4fec")
        XCTAssertEqual(challengeRequestData.r, "Zh2GRwhm36gpV1TZc_j5E74P4taykE0CxKICGPxVP-Y")
    }
}
