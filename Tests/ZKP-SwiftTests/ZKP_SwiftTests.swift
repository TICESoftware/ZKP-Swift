import XCTest
import SwiftECC
import Digest
import CryptoKit
@testable import ZKP_Swift

let privateKeyPEM = """
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgb4UzEf6QFxSVF9yz
TA3+WFFacPJfp2iXgd+A2ZEzPJqhRANCAASwW742XU1e8LxEz8heJcu7wxUDtfuZ
dPcme9vm4fEr/klnGLTCrMZDXUqNm9QXwW1z+gYDNZ0+ZPAYSDlkPb3e
-----END PRIVATE KEY-----
"""

let publicKeyPEM = """
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEsFu+Nl1NXvC8RM/IXiXLu8MVA7X7
mXT3Jnvb5uHxK/5JZxi0wqzGQ11KjZvUF8Ftc/oGAzWdPmTwGEg5ZD293g==
-----END PUBLIC KEY-----
"""

let ephPublicKeyPEM = """
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAETh2gvUk5JJmz+381XiN6gVZrAu4R
cqKw0CDsXMccimgga3wvNwjaMTFE34NFROJurbCOEtna6gSMFwQQk5Gt6Q==
-----END PUBLIC KEY-----
"""

let ephPrivateKeyPEM = """
-----BEGIN PRIVATE KEY-----
MIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQgandHRq1kbZypYtUN
CbiSWKbtgDpb44KNGEhyAU/FbVKgCgYIKoZIzj0DAQehRANCAAROHaC9STkkmbP7
fzVeI3qBVmsC7hFyorDQIOxcxxyKaCBrfC83CNoxMUTfg0VE4m6tsI4S2drqBIwX
BBCTka3p
-----END PRIVATE KEY-----
"""

let challengePEM = """
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEnXtC2D/1YWRQMUvN7Q2dhhA18s8
OReuOkJELEjEwGZ63z5t9rGJoxkxz1/PoQq63y2J+TK8CCT4YEXsP/xgSw==
-----END PUBLIC KEY-----
"""

final class ZKP_SwiftTests: XCTestCase {
    func testDeterministicSignature() throws {
        let issuerPrivateKey = try ECPrivateKey(pem: privateKeyPEM)
        let issuerPublicKey = try ECPublicKey(pem: publicKeyPEM)
        let prover = ZKPProver(issuerPublicKey: issuerPublicKey)
        
        let ephPubKey = try ECPublicKey(pem: ephPublicKeyPEM)
        
        let payloadData = "Some raw string".data(using: .utf8)!
        let sha256 = SHA256.hash(data: payloadData)
        let sha256Bytes = Bytes.init(sha256)
        let encoded = Base64.encode(sha256Bytes)
        print(encoded)
        
        let signature = issuerPrivateKey.sign(msg: sha256Bytes, deterministic: true)
        let signatureBase64UrlEncoded = Base64.encode(signature.r + signature.s, -1)
        print(signatureBase64UrlEncoded)
        
        let (R, S) = try prover.answerChallenge(ephemeralPublicKey: ephPubKey, digest: sha256Bytes, signatureR: signature.r, signatureS: signature.s)
        let base64EncodedSignature = Base64.encode(R + S, -1)
        
        XCTAssertEqual(base64EncodedSignature, "Am1Q+qb0kPPSZu8SyY44FK0EgBcFMPb0C6LCsIl6qjSbA45/2zadsTAEl8HDWIJWMK+EJNyV95/YL9V2rXuGj4y1")
    }
    
    func testKotlinSignature() throws {
        let issuerPublicKey = try ECPublicKey(pem: publicKeyPEM)
        
        let payloadData = "Some raw string".data(using: .utf8)!
        let payloadDigest = Bytes.init(SHA256.hash(data: payloadData))
        
        let signatureBase64URLEncoded = "v2eKEsw0rlxHIY1uUzXWkVB-WSnhcMTujqZmDeRAkURZqkWnUM4D1ixhzYn1pA7OSiP3FBxNIlv7I5TU0fce0g"
        let signatureData = Data(base64URLEncoded: signatureBase64URLEncoded)!
        let bytes = Bytes(signatureData)
        let r = Bytes(bytes[0..<bytes.count / 2])
        let s = Bytes(bytes[bytes.count / 2..<bytes.count])
        let domain = issuerPublicKey.domain
        let signature = ECSignature(domain: domain, r: r, s: s)
        
        XCTAssertTrue(issuerPublicKey.verify(signature: signature, msg: payloadDigest, bw: nil))
    }
    
    func testAnswerChallenge() throws {
        let issuerPrivateKey = try ECPrivateKey(pem: privateKeyPEM)
        let issuerPublicKey = try ECPublicKey(pem: publicKeyPEM)
        let prover = ZKPProver(issuerPublicKey: issuerPublicKey)
        
        let ephPubKey = try ECPublicKey(pem: challengePEM)
        let jwtFromKotlin = "eyJhbGciOiJFUzI1NiJ9.U29tZSByYXcgbWVzc2FnZQ.Zh2GRwhm36gpV1TZc_j5E74P4taykE0CxKICGPxVP-bsP1BQIKKixBJe6CQpAt0dizITTHQnLujDNFAMixcT-w"
        let zkpJwt = try prover.answerChallenge(ephemeralPublicKey: ephPubKey, jwt: jwtFromKotlin)
        print(zkpJwt)
    }
    
    func testCreateChallengeRequestSDJWT() throws {
        let issuerPrivateKey = try ECPrivateKey(pem: privateKeyPEM)
        let issuerPublicKey = try ECPublicKey(pem: publicKeyPEM)
        let prover = ZKPProver(issuerPublicKey: issuerPublicKey)
        
        let jwt = "eyJhbGciOiJFUzI1NiJ9.U29tZSByYXcgbWVzc2FnZQ.Zh2GRwhm36gpV1TZc_j5E74P4taykE0CxKICGPxVP-bsP1BQIKKixBJe6CQpAt0dizITTHQnLujDNFAMixcT-w"
        let challengeRequestData = try prover.createChallengeRequestData(jwt: jwt)
        print(challengeRequestData.digest)
        print(challengeRequestData.r)
    }
    
    func testGenerateKey() throws {
        let domain = Domain.instance(curve: .EC256r1)
        let (pub, pri) = domain.makeKeyPair()
        print(pub.pem)
        print(pri.pemPkcs8)
    }
}
