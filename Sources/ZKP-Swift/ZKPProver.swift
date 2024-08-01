import Foundation
import SwiftECC

public class ZKPProver {
    
    let zkpProverSDJWT: ZKPProverSDJWT
    
    init(zkpProverSDJWT: ZKPProverSDJWT) {
        self.zkpProverSDJWT = zkpProverSDJWT
    }

    public func createChallengeRequest(vpTokenFormat: VpTokenFormat, data: String) throws -> ChallengeRequestData {
        return switch vpTokenFormat {
        case .msoMdoc: fatalError("not implemented yet")
        case .sdJWT: try zkpProverSDJWT.createChallengeRequestData(jwt: data)
        }
    }

    public func answerChallenge(ephemeralPublicKey: ECPublicKey, vpTokenFormat: VpTokenFormat, data: String) throws -> String {
        return switch vpTokenFormat {
        case .msoMdoc: fatalError("not implemented yet")
        case .sdJWT: try zkpProverSDJWT.answerChallenge(ephemeralPublicKey: ephemeralPublicKey, jwt: data)
        }
    }
}
