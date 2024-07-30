import Foundation
import SwiftECC

public extension Data {
    var base64URLEncoded: String {
        // Step 1: Base64 encode the Data
        var base64String = base64EncodedString()

        // Step 2: Replace URL-unsafe characters and remove padding
        base64String = base64String.replacingOccurrences(of: "+", with: "-")
        base64String = base64String.replacingOccurrences(of: "/", with: "_")
        base64String = base64String.replacingOccurrences(of: "=", with: "")

        return base64String
    }
}

public extension Data {
    init?(base64URLEncoded: String) {
        var base64String = base64URLEncoded
        base64String = base64String.replacingOccurrences(of: "-", with: "+")
        base64String = base64String.replacingOccurrences(of: "_", with: "/")

        let remainder = base64String.count % 4
        if remainder > 0 {
            base64String = base64String.padding(toLength: base64String.count + 4 - remainder, withPad: "=", startingAt: 0)
        }

        self.init(base64Encoded: base64String)
    }
}

func decodeConcatSignature(signature: String) -> Signature {
    precondition(signature.count % 2 == 0)
    let signatureData = Data(base64URLEncoded: signature)!

    let r = signatureData.subdata(in: 0 ..< signatureData.count / 2)
    let s = signatureData.subdata(in: signatureData.count / 2 ..< signatureData.count)

    return Signature(r: Bytes(r), s: Bytes(s))
}

struct Signature {
    let r: Bytes
    let s: Bytes
}
