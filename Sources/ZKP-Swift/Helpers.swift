import Foundation

public extension Data {
    var base64URLEncoded: String {
        
        // Step 1: Base64 encode the Data
        var base64String = self.base64EncodedString()
        
        // Step 2: Replace URL-unsafe characters and remove padding
        base64String = base64String.replacingOccurrences(of: "+", with: "-")
        base64String = base64String.replacingOccurrences(of: "/", with: "_")
        base64String = base64String.replacingOccurrences(of: "=", with: "")
        
        return base64String
    }
}

public extension Data {
    
    // Function to decode a Base64 URL encoded string
    init?(base64URLEncoded: String) {
        // Step 1: Replace URL-safe characters back to Base64 characters
        var base64String = base64URLEncoded
        base64String = base64String.replacingOccurrences(of: "-", with: "+")
        base64String = base64String.replacingOccurrences(of: "_", with: "/")
        
        // Step 2: Add padding if necessary
        let remainder = base64String.count % 4
        if remainder > 0 {
            base64String = base64String.padding(toLength: base64String.count + 4 - remainder, withPad: "=", startingAt: 0)
        }
        
        // Step 3: Decode the Base64 string to Data
        guard let data = Data(base64Encoded: base64String) else {
            return nil
        }
        
        self = data
    }
}

