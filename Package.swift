// swift-tools-version: 5.10
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "ZKP-Swift",
    platforms: [.iOS(.v17), .macOS(.v14)],
    products: [
        // Products define the executables and libraries a package produces, making them visible to other packages.
        .library(
            name: "ZKP-Swift",
            targets: ["ZKP-Swift"]
        ),
    ],
    dependencies: [
        .package(url: "https://github.com/leif-ibsen/SwiftECC.git", from: "5.3.0"),
        .package(url: "https://github.com/eu-digital-identity-wallet/eudi-lib-ios-iso18013-data-model", from: "0.2.0")
    ],
    targets: [
        .target(
            name: "ZKP-Swift",
            dependencies: [
                .product(name: "SwiftECC", package: "SwiftECC"),
                .product(name: "MdocDataModel18013", package: "eudi-lib-ios-iso18013-data-model"),
            ]
        ),
        .testTarget(
            name: "ZKP-SwiftTests",
            dependencies: ["ZKP-Swift"]
        ),
    ]
)
