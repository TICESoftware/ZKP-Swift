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
            targets: ["ZKP-Swift"]),
    ],
    dependencies: [
        .package(url: "https://github.com/leif-ibsen/SwiftECC.git", from: "5.3.0"),
    ],
    targets: [
        // Targets are the basic building blocks of a package, defining a module or a test suite.
        // Targets can depend on other targets in this package and products from dependencies.
        .target(
            name: "ZKP-Swift",
            dependencies: [
                .product(name: "SwiftECC", package: "SwiftECC")
            ]
        ),
        .testTarget(
            name: "ZKP-SwiftTests",
            dependencies: ["ZKP-Swift"]),
    ]
)
