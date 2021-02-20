// swift-tools-version:5.3
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "JailbreakDetector",
    platforms: [
        .iOS(.v10)
    ],
    products: [
        .library(
            name: "JailbreakDetector",
            targets: ["JailbreakDetector"]),
    ],
    targets: [
        .target(
            name: "JailbreakDetector",
            dependencies: []),
        .testTarget(
            name: "JailbreakDetectorTests",
            dependencies: ["JailbreakDetector"]),
    ]
)
