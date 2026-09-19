// swift-tools-version: 6.0
import PackageDescription

// Test harness only. The app itself is built by ADToLocal.xcodeproj.
// It compiles just the pure decision logic so it can be unit tested with `swift test`.
let package = Package(
    name: "ADToLocalLogic",
    platforms: [.macOS(.v14)],
    targets: [
        .target(name: "ADToLocalLogic", path: "ADToLocal", sources: ["AccountLogic.swift"]),
        .testTarget(name: "ADToLocalLogicTests", dependencies: ["ADToLocalLogic"])
    ],
    swiftLanguageModes: [.v5]
)
