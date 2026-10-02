// swift-tools-version: 6.0
import PackageDescription

// Test harness only. The app itself is built by Decouple.xcodeproj.
// It compiles just the pure decision logic so it can be unit tested with `swift test`.
let package = Package(
    name: "DecoupleLogic",
    platforms: [.macOS(.v14)],
    targets: [
        .target(name: "DecoupleLogic", path: "Decouple", sources: ["AccountLogic.swift"]),
        .testTarget(name: "DecoupleLogicTests", dependencies: ["DecoupleLogic"])
    ],
    swiftLanguageModes: [.v5]
)
