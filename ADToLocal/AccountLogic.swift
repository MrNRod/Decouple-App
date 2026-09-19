//
//  AccountLogic.swift
//  ADToLocal
//
//  Pure, Foundation-only decision logic. Nothing in this file touches the
//  system, so it can be unit tested with `swift test` (see Package.swift).
//

import Foundation

// MARK: - Input Validation

/// The target user name ends up in `dscl` paths and file-system commands that run as root,
/// and it can come from a managed preference. Only accept what macOS short names allow.
nonisolated enum UsernameValidator {
    static func isValid(_ name: String) -> Bool {
        guard (1...64).contains(name.utf8.count), !name.hasPrefix("-") else { return false }
        return name.utf8.allSatisfy { byte in
            switch byte {
            case UInt8(ascii: "a")...UInt8(ascii: "z"),
                 UInt8(ascii: "A")...UInt8(ascii: "Z"),
                 UInt8(ascii: "0")...UInt8(ascii: "9"),
                 UInt8(ascii: "."), UInt8(ascii: "_"), UInt8(ascii: "-"):
                return true
            default:
                return false
            }
        }
    }
}
