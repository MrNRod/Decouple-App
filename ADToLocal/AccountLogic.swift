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

/// Guards the recursive, root-level file operations against a bad `NFSHomeDirectory`.
nonisolated enum HomeDirectoryValidator {
    private static let systemRoots: Set<String> = [
        "/", "/Users", "/Users/Shared", "/System", "/Library", "/Applications", "/private", "/var",
        "/usr", "/bin", "/sbin", "/etc", "/opt", "/Volumes", "/tmp", "/cores"
    ]

    static func isSafe(_ path: String, forUser user: String) -> Bool {
        guard path.hasPrefix("/"), !path.contains("\0") else { return false }
        let components = path.split(separator: "/", omittingEmptySubsequences: true)
        guard components.count >= 2, !components.contains(".."), !components.contains(".") else { return false }
        guard !systemRoots.contains("/" + components.joined(separator: "/")) else { return false }
        // Recursive ownership changes only run on a folder that is clearly this user's.
        return components.last.map { $0.caseInsensitiveCompare(user) == .orderedSame } ?? false
    }
}

// MARK: - AuthenticationAuthority

/// A fresh local account keeps `ShadowHash` (the password), `SecureToken` (FileVault unlock)
/// and a `Kerberosv5 ... @LKDC:SHA1...` entry (the local KDC). Only Active Directory entries go.
nonisolated enum AuthorityFilter {
    /// Entries that must never be removed. Removing them can lock the user out at the FileVault screen.
    static func isProtected(_ entry: String) -> Bool {
        entry.contains("ShadowHash") || entry.contains("SecureToken") || entry.contains("LKDC:")
    }

    static func isActiveDirectory(_ entry: String) -> Bool {
        let trimmed = entry.trimmingCharacters(in: .whitespaces)
        guard !isProtected(trimmed) else { return false }
        return trimmed.contains("LocalCachedUser")
            || trimmed.contains("Kerberosv5")
            || trimmed.contains("Active Directory")
            || trimmed.hasPrefix(";NetLogon;")
    }

    static func entriesToRemove(from entries: [String]) -> [String] {
        entries.filter(isActiveDirectory)
    }
}

/// `AltSecurityIdentities` is used by local accounts too (an Apple Account adds an `X509:` value).
/// Only AD Kerberos principals are removed, never the whole attribute.
nonisolated enum AltIdentityFilter {
    static func isActiveDirectory(_ value: String) -> Bool {
        let trimmed = value.trimmingCharacters(in: .whitespaces)
        return trimmed.hasPrefix("Kerberos:") && !trimmed.contains("LKDC:")
    }
}

/// AD mobile accounts carry `user@DOMAIN` aliases in `RecordName`. A fresh account has none.
nonisolated enum RecordNameFilter {
    static func isDomainAlias(_ value: String) -> Bool {
        value.contains("@") && !value.contains("LKDC")
    }
}

// MARK: - AD Attributes

nonisolated enum ADAttributes {
    /// Attributes an AD mobile account adds and a local account never has.
    /// Deliberately NOT here (a fresh account can legitimately have them):
    /// `AltSecurityIdentities` (value-filtered), `accountPolicyData` (cleared with pwpolicy),
    /// `_writers_LinkedIdentity` (Apple Account), and the virtual `AppleMeta*` attributes.
    static let names: [String] = [
        "CachedGroups",
        "SMBPrimaryGroupSID",
        "OriginalAuthenticationAuthority",
        "OriginalNodeName",
        "SMBSID",
        "SMBScriptPath",
        "SMBPasswordLastSet",
        "SMBGroupRID",
        "MCXSettings",
        "MCXFlags",
        "accountType",
        "CopyTimestamp",
        "dsAttrTypeNative:account_instance",
        "dsAttrTypeNative:cached_auth_policy",
        "dsAttrTypeNative:cached_groups",
        "dsAttrTypeNative:original_realname",
        "dsAttrTypeNative:original_shell",
        "dsAttrTypeNative:preserved_attributes",
        "dsAttrTypeNative:email_address",
        "dsAttrTypeStandard:PrimaryNTDomain",
        "FirstName",
        "LastName",
        "JobTitle",
        "Company",
        "Department",
        "EMailAddress"
    ]

    private static let lookup = Set(names.map(normalized))

    /// Strips the `dsAttrType…:` namespace and case so plist keys can be matched to `names`.
    static func normalized(_ key: String) -> String {
        var name = key
        for prefix in ["dsAttrTypeStandard:", "dsAttrTypeNative:"] where name.hasPrefix(prefix) {
            name.removeFirst(prefix.count)
        }
        return name.lowercased()
    }

    /// The record keys (exactly as `dscl` reports them) that are AD leftovers.
    static func keysToRemove(from recordKeys: [String]) -> [String] {
        recordKeys.filter { lookup.contains(normalized($0)) }.sorted()
    }
}

// MARK: - Account Snapshot

/// A parsed `dscl -plist . -read /Users/<name>`.
nonisolated struct AccountSnapshot: Sendable, Equatable {
    static let allowedPolicyKeys: Set<String> = [
        "creationTime", "failedLoginCount", "failedLoginTimestamp", "passwordLastSetTime"
    ]
    static let freshPrimaryGroupID = 20

    let attributes: [String: [String]]

    init(attributes: [String: [String]]) {
        self.attributes = attributes
    }

    /// Returns nil when the data isn't a property-list dictionary (for example, the user doesn't exist).
    init?(plistData: Data) {
        guard let object = try? PropertyListSerialization.propertyList(from: plistData, format: nil),
              let dictionary = object as? [String: Any] else { return nil }
        var parsed: [String: [String]] = [:]
        for (key, value) in dictionary {
            guard let array = value as? [Any] else { continue }
            parsed[key] = array.map { element in
                if let string = element as? String { return string }
                if let data = element as? Data { return "<\(data.count) bytes>" }
                return String(describing: element)
            }
        }
        self.attributes = parsed
    }

    /// Looks an attribute up by short name (`RecordName`) or full key.
    func values(_ name: String) -> [String] {
        attributes[name]
            ?? attributes["dsAttrTypeStandard:" + name]
            ?? attributes["dsAttrTypeNative:" + name]
            ?? []
    }

    var recordNames: [String] { values("RecordName") }
    var authorityEntries: [String] { values("AuthenticationAuthority") }
    var uniqueID: Int? { values("UniqueID").first.flatMap { Int($0) } }
    var primaryGroupID: Int? { values("PrimaryGroupID").first.flatMap { Int($0) } }
    var generatedUID: String? { values("GeneratedUID").first }
    var homeDirectory: String? { values("NFSHomeDirectory").first }

    var hasSecureToken: Bool { authorityEntries.contains { $0.contains("SecureToken") } }
    var adAuthorityEntries: [String] { AuthorityFilter.entriesToRemove(from: authorityEntries) }
    var adAltIdentities: [String] { values("AltSecurityIdentities").filter(AltIdentityFilter.isActiveDirectory) }
    var domainRecordNames: [String] { recordNames.filter(RecordNameFilter.isDomainAlias) }
    var adAttributeKeys: [String] { ADAttributes.keysToRemove(from: Array(attributes.keys)) }

    /// A mobile account is one whose authority still points at Active Directory.
    var isMobileAccount: Bool { !adAuthorityEntries.isEmpty }

    /// Keys in `accountPolicyData` that a fresh account doesn't have (AD-imposed password rules).
    var extraPolicyKeys: [String] {
        guard let xml = values("accountPolicyData").first,
              let object = try? PropertyListSerialization.propertyList(from: Data(xml.utf8), format: nil),
              let policy = object as? [String: Any] else { return [] }
        return policy.keys.filter { !Self.allowedPolicyKeys.contains($0) }.sorted()
    }

    /// Restore point written before anything is changed. The password hash is never included.
    func backupPlistData(extra: [String: String]) throws -> Data {
        var record: [String: Any] = [:]
        for (key, value) in attributes where !key.localizedCaseInsensitiveContains("ShadowHash") {
            record[key] = value
        }
        let document: [String: Any] = ["record": record, "context": extra]
        return try PropertyListSerialization.data(fromPropertyList: document, format: .xml, options: 0)
    }
}

// MARK: - FileVault

nonisolated enum FileVaultParser {
    static func isEnabled(fdesetupStatus output: String) -> Bool {
        output.contains("FileVault is On")
    }

    /// UUIDs listed by `diskutil apfs listCryptoUsers /`, upper-cased.
    static func cryptoUserUUIDs(from output: String) -> Set<String> {
        let pattern = "[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}"
        var found: Set<String> = []
        var searchRange = output.startIndex..<output.endIndex
        while let range = output.range(of: pattern, options: .regularExpression, range: searchRange) {
            found.insert(output[range].uppercased())
            searchRange = range.upperBound..<output.endIndex
        }
        return found
    }
}

// MARK: - Fresh Account Profile

/// What the verification step checks the account against.
nonisolated struct HomeState: Sendable, Equatable {
    var exists: Bool
    var mode: Int?
    var groupID: Int?
    var hasDenyDeleteACL: Bool

    /// A stock macOS home: `drwxr-xr-x+` with `group:everyone deny delete`, group `staff`.
    static let freshMode = 0o755
    static let freshACL = "group:everyone deny delete"
}

nonisolated struct Finding: Sendable, Equatable {
    let message: String
}

nonisolated enum FreshAccountProfile {
    static func findings(
        snapshot: AccountSnapshot,
        machineBound: Bool,
        home: HomeState?,
        adminNestedGroups: [String],
        staffMembers: [String],
        userName: String
    ) -> [Finding] {
        var findings: [Finding] = []
        func add(_ message: String) { findings.append(Finding(message: message)) }

        if machineBound { add("This Mac is still bound to Active Directory.") }
        if !snapshot.adAuthorityEntries.isEmpty {
            add("AuthenticationAuthority still has AD entries (\(snapshot.adAuthorityEntries.count)).")
        }
        if !snapshot.adAttributeKeys.isEmpty {
            add("AD attributes remain: \(snapshot.adAttributeKeys.joined(separator: ", ")).")
        }
        if !snapshot.adAltIdentities.isEmpty { add("AltSecurityIdentities still has AD Kerberos principals.") }
        if !snapshot.domainRecordNames.isEmpty {
            add("RecordName still has domain aliases: \(snapshot.domainRecordNames.joined(separator: ", ")).")
        }
        if let gid = snapshot.primaryGroupID, gid != AccountSnapshot.freshPrimaryGroupID {
            add("PrimaryGroupID is \(gid), a fresh account uses \(AccountSnapshot.freshPrimaryGroupID).")
        }
        if !snapshot.extraPolicyKeys.isEmpty {
            add("Account policy still has AD rules: \(snapshot.extraPolicyKeys.joined(separator: ", ")).")
        }
        if !adminNestedGroups.isEmpty { add("The admin group still has nested (AD) groups.") }
        if staffMembers.contains(userName) {
            add("The user is listed in the staff group; on a fresh account only root is.")
        }
        if let home, home.exists {
            if let mode = home.mode, mode != HomeState.freshMode {
                add("Home folder mode is \(String(mode, radix: 8)), a fresh account uses \(String(HomeState.freshMode, radix: 8)).")
            }
            if !home.hasDenyDeleteACL { add("Home folder is missing the standard 'everyone deny delete' ACL.") }
            if let gid = home.groupID, gid != AccountSnapshot.freshPrimaryGroupID {
                add("Home folder group is \(gid), a fresh account uses staff (\(AccountSnapshot.freshPrimaryGroupID)).")
            }
        }
        return findings
    }
}

// MARK: - Step Planning

nonisolated enum FailurePolicy: Sendable {
    /// A failure stops the run.
    case critical
    /// A failure is shown as a warning and the run continues.
    case warnOnFailure
}

nonisolated enum StepAction: Sendable, Equatable {
    case verifyUserExists
    case backupAccount
    case unbindMachine
    case cleanSearchPaths
    case fixAuthenticationAuthority
    case removeADAttributes
    case removeADAltIdentities
    case removeDomainRecordNames
    case clearAccountPolicies
    case destroyKerberosTickets
    case removeStaffMembership
    case fixHomeOwnership
    case fixHomeContentGroups
    case fixHomePermissions
    case resetPrimaryGroup
    case restartDirectoryServices
    case verifyAccount

    var title: String {
        switch self {
        case .verifyUserExists: "Verify User Account"
        case .backupAccount: "Back Up Account Record"
        case .unbindMachine: "Unbind from Active Directory"
        case .cleanSearchPaths: "Remove AD from Search Paths"
        case .fixAuthenticationAuthority: "Remove AD Authentication Entries"
        case .removeADAttributes: "Remove AD Attributes"
        case .removeADAltIdentities: "Remove AD Kerberos Identities"
        case .removeDomainRecordNames: "Remove Domain Aliases"
        case .clearAccountPolicies: "Clear AD Password Policies"
        case .destroyKerberosTickets: "Destroy Kerberos Tickets"
        case .removeStaffMembership: "Remove Explicit Staff Membership"
        case .fixHomeOwnership: "Reset Home Folder Ownership"
        case .fixHomeContentGroups: "Reset Group on Home Contents"
        case .fixHomePermissions: "Reset Home Folder Permissions"
        case .resetPrimaryGroup: "Reset Primary Group to Staff"
        case .restartDirectoryServices: "Restart Directory Services"
        case .verifyAccount: "Verify Against a Fresh Local Account"
        }
    }

    /// Only steps that guard the user's ability to log in, or the ability to undo, stop the run.
    var policy: FailurePolicy {
        switch self {
        case .verifyUserExists, .backupAccount, .fixAuthenticationAuthority, .verifyAccount: .critical
        default: .warnOnFailure
        }
    }
}

nonisolated enum StepPlanner {
    /// Builds only the steps this machine and account need. An empty plan means nothing to do.
    static func plan(
        snapshot: AccountSnapshot,
        machineBound: Bool,
        home: HomeState?,
        adminNestedGroups: [String],
        staffMembers: [String],
        userName: String
    ) -> [StepAction] {
        let traces = FreshAccountProfile.findings(
            snapshot: snapshot, machineBound: machineBound, home: home,
            adminNestedGroups: adminNestedGroups, staffMembers: staffMembers, userName: userName
        )
        guard !traces.isEmpty else { return [] }

        var steps: [StepAction] = [.verifyUserExists, .backupAccount]
        if machineBound { steps += [.unbindMachine, .cleanSearchPaths] }

        let isMobile = snapshot.isMobileAccount
        if isMobile { steps.append(.fixAuthenticationAuthority) }
        if !snapshot.adAttributeKeys.isEmpty { steps.append(.removeADAttributes) }
        if !snapshot.adAltIdentities.isEmpty { steps.append(.removeADAltIdentities) }
        if !snapshot.domainRecordNames.isEmpty { steps.append(.removeDomainRecordNames) }
        if !snapshot.extraPolicyKeys.isEmpty { steps.append(.clearAccountPolicies) }
        if isMobile { steps.append(.destroyKerberosTickets) }
        if staffMembers.contains(userName) { steps.append(.removeStaffMembership) }

        let originalGroup = snapshot.primaryGroupID ?? AccountSnapshot.freshPrimaryGroupID
        let groupIsWrong = originalGroup != AccountSnapshot.freshPrimaryGroupID
        if let home, home.exists {
            if isMobile || groupIsWrong || home.groupID != AccountSnapshot.freshPrimaryGroupID {
                steps.append(.fixHomeOwnership)
            }
            if groupIsWrong { steps.append(.fixHomeContentGroups) }
            if home.mode != HomeState.freshMode || !home.hasDenyDeleteACL { steps.append(.fixHomePermissions) }
        }
        if groupIsWrong { steps.append(.resetPrimaryGroup) }

        steps += [.restartDirectoryServices, .verifyAccount]
        return steps
    }
}
