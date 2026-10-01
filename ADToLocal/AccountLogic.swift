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

/// The search paths (`dscl /Search -read . CSPSearchPath`) of a Mac that was bound to AD.
nonisolated enum SearchPathFilter {
    static func isActiveDirectory(_ path: String) -> Bool { path.contains("Active Directory") }
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
    /// `AppleMetaRecordName` holds the AD distinguished name on a mobile account; a fresh one has none.
    /// Deliberately NOT here (a fresh account can legitimately have them):
    /// `AltSecurityIdentities` (value-filtered), `accountPolicyData` (cleared with pwpolicy),
    /// `_writers_LinkedIdentity` (Apple Account), and `AppleMetaNodeLocation`.
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
        "EMailAddress",
        "AppleMetaRecordName"
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
    static let freshShell = "/bin/zsh"
    /// A fresh account has `_writers_<name>` for each, so the user can change their own picture,
    /// input sources and unlock options. A mobile account doesn't. Permissions only, no data.
    static let writerAttributes = ["AvatarRepresentation", "inputSources", "unlockOptions"]

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

    /// The shell AD assigned: `UserShell` still equals `original_shell` and isn't the fresh one.
    /// A shell the user picked later is kept (nil).
    var adAssignedShell: String? {
        guard let shell = values("UserShell").first, let original = values("original_shell").first,
              shell == original, shell != Self.freshShell else { return nil }
        return shell
    }

    /// The `writerAttributes` without a `_writers_` key.
    var missingWriters: [String] {
        Self.writerAttributes.filter { attributes["dsAttrTypeNative:_writers_" + $0] == nil }
    }

    /// `accountPolicyData` as a dictionary. A mobile account stores it as a binary plist, which
    /// `dscl -plist` (as root) prints as hex text ("62706c69 73743030 ..."); a fresh one as XML.
    var accountPolicy: [String: Any]? {
        guard let value = values("accountPolicyData").first else { return nil }
        let data = Self.hexData(value) ?? Data(value.utf8)
        return (try? PropertyListSerialization.propertyList(from: data, format: nil)) as? [String: Any]
    }

    /// Keys in `accountPolicyData` that a fresh account doesn't have (AD-imposed password rules).
    var extraPolicyKeys: [String] {
        (accountPolicy ?? [:]).keys.filter { !Self.allowedPolicyKeys.contains($0) }.sorted()
    }

    /// The policy with only the keys a fresh account has, as XML (how a fresh account stores it).
    /// Nil when there is no policy or nothing to remove.
    var freshPolicyXML: String? {
        guard let policy = accountPolicy, !extraPolicyKeys.isEmpty else { return nil }
        let kept = policy.filter { Self.allowedPolicyKeys.contains($0.key) }
        guard let data = try? PropertyListSerialization.data(fromPropertyList: kept, format: .xml, options: 0) else { return nil }
        return String(decoding: data, as: UTF8.self)
    }

    /// Decodes dscl's hex text for a data value: groups of 8 hex digits (the last can be shorter).
    static func hexData(_ text: String) -> Data? {
        guard text.range(of: "^[0-9a-fA-F]{8}( [0-9a-fA-F]{2,8})*$", options: .regularExpression) != nil else { return nil }
        let digits = Array(text.replacingOccurrences(of: " ", with: "").utf8)
        guard digits.count.isMultiple(of: 2) else { return nil }
        var bytes: [UInt8] = []
        bytes.reserveCapacity(digits.count / 2)
        for index in stride(from: 0, to: digits.count, by: 2) {
            guard let byte = UInt8(String(decoding: digits[index...index + 1], as: UTF8.self), radix: 16) else { return nil }
            bytes.append(byte)
        }
        return Data(bytes)
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
    /// The ACL is exactly the stock entry, with nothing else (such as an old domain ACL).
    var hasStockACL: Bool
    /// The mode of `~/.CFUserTextEncoding`, nil when there is none.
    var textEncodingMode: Int? = nil
    /// Items whose group no longer resolves. After the unbind that is every AD group.
    var unresolvedGroupItems = 0

    /// A stock macOS 27 home: `drwxr-x---+` with `group:everyone deny delete`, group `staff`.
    static let freshMode = 0o750
    static let freshACL = "group:everyone deny delete"
    static let publicMode = 0o755
    /// A fresh account's `~/.CFUserTextEncoding`. A mobile account's is 400.
    static let freshTextEncodingMode = 0o600

    /// Accounts made on older macOS have a 755 home folder, which is stock as well and left alone.
    static func isStockMode(_ mode: Int?) -> Bool {
        mode == freshMode || mode == 0o755
    }

    var hasStockTextEncodingMode: Bool {
        textEncodingMode.map { $0 == Self.freshTextEncodingMode } ?? true
    }

    /// The `find` expression for items to move to staff: every group that no longer resolves, plus
    /// the old AD primary group (which still resolves while the Mac is bound).
    static func regroupExpression(originalGroupID: Int?) -> [String] {
        guard let original = originalGroupID, original != AccountSnapshot.freshPrimaryGroupID else { return ["-nogroup"] }
        return ["(", "-gid", String(original), "-o", "-nogroup", ")"]
    }

    /// `listing` is `ls -lde <home>`; ACL entries print as " 0: group:everyone deny delete".
    static func isStockACL(listing: String) -> Bool {
        let entries = listing.split(separator: "\n").filter {
            $0.range(of: #"^\s*\d+:\s"#, options: .regularExpression) != nil
        }
        return entries.count == 1 && entries[0].contains(freshACL)
    }
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
        userName: String,
        searchPaths: [String] = []
    ) -> [Finding] {
        var findings: [Finding] = []
        func add(_ message: String) { findings.append(Finding(message: message)) }

        if machineBound { add("This Mac is still bound to Active Directory.") }
        if searchPaths.contains(where: SearchPathFilter.isActiveDirectory) {
            add("Active Directory is still in the search path.")
        }
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
        if let shell = snapshot.adAssignedShell {
            add("UserShell is \(shell) (set by AD), a fresh account uses \(AccountSnapshot.freshShell).")
        }
        for name in snapshot.missingWriters {
            add("The record has no _writers_\(name); on a fresh account the user can change \(name).")
        }
        if !snapshot.extraPolicyKeys.isEmpty {
            add("Account policy still has AD rules: \(snapshot.extraPolicyKeys.joined(separator: ", ")).")
        }
        if !adminNestedGroups.isEmpty { add("The admin group still has nested (AD) groups.") }
        if staffMembers.contains(userName) {
            add("The user is listed in the staff group; on a fresh account only root is.")
        }
        if let home, home.exists {
            if let mode = home.mode, !HomeState.isStockMode(mode) {
                add("Home folder mode is \(String(mode, radix: 8)), a fresh account uses \(String(HomeState.freshMode, radix: 8)).")
            }
            if !home.hasStockACL { add("Home folder ACL isn't just the standard 'everyone deny delete' entry.") }
            if let gid = home.groupID, gid != AccountSnapshot.freshPrimaryGroupID {
                add("Home folder group is \(gid), a fresh account uses staff (\(AccountSnapshot.freshPrimaryGroupID)).")
            }
            if home.unresolvedGroupItems > 0 {
                add("\(home.unresolvedGroupItems) item(s) in the home folder still have an AD group.")
            }
            if let mode = home.textEncodingMode, !home.hasStockTextEncodingMode {
                add(".CFUserTextEncoding mode is \(String(mode, radix: 8)), a fresh account uses \(String(HomeState.freshTextEncodingMode, radix: 8)).")
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
    case grantAdmin
    case resetPrimaryGroup
    case resetShell
    case addWriterPermissions
    case restartDirectoryServices
    case fixHomeOwnership
    case fixHomeContentGroups
    case fixHomePermissions
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
        case .grantAdmin: "Grant Admin Rights"
        case .resetPrimaryGroup: "Reset Primary Group to Staff"
        case .resetShell: "Reset Shell to zsh"
        case .addWriterPermissions: "Let the User Edit Their Own Settings"
        case .restartDirectoryServices: "Restart Directory Services"
        case .fixHomeOwnership: "Reset Home Folder Ownership"
        case .fixHomeContentGroups: "Reset Group on Home Contents"
        case .fixHomePermissions: "Reset Home Folder Permissions"
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
        userName: String,
        grantAdmin: Bool = false,
        adminMembers: [String] = [],
        searchPaths: [String] = []
    ) -> [StepAction] {
        let traces = FreshAccountProfile.findings(
            snapshot: snapshot, machineBound: machineBound, home: home,
            adminNestedGroups: adminNestedGroups, staffMembers: staffMembers, userName: userName,
            searchPaths: searchPaths
        )
        guard !traces.isEmpty else { return [] }

        var steps: [StepAction] = [.verifyUserExists, .backupAccount]
        if machineBound { steps.append(.unbindMachine) }
        // Also when another tool already unbound the Mac and left AD in the search path.
        if machineBound || searchPaths.contains(where: SearchPathFilter.isActiveDirectory) { steps.append(.cleanSearchPaths) }

        let isMobile = snapshot.isMobileAccount
        if isMobile { steps.append(.fixAuthenticationAuthority) }
        if !snapshot.adAttributeKeys.isEmpty { steps.append(.removeADAttributes) }
        if !snapshot.adAltIdentities.isEmpty { steps.append(.removeADAltIdentities) }
        if !snapshot.domainRecordNames.isEmpty { steps.append(.removeDomainRecordNames) }
        if !snapshot.extraPolicyKeys.isEmpty { steps.append(.clearAccountPolicies) }
        if isMobile { steps.append(.destroyKerberosTickets) }
        if staffMembers.contains(userName) { steps.append(.removeStaffMembership) }
        // Opt-in (the grantAdmin preference). A fresh local account isn't an admin unless asked to be.
        if grantAdmin, !adminMembers.contains(userName) { steps.append(.grantAdmin) }

        let originalGroup = snapshot.primaryGroupID ?? AccountSnapshot.freshPrimaryGroupID
        let groupIsWrong = originalGroup != AccountSnapshot.freshPrimaryGroupID
        if groupIsWrong { steps.append(.resetPrimaryGroup) }
        if snapshot.adAssignedShell != nil { steps.append(.resetShell) }
        if !snapshot.missingWriters.isEmpty { steps.append(.addWriterPermissions) }

        // Record changes are done. Restart first so the AD groups no longer resolve, then fix the files.
        steps.append(.restartDirectoryServices)
        if let home, home.exists {
            if isMobile || groupIsWrong || home.groupID != AccountSnapshot.freshPrimaryGroupID {
                steps.append(.fixHomeOwnership)
            }
            // While bound, AD groups other than the primary one still resolve, so they only show up
            // after the unbind. Also runs on an account converted earlier.
            if isMobile || groupIsWrong || home.unresolvedGroupItems > 0 {
                steps.append(.fixHomeContentGroups)
            }
            if !HomeState.isStockMode(home.mode) || !home.hasStockACL || !home.hasStockTextEncodingMode {
                steps.append(.fixHomePermissions)
            }
        }
        steps.append(.verifyAccount)
        return steps
    }
}
