import Foundation
import Testing
@testable import DecoupleLogic

// Fixtures mirror what `dscl -plist . -read /Users/<name>` returns on macOS 14+.
// GUIDs and hashes are made up.
private let lkdc = ";Kerberosv5;;jdoe@LKDC:SHA1.AAAA;LKDC:SHA1.AAAA;"
private let shadow = ";ShadowHash;HASHLIST:<SALTED-SHA512-PBKDF2>"
private let secureToken = ";SecureToken;"
private let adKerberos = ";Kerberosv5;;jdoe@CORP.EXAMPLE.COM;CORP.EXAMPLE.COM;"
private let cachedUser = ";LocalCachedUser;/Active Directory/CORP/corp.example.com:jdoe:11111111-2222-3333-4444-555555555555"

private func plist(_ dictionary: [String: [String]]) throws -> Data {
    try PropertyListSerialization.data(fromPropertyList: dictionary, format: .xml, options: 0)
}

private func snapshot(_ dictionary: [String: [String]]) throws -> AccountSnapshot {
    try #require(AccountSnapshot(plistData: try plist(dictionary)))
}

private let freshLocal: [String: [String]] = [
    "dsAttrTypeStandard:RecordName": ["jdoe"],
    "dsAttrTypeStandard:UniqueID": ["503"],
    "dsAttrTypeStandard:PrimaryGroupID": ["20"],
    "dsAttrTypeStandard:GeneratedUID": ["9CBD8180-82AE-414C-8D00-2401A5B92916"],
    "dsAttrTypeStandard:NFSHomeDirectory": ["/Users/jdoe"],
    "dsAttrTypeStandard:UserShell": ["/bin/zsh"],
    "dsAttrTypeStandard:AuthenticationAuthority": [shadow, lkdc, secureToken],
    "dsAttrTypeStandard:AltSecurityIdentities": ["X509:<T>CN=Apple Root CA<S>CN=com.apple.idms.appleid.prd.1"],
    "dsAttrTypeNative:_writers_AvatarRepresentation": ["jdoe"],
    "dsAttrTypeNative:_writers_inputSources": ["jdoe"],
    "dsAttrTypeNative:_writers_unlockOptions": ["jdoe"]
]

private let cleanHome = HomeState(exists: true, mode: 0o750, groupID: 20, hasStockACL: true)

private func findings(
    _ snapshot: AccountSnapshot,
    bound: Bool = false,
    home: HomeState? = cleanHome,
    nested: [String] = [],
    staff: [String] = ["root"],
    searchPaths: [String] = []
) -> [Finding] {
    FreshAccountProfile.findings(
        snapshot: snapshot, machineBound: bound, home: home,
        adminNestedGroups: nested, staffMembers: staff, userName: "jdoe", searchPaths: searchPaths
    )
}

// MARK: - Validation

@Suite struct ValidationTests {
    @Test(arguments: ["jdoe", "john.doe", "j_doe-2", "A1"])
    func acceptsShortNames(name: String) {
        #expect(UsernameValidator.isValid(name))
    }

    @Test(arguments: ["", "-rf", "a b", "a;rm -rf /", "$(id)", "a`id`", "a/b", "a\"b", "é", "a\nb"])
    func rejectsUnsafeNames(name: String) {
        #expect(!UsernameValidator.isValid(name))
    }

    @Test func rejectsOverlongNames() {
        #expect(!UsernameValidator.isValid(String(repeating: "a", count: 65)))
    }

    @Test func homeMustBelongToTheUser() {
        #expect(HomeDirectoryValidator.isSafe("/Users/jdoe", forUser: "jdoe"))
        #expect(HomeDirectoryValidator.isSafe("/Users/JDoe", forUser: "jdoe"))
        #expect(!HomeDirectoryValidator.isSafe("/Users/other", forUser: "jdoe"))
        #expect(!HomeDirectoryValidator.isSafe("/", forUser: "jdoe"))
        #expect(!HomeDirectoryValidator.isSafe("/Users", forUser: "jdoe"))
        #expect(!HomeDirectoryValidator.isSafe("/Users/../jdoe", forUser: "jdoe"))
        #expect(!HomeDirectoryValidator.isSafe("Users/jdoe", forUser: "jdoe"))
        #expect(!HomeDirectoryValidator.isSafe("/jdoe", forUser: "jdoe"))
    }
}

// MARK: - AuthenticationAuthority

@Suite struct AuthorityTests {
    @Test func removesOnlyActiveDirectoryEntries() {
        let all = [shadow, lkdc, secureToken, adKerberos, cachedUser]
        #expect(AuthorityFilter.entriesToRemove(from: all) == [adKerberos, cachedUser])
    }

    @Test func neverTouchesAFreshAccount() {
        #expect(AuthorityFilter.entriesToRemove(from: [shadow, lkdc, secureToken]).isEmpty)
    }

    /// The first Kerberosv5 entry can be the local one. It must survive.
    @Test func keepsLKDCEvenWhenListedFirst() {
        #expect(AuthorityFilter.entriesToRemove(from: [lkdc, adKerberos]) == [adKerberos])
    }

    @Test func protectedEntriesWinOverADMatches() {
        let odd = ";ShadowHash;HASHLIST:<X> Active Directory"
        #expect(AuthorityFilter.isProtected(odd))
        #expect(!AuthorityFilter.isActiveDirectory(odd))
    }

    @Test func netLogonIsRemoved() {
        #expect(AuthorityFilter.isActiveDirectory(";NetLogon;jdoe;CORP"))
    }

    @Test func altIdentitiesKeepAppleAndLocalValues() {
        #expect(!AltIdentityFilter.isActiveDirectory("X509:<T>CN=Apple Root CA<S>CN=x"))
        #expect(!AltIdentityFilter.isActiveDirectory("Kerberos:jdoe@LKDC:SHA1.AAAA"))
        #expect(AltIdentityFilter.isActiveDirectory("Kerberos:jdoe@CORP.EXAMPLE.COM"))
    }

    @Test func recordNameAliases() {
        #expect(RecordNameFilter.isDomainAlias("jdoe@corp.example.com"))
        #expect(!RecordNameFilter.isDomainAlias("jdoe"))
        #expect(!RecordNameFilter.isDomainAlias("com.apple.idms.appleid.prd.000716-08-0ca2476f"))
    }
}

// MARK: - Attributes

@Suite struct AttributeTests {
    @Test func matchesStandardAndNativeKeys() {
        let keys = [
            "dsAttrTypeStandard:RecordName",
            "dsAttrTypeStandard:CachedGroups",
            "dsAttrTypeStandard:SMBSID",
            "dsAttrTypeStandard:AppleMetaRecordName",
            "dsAttrTypeNative:cached_groups",
            "dsAttrTypeNative:accountPolicyData",
            "dsAttrTypeStandard:AltSecurityIdentities",
            "dsAttrTypeStandard:FirstName"
        ]
        #expect(ADAttributes.keysToRemove(from: keys) == [
            "dsAttrTypeNative:cached_groups",
            "dsAttrTypeStandard:AppleMetaRecordName",
            "dsAttrTypeStandard:CachedGroups",
            "dsAttrTypeStandard:FirstName",
            "dsAttrTypeStandard:SMBSID"
        ])
    }

    @Test func neverListsAttributesAFreshAccountOwns() {
        let protected = ["AuthenticationAuthority", "GeneratedUID", "Password", "AltSecurityIdentities",
                         "accountPolicyData", "UniqueID", "PrimaryGroupID", "RealName", "RecordName",
                         "UserShell", "AppleMetaNodeLocation"]
        let names = Set(ADAttributes.names.map(ADAttributes.normalized))
        for name in protected {
            #expect(!names.contains(ADAttributes.normalized(name)), "\(name) must not be deleted")
        }
    }
}

// MARK: - Snapshot

@Suite struct SnapshotTests {
    @Test func freshAccountHasNoTraces() throws {
        let account = try snapshot(freshLocal)
        #expect(!account.isMobileAccount)
        #expect(account.adAttributeKeys.isEmpty)
        #expect(account.hasSecureToken)
        #expect(account.uniqueID == 503)
        #expect(findings(account).isEmpty)
    }

    @Test func mobileAccountIsDetectedAndFullyReported() throws {
        var mobile = freshLocal
        mobile["dsAttrTypeStandard:AuthenticationAuthority"] = [shadow, adKerberos, lkdc, cachedUser, secureToken]
        mobile["dsAttrTypeStandard:RecordName"] = ["jdoe", "jdoe@corp.example.com"]
        mobile["dsAttrTypeStandard:PrimaryGroupID"] = ["12"]
        mobile["dsAttrTypeStandard:CachedGroups"] = ["g"]
        mobile["dsAttrTypeStandard:SMBSID"] = ["S-1-5-21"]
        mobile["dsAttrTypeStandard:AltSecurityIdentities"] = ["Kerberos:jdoe@CORP.EXAMPLE.COM", "X509:<T>Apple"]
        let account = try snapshot(mobile)
        #expect(account.isMobileAccount)
        #expect(account.adAuthorityEntries == [adKerberos, cachedUser])
        #expect(account.adAltIdentities == ["Kerberos:jdoe@CORP.EXAMPLE.COM"])
        #expect(account.domainRecordNames == ["jdoe@corp.example.com"])
        #expect(account.adAttributeKeys == ["dsAttrTypeStandard:CachedGroups", "dsAttrTypeStandard:SMBSID"])
        // bound, authority, attributes, alt identities, record names, primary group
        #expect(findings(account, bound: true).count == 6)
    }

    @Test func halfMigratedAccountIsNotReportedClean() throws {
        var partial = freshLocal
        partial["dsAttrTypeStandard:SMBSID"] = ["S-1-5-21"]
        let account = try snapshot(partial)
        #expect(!account.isMobileAccount)
        #expect(!findings(account).isEmpty)
    }

    @Test func policyDataWithADRulesIsFlagged() throws {
        let policy = """
        <?xml version="1.0" encoding="UTF-8"?>
        <plist version="1.0"><dict>
        <key>creationTime</key><real>1.0</real>
        <key>passwordLastSetTime</key><real>2.0</real>
        <key>maxMinutesUntilChangePassword</key><integer>129600</integer>
        </dict></plist>
        """
        var withPolicy = freshLocal
        withPolicy["dsAttrTypeNative:accountPolicyData"] = [policy]
        #expect(try snapshot(withPolicy).extraPolicyKeys == ["maxMinutesUntilChangePassword"])

        var freshPolicy = freshLocal
        freshPolicy["dsAttrTypeNative:accountPolicyData"] = [
            "<plist version=\"1.0\"><dict><key>creationTime</key><real>1.0</real></dict></plist>"
        ]
        #expect(try snapshot(freshPolicy).extraPolicyKeys.isEmpty)
    }

    @Test func rejectsNonPlistOutput() {
        #expect(AccountSnapshot(plistData: Data("<dscl_cmd> DS Error: eDSRecordNotFound".utf8)) == nil)
    }

    @Test func backupNeverContainsPasswordHashData() throws {
        var withHash = freshLocal
        withHash["dsAttrTypeNative:ShadowHashData"] = ["secret-bytes"]
        let data = try snapshot(withHash).backupPlistData(extra: ["boundToAD": "false"])
        let text = String(decoding: data, as: UTF8.self)
        #expect(!text.contains("secret-bytes"))
        #expect(text.contains("GeneratedUID"))
        #expect(text.contains("boundToAD"))
    }
}

// MARK: - Home and groups

@Suite struct HomeAndGroupTests {
    @Test func flagsWrongHomeModeAclAndGroup() throws {
        let account = try snapshot(freshLocal)
        // 750 is now the stock mode; use 700 to actually be wrong.
        let bad = HomeState(exists: true, mode: 0o700, groupID: 12345, hasStockACL: false)
        #expect(findings(account, home: bad).count == 3)
    }

    @Test func missingHomeIsNotAFinding() throws {
        let account = try snapshot(freshLocal)
        #expect(findings(account, home: HomeState(exists: false, mode: nil, groupID: nil, hasStockACL: false)).isEmpty)
    }

    @Test func staffMembershipAndNestedGroupsAreFlagged() throws {
        let account = try snapshot(freshLocal)
        #expect(findings(account, nested: ["ABC"], staff: ["root", "jdoe"]).count == 2)
    }
}

// MARK: - FileVault

@Suite struct FileVaultTests {
    @Test func parsesStatus() {
        #expect(FileVaultParser.isEnabled(fdesetupStatus: "FileVault is On."))
        #expect(!FileVaultParser.isEnabled(fdesetupStatus: "FileVault is Off."))
    }

    @Test func parsesCryptoUsers() {
        let output = """
        Cryptographic Users for disk3s5 (2 found)
        |
        +-- 9CBD8180-82AE-414C-8D00-2401A5B92916
        |   Type: Local Open Directory User
        +-- ebc6c064-2f3d-4cb8-9a57-9d6f1f1b3a10
            Type: iCloud Recovery Key
        """
        #expect(FileVaultParser.cryptoUserUUIDs(from: output) == [
            "9CBD8180-82AE-414C-8D00-2401A5B92916",
            "EBC6C064-2F3D-4CB8-9A57-9D6F1F1B3A10"
        ])
    }
}

// MARK: - Planning

@Suite struct PlannerTests {
    private func plan(
        _ dictionary: [String: [String]], bound: Bool = false, home: HomeState? = cleanHome,
        staff: [String] = ["root"]
    ) throws -> [StepAction] {
        StepPlanner.plan(
            snapshot: try snapshot(dictionary), machineBound: bound, home: home,
            adminNestedGroups: [], staffMembers: staff, userName: "jdoe"
        )
    }

    @Test func freshLocalAccountNeedsNothing() throws {
        #expect(try plan(freshLocal).isEmpty)
    }

    @Test func fullMobileMigrationOrder() throws {
        var mobile = freshLocal
        mobile["dsAttrTypeStandard:AuthenticationAuthority"] = [shadow, adKerberos, lkdc, cachedUser, secureToken]
        mobile["dsAttrTypeStandard:PrimaryGroupID"] = ["12"]
        mobile["dsAttrTypeStandard:SMBSID"] = ["S-1-5-21"]
        let bad = HomeState(exists: true, mode: 0o700, groupID: 12, hasStockACL: false)
        #expect(try plan(mobile, bound: true, home: bad) == [
            .verifyUserExists, .backupAccount, .unbindMachine, .cleanSearchPaths,
            .fixAuthenticationAuthority, .removeADAttributes, .destroyKerberosTickets,
            .resetPrimaryGroup,
            .restartDirectoryServices,
            .fixHomeOwnership, .fixHomeContentGroups, .fixHomePermissions,
            .verifyAccount
        ])
    }

    @Test func backupAlwaysPrecedesAnyChange() throws {
        var mobile = freshLocal
        mobile["dsAttrTypeStandard:AuthenticationAuthority"] = [shadow, adKerberos]
        let steps = try plan(mobile)
        #expect(steps.prefix(2) == [.verifyUserExists, .backupAccount])
    }

    @Test func boundMachineWithLocalUserOnlyUnbinds() throws {
        let steps = try plan(freshLocal, bound: true)
        #expect(steps == [.verifyUserExists, .backupAccount, .unbindMachine, .cleanSearchPaths,
                          .restartDirectoryServices, .verifyAccount])
    }

    @Test func staffMembershipFromAnEarlierVersionIsRemoved() throws {
        #expect(try plan(freshLocal, staff: ["root", "jdoe"]).contains(.removeStaffMembership))
    }

    @Test func missingHomeSkipsHomeSteps() throws {
        var mobile = freshLocal
        mobile["dsAttrTypeStandard:AuthenticationAuthority"] = [shadow, adKerberos]
        let steps = try plan(mobile, home: HomeState(exists: false, mode: nil, groupID: nil, hasStockACL: false))
        #expect(!steps.contains(.fixHomeOwnership) && !steps.contains(.fixHomePermissions))
    }

    @Test func onlyIrreversibleGuardsAreCritical() {
        #expect(StepAction.backupAccount.policy == .critical)
        #expect(StepAction.fixAuthenticationAuthority.policy == .critical)
        #expect(StepAction.fixHomeContentGroups.policy == .warnOnFailure)
        #expect(StepAction.unbindMachine.policy == .warnOnFailure)
    }
}

// MARK: - swiftDialog commands

@Suite struct DialogCommandTests {
    @Test func formatsListItemUpdates() {
        #expect(DialogCommands.listItem(index: 2, status: .success, text: "Done")
                == "listitem: index: 2, status: success, statustext: Done")
    }

    /// Text is untrusted (command output). It must not add a field, a line, or a command.
    @Test func sanitizingKeepsTextOnOneLineWithoutSeparators() {
        let line = DialogCommands.listItem(index: 0, status: .fail, text: "bad, status: success\nquit:")
        #expect(!line.contains("\n"))
        #expect(line.components(separatedBy: ",").count == 3)   // index, status, statustext only
        #expect(DialogCommands.sanitize("a\r\nb") == "a  b")
    }

    @Test func longTextIsTruncated() {
        #expect(DialogCommands.sanitize(String(repeating: "x", count: 500)).count == 140)
    }

    @Test func messageEncodesLineBreaks() {
        #expect(DialogCommands.message("one\ntwo") == "message: one\\ntwo")
    }

    @Test func launchArgumentsListEveryStep() {
        let args = DialogCommands.launchArguments(title: "T", message: "M", items: ["A", "B"], commandFile: "/tmp/x")
        #expect(args.filter { $0 == "--listitem" }.count == 2)
        #expect(args[args.firstIndex(of: "--progress")! + 1] == "2")
        #expect(args[args.firstIndex(of: "--commandfile")! + 1] == "/tmp/x")
    }
}

// MARK: - Stock ACL and admin option

@Suite struct HomeAclAndAdminTests {
    @Test func onlyTheStockAclCounts() {
        let stock = "drwxr-xr-x+ 72 jdoe  staff  2304 Sep 18 22:12 /Users/jdoe\n 0: group:everyone deny delete\n"
        #expect(HomeState.isStockACL(listing: stock))
        #expect(!HomeState.isStockACL(listing: "drwxr-xr-x  72 jdoe  staff  2304 Sep 18 22:12 /Users/jdoe\n"))
        // A leftover domain ACL next to the stock entry is not a fresh home.
        let stale = stock + " 1: group:11111111-2222-3333-4444-555555555555 allow list,search\n"
        #expect(!HomeState.isStockACL(listing: stale))
        #expect(!HomeState.isStockACL(listing: "drwxr-xr-x+ 1 a b 1 Jan 1 /x\n 0: user:x allow read\n"))
    }

    @Test func staleAclIsAFindingAndPlansAPermissionsFix() throws {
        let account = try snapshot(freshLocal)
        let staleHome = HomeState(exists: true, mode: 0o755, groupID: 20, hasStockACL: false)
        #expect(findings(account, home: staleHome).count == 1)
        let steps = StepPlanner.plan(snapshot: account, machineBound: false, home: staleHome, adminNestedGroups: [],
                                     staffMembers: ["root"], userName: "jdoe")
        #expect(steps == [.verifyUserExists, .backupAccount, .restartDirectoryServices, .fixHomePermissions, .verifyAccount])
    }

    private func mobilePlan(grantAdmin: Bool, admins: [String] = []) throws -> [StepAction] {
        var mobile = freshLocal
        mobile["dsAttrTypeStandard:AuthenticationAuthority"] = [shadow, adKerberos, lkdc, secureToken]
        return StepPlanner.plan(snapshot: try snapshot(mobile), machineBound: false, home: cleanHome, adminNestedGroups: [],
                                staffMembers: ["root"], userName: "jdoe", grantAdmin: grantAdmin, adminMembers: admins)
    }

    @Test func adminIsOffByDefault() throws {
        #expect(!(try mobilePlan(grantAdmin: false)).contains(.grantAdmin))
    }

    @Test func adminIsGrantedWhenAskedAndNotAlreadyAdmin() throws {
        #expect(try mobilePlan(grantAdmin: true).contains(.grantAdmin))
        #expect(!(try mobilePlan(grantAdmin: true, admins: ["root", "jdoe"])).contains(.grantAdmin))
    }

    /// The option applies to a conversion. A clean local account is left alone.
    @Test func adminAloneDoesNotStartAMigration() throws {
        let steps = StepPlanner.plan(snapshot: try snapshot(freshLocal), machineBound: false, home: cleanHome,
                                     adminNestedGroups: [], staffMembers: ["root"], userName: "jdoe",
                                     grantAdmin: true, adminMembers: ["root"])
        #expect(steps.isEmpty)
    }
}

// MARK: - Search paths

@Suite struct SearchPathTests {
    @Test func matchesAnyActiveDirectoryPath() {
        #expect(SearchPathFilter.isActiveDirectory("/Active Directory/All Domains"))
        #expect(SearchPathFilter.isActiveDirectory("/Active Directory/CORP/corp.example.com"))
        #expect(!SearchPathFilter.isActiveDirectory("/Local/Default"))
    }

    @Test func aLeftoverADSearchPathIsCleanedEvenWhenUnbound() throws {
        let account = try snapshot(freshLocal)
        let paths = ["/Local/Default", "/Active Directory/CORP/corp.example.com"]
        #expect(findings(account, searchPaths: paths).count == 1)
        let steps = StepPlanner.plan(snapshot: account, machineBound: false, home: cleanHome, adminNestedGroups: [],
                                     staffMembers: ["root"], userName: "jdoe", searchPaths: paths)
        #expect(steps == [.verifyUserExists, .backupAccount, .cleanSearchPaths, .restartDirectoryServices, .verifyAccount])
        // Not bound and nothing in the path: nothing to do.
        #expect(findings(account, searchPaths: ["/Local/Default"]).isEmpty)
    }
}

// MARK: - Shell, writers and binary policy (ported from the live test)

@Suite struct ShellAndWriterTests {
    @Test func adAssignedShellDetected() throws {
        var mobile = freshLocal
        mobile["dsAttrTypeStandard:UserShell"] = ["/bin/bash"]
        mobile["dsAttrTypeNative:original_shell"] = ["/bin/bash"]
        let account = try snapshot(mobile)
        #expect(account.adAssignedShell == "/bin/bash")
        #expect(findings(account).contains { $0.message.contains("UserShell") })
        #expect(try plan(mobile).contains(.resetShell))
    }

    @Test func shellTheUserPickedIsKept() throws {
        var mobile = freshLocal
        mobile["dsAttrTypeStandard:UserShell"] = ["/opt/homebrew/bin/fish"]
        mobile["dsAttrTypeNative:original_shell"] = ["/bin/bash"]
        #expect(try snapshot(mobile).adAssignedShell == nil)
    }

    @Test func missingWritersAreFlaggedAndAdded() throws {
        var mobile = freshLocal
        mobile.removeValue(forKey: "dsAttrTypeNative:_writers_AvatarRepresentation")
        mobile.removeValue(forKey: "dsAttrTypeNative:_writers_inputSources")
        let account = try snapshot(mobile)
        #expect(account.missingWriters == ["AvatarRepresentation", "inputSources"])
        #expect(findings(account).contains { $0.message.contains("_writers_AvatarRepresentation") })
        #expect(try plan(mobile).contains(.addWriterPermissions))
    }

    private func plan(_ dictionary: [String: [String]], bound: Bool = false, home: HomeState? = cleanHome,
                      staff: [String] = ["root"]) throws -> [StepAction] {
        StepPlanner.plan(snapshot: try snapshot(dictionary), machineBound: bound, home: home,
                        adminNestedGroups: [], staffMembers: staff, userName: "jdoe")
    }
}

// MARK: - Binary policy and fresh policy XML

@Suite struct BinaryPolicyTests {
    @Test func binaryPlistPolicyIsParsed() throws {
        let xml = """
        <?xml version="1.0" encoding="UTF-8"?>
        <plist version="1.0"><dict>
        <key>creationTime</key><real>1.0</real>
        <key>maxMinutesUntilChangePassword</key><integer>129600</integer>
        </dict></plist>
        """
        let binary = try PropertyListSerialization.data(fromPropertyList: 
            try PropertyListSerialization.propertyList(from: Data(xml.utf8), format: nil) as Any,
            format: .binary, options: 0)
        // dscl prints binary data as hex text in groups of 8 hex digits (the last can be shorter).
        let hexChars = binary.map { String(format: "%02x", $0) }.joined()
        var hex = ""
        for (i, ch) in hexChars.enumerated() {
            if i > 0 && i % 8 == 0 { hex += " " }
            hex.append(ch)
        }
        var record = freshLocal
        record["dsAttrTypeNative:accountPolicyData"] = [hex]
        let account = try snapshot(record)
        #expect(account.extraPolicyKeys == ["maxMinutesUntilChangePassword"])
        #expect(account.freshPolicyXML?.contains("creationTime") == true)
        #expect(account.freshPolicyXML?.contains("maxMinutesUntilChangePassword") == false)
    }

    @Test func hexDataDecodesGroupsOfEight() {
        let hex = "62706c69 73743030"
        let data = AccountSnapshot.hexData(hex)
        #expect(data != nil)
        #expect(data?.prefix(6) == Data("bplist".utf8))
        #expect(AccountSnapshot.hexData("not hex") == nil)
        #expect(AccountSnapshot.hexData("62706c") == nil)  // odd number of digits
    }
}

// MARK: - Home: .CFUserTextEncoding and -nogroup

@Suite struct HomeDetailTests {
    @Test func cfUserTextEncodingModeIsFlagged() throws {
        let account = try snapshot(freshLocal)
        let home = HomeState(exists: true, mode: 0o750, groupID: 20, hasStockACL: true, textEncodingMode: 0o400)
        #expect(findings(account, home: home).contains { $0.message.contains("CFUserTextEncoding") })
        #expect(StepPlanner.plan(snapshot: account, machineBound: false, home: home, adminNestedGroups: [],
                                staffMembers: ["root"], userName: "jdoe").contains(.fixHomePermissions))
    }

    @Test func unresolvedGroupItemsAreFlagged() throws {
        let account = try snapshot(freshLocal)
        let home = HomeState(exists: true, mode: 0o750, groupID: 20, hasStockACL: true, unresolvedGroupItems: 5)
        #expect(findings(account, home: home).contains { $0.message.contains("AD group") })
        let steps = StepPlanner.plan(snapshot: account, machineBound: false, home: home, adminNestedGroups: [],
                                    staffMembers: ["root"], userName: "jdoe")
        #expect(steps.contains(.fixHomeContentGroups))
    }

    @Test func regroupExpressionMatchesOldGroupAndNogroup() {
        #expect(HomeState.regroupExpression(originalGroupID: 12) == ["(", "-gid", "12", "-o", "-nogroup", ")"])
        #expect(HomeState.regroupExpression(originalGroupID: 20) == ["-nogroup"])
        #expect(HomeState.regroupExpression(originalGroupID: nil) == ["-nogroup"])
    }

    @Test func stockModeAccepts750And755() {
        #expect(HomeState.isStockMode(0o750))
        #expect(HomeState.isStockMode(0o755))
        #expect(!HomeState.isStockMode(0o700))
        #expect(!HomeState.isStockMode(0o775))
    }
}

// MARK: - AppleMetaRecordName

@Suite struct AppleMetaRecordNameTests {
    @Test func detectedAsADAttribute() throws {
        var mobile = freshLocal
        mobile["dsAttrTypeStandard:AppleMetaRecordName"] = ["CN=Test User,CN=Users,DC=corp,DC=example,DC=com"]
        let account = try snapshot(mobile)
        #expect(account.adAttributeKeys.contains("dsAttrTypeStandard:AppleMetaRecordName"))
        #expect(findings(account).contains { $0.message.contains("AppleMetaRecordName") })
        #expect(try snapshot(freshLocal).adAttributeKeys.isEmpty)
    }
}
