//
//  AccountOperations.swift
//  ADToLocal
//
//  Everything that reads or changes the system. All calls block, so run them off the main actor.
//  Decisions (what is AD, what to keep, which steps to run) live in AccountLogic.swift.
//

import Foundation

nonisolated enum AccountOperations {
    private enum Tool {
        static let dscl = "/usr/bin/dscl"
        static let dsconfigad = "/usr/sbin/dsconfigad"
        static let pwpolicy = "/usr/bin/pwpolicy"
        static let kdestroy = "/usr/bin/kdestroy"
        static let launchctl = "/bin/launchctl"
        static let chown = "/usr/sbin/chown"
        static let chmod = "/bin/chmod"
        static let chgrp = "/usr/bin/chgrp"
        static let find = "/usr/bin/find"
        static let killall = "/usr/bin/killall"
        static let dseditgroup = "/usr/sbin/dseditgroup"
        static let fdesetup = "/usr/bin/fdesetup"
        static let diskutil = "/usr/sbin/diskutil"
        static let ls = "/bin/ls"
        static let stat = "/usr/bin/stat"
    }

    // MARK: - Reading

    static func readSnapshot(user: String) -> AccountSnapshot? {
        readRecord("/Users/\(user)")
    }

    private static func readRecord(_ path: String, attribute: String? = nil) -> AccountSnapshot? {
        let arguments = ["-plist", ".", "-read", path] + (attribute.map { [$0] } ?? [])
        let result = CommandRunner.run(Tool.dscl, arguments)
        return result.succeeded ? AccountSnapshot(plistData: Data(result.output.utf8)) : nil
    }

    static func isMachineBound() -> Bool {
        CommandRunner.run(Tool.dsconfigad, ["-show"]).output.contains("Active Directory Domain")
    }

    static func homeState(_ path: String) -> HomeState {
        guard FileManager.default.fileExists(atPath: path) else {
            return HomeState(exists: false, mode: nil, groupID: nil, hasDenyDeleteACL: false)
        }
        // "%Lp %g" prints the octal permission bits and the numeric group, e.g. "755 20".
        let stat = CommandRunner.run(Tool.stat, ["-f", "%Lp %g", path]).output.split(separator: " ")
        let mode = stat.first.flatMap { Int($0, radix: 8) }
        let group = stat.dropFirst().first.flatMap { Int($0) }
        let listing = CommandRunner.run(Tool.ls, ["-lde", path]).output
        return HomeState(
            exists: true, mode: mode, groupID: group,
            hasDenyDeleteACL: listing.contains(HomeState.freshACL)
        )
    }

    private static func groupValues(_ group: String, _ attribute: String) -> [String] {
        readRecord("/Groups/\(group)", attribute: attribute)?.values(attribute) ?? []
    }

    private static func fileVaultEnabled() -> Bool {
        FileVaultParser.isEnabled(fdesetupStatus: CommandRunner.run(Tool.fdesetup, ["status"]).output)
    }

    private static func cryptoUsers() -> Set<String> {
        FileVaultParser.cryptoUserUUIDs(from: CommandRunner.run(Tool.diskutil, ["apfs", "listCryptoUsers", "/"]).output)
    }

    /// Reads the system and builds the plan. Returns nil if the account doesn't exist.
    static func analyze(user: String) -> SystemAnalysis? {
        guard let snapshot = readSnapshot(user: user) else { return nil }
        let bound = isMachineBound()
        let homePath = snapshot.homeDirectory ?? "/Users/\(user)"
        let home = homeState(homePath)
        let nested = groupValues("admin", "NestedGroups")
        let staff = groupValues("staff", "GroupMembership")
        let fileVault = fileVaultEnabled()

        let context = MigrationContext(
            user: user,
            uid: snapshot.uniqueID ?? -1,
            homeDirectory: homePath,
            originalPrimaryGroupID: snapshot.primaryGroupID,
            generatedUID: snapshot.generatedUID,
            hadSecureToken: snapshot.hasSecureToken,
            fileVaultEnabled: fileVault,
            cryptoUsersBefore: fileVault ? cryptoUsers() : []
        )
        return SystemAnalysis(
            snapshot: snapshot, machineBound: bound, home: home,
            adminNestedGroups: nested, staffMembers: staff, context: context,
            findings: FreshAccountProfile.findings(
                snapshot: snapshot, machineBound: bound, home: home,
                adminNestedGroups: nested, staffMembers: staff, userName: user
            ),
            plan: StepPlanner.plan(
                snapshot: snapshot, machineBound: bound, home: home,
                adminNestedGroups: nested, staffMembers: staff, userName: user
            )
        )
    }

    // MARK: - Executing

    static func execute(_ action: StepAction, context: MigrationContext) -> StepOutcome {
        AppLog.write("Step: \(action.title)")
        let outcome: StepOutcome
        switch action {
        case .verifyUserExists: outcome = verifyUserExists(context)
        case .backupAccount: outcome = backupAccount(context)
        case .unbindMachine: outcome = unbindMachine()
        case .cleanSearchPaths: outcome = cleanSearchPaths()
        case .fixAuthenticationAuthority: outcome = fixAuthenticationAuthority(context)
        case .removeADAttributes: outcome = removeADAttributes(context)
        case .removeADAltIdentities: outcome = removeValues(context, attribute: "AltSecurityIdentities") { $0.adAltIdentities }
        case .removeDomainRecordNames: outcome = removeValues(context, attribute: "RecordName") { $0.domainRecordNames }
        case .clearAccountPolicies: outcome = clearAccountPolicies(context)
        case .destroyKerberosTickets: outcome = destroyKerberosTickets(context)
        case .removeStaffMembership: outcome = removeStaffMembership(context)
        case .fixHomeOwnership: outcome = fixHomeOwnership(context)
        case .fixHomeContentGroups: outcome = fixHomeContentGroups(context)
        case .fixHomePermissions: outcome = fixHomePermissions(context)
        case .resetPrimaryGroup: outcome = resetPrimaryGroup(context)
        case .restartDirectoryServices: outcome = restartDirectoryServices()
        case .verifyAccount: outcome = verifyAccount(context)
        }
        AppLog.write("Result: \(outcome)")
        return outcome
    }

    private static func verifyUserExists(_ context: MigrationContext) -> StepOutcome {
        readSnapshot(user: context.user) != nil
            ? .success("Account found")
            : .failure("The account '\(context.user)' does not exist.")
    }

    /// Restore point, written before anything is changed. The password hash is never included.
    private static func backupAccount(_ context: MigrationContext) -> StepOutcome {
        guard let snapshot = readSnapshot(user: context.user) else { return .failure("Could not read the account record.") }
        let path = "/private/var/log/ad_to_local_backup_\(context.user)_\(Int(Date().timeIntervalSince1970)).plist"
        let extra = [
            "user": context.user,
            "createdAt": Date().formatted(.iso8601),
            "dsconfigad": CommandRunner.run(Tool.dsconfigad, ["-show"]).output
        ]
        do {
            let data = try snapshot.backupPlistData(extra: extra)
            guard FileManager.default.createFile(atPath: path, contents: data, attributes: [.posixPermissions: 0o600]) else {
                return .failure("Could not write the backup to \(path). Not running as root?")
            }
            return .success("Saved \((path as NSString).lastPathComponent)")
        } catch {
            return .failure("Could not create the backup: \(error.localizedDescription)")
        }
    }

    private static func unbindMachine() -> StepOutcome {
        let attempts = 3
        for attempt in 1...attempts {
            AppLog.write("Unbind attempt \(attempt)")
            let unbind = CommandRunner.run(Tool.dsconfigad, ["-remove", "-force", "-u", "none", "-p", "none"])
            AppLog.write("Unbind output: \(unbind.output)")
            // Restart Directory Services and let AD release before checking; checking sooner races.
            _ = CommandRunner.run(Tool.killall, ["opendirectoryd"])
            Thread.sleep(forTimeInterval: 2)
            if !isMachineBound() { return .success("Unbound (verified)") }
            AppLog.write("Still bound after attempt \(attempt).")
        }
        return .warning("Still bound after \(attempts) attempts. Continuing.")
    }

    private static func cleanSearchPaths() -> StepOutcome {
        let path = "/Active Directory/All Domains"
        let current = CommandRunner.run(Tool.dscl, ["/Search", "-read", ".", "CSPSearchPath"]).output
        guard current.contains("Active Directory") else { return .success("Not present") }
        _ = CommandRunner.run(Tool.dscl, ["/Search/Contacts", "-delete", ".", "CSPSearchPath", path])
        _ = CommandRunner.run(Tool.dscl, ["/Search", "-delete", ".", "CSPSearchPath", path])
        let after = CommandRunner.run(Tool.dscl, ["/Search", "-read", ".", "CSPSearchPath"]).output
        return after.contains("Active Directory") ? .warning("AD is still in the search path.") : .success("Removed")
    }

    /// Removes only AD entries. ShadowHash, SecureToken and the local (LKDC) Kerberos entry stay,
    /// so the local password and FileVault unlock keep working.
    private static func fixAuthenticationAuthority(_ context: MigrationContext) -> StepOutcome {
        guard let before = readSnapshot(user: context.user) else { return .failure("Could not read the account record.") }
        let entries = before.adAuthorityEntries
        guard !entries.isEmpty else { return .success("Not present") }

        var failures: [String] = []
        for entry in entries where !AuthorityFilter.isProtected(entry) {
            AppLog.write("Removing authority entry: \(entry.prefix(40))...")
            let result = CommandRunner.run(Tool.dscl, [".", "-delete", "/Users/\(context.user)", "AuthenticationAuthority", entry])
            if !result.succeeded { failures.append(result.output) }
        }

        if let violation = fileVaultViolation(context) { return .failure(violation) }
        let remaining = readSnapshot(user: context.user)?.adAuthorityEntries.count ?? entries.count
        if remaining > 0 { return .warning("\(remaining) AD entries remain. \(failures.first ?? "")") }
        return .success("Removed \(entries.count) AD entries; local password and FileVault entries kept")
    }

    private static func removeADAttributes(_ context: MigrationContext) -> StepOutcome {
        guard let snapshot = readSnapshot(user: context.user) else { return .failure("Could not read the account record.") }
        let keys = snapshot.adAttributeKeys
        guard !keys.isEmpty else { return .success("Not present") }
        var failed: [String] = []
        for key in keys {
            let result = CommandRunner.run(Tool.dscl, [".", "-delete", "/Users/\(context.user)", key])
            if !result.succeeded { failed.append(key) }
        }
        return failed.isEmpty
            ? .success("Removed \(keys.count): \(keys.map { $0.replacingOccurrences(of: "dsAttrType", with: "") }.joined(separator: ", "))")
            : .warning("Could not remove: \(failed.joined(separator: ", "))")
    }

    /// Deletes individual attribute values, not the attribute, so legitimate values (Apple Account, primary name) stay.
    private static func removeValues(
        _ context: MigrationContext,
        attribute: String,
        select: (AccountSnapshot) -> [String]
    ) -> StepOutcome {
        guard let snapshot = readSnapshot(user: context.user) else { return .failure("Could not read the account record.") }
        let values = select(snapshot)
        guard !values.isEmpty else { return .success("Not present") }
        var failed = 0
        for value in values {
            let result = CommandRunner.run(Tool.dscl, [".", "-delete", "/Users/\(context.user)", attribute, value])
            if !result.succeeded { failed += 1 }
        }
        return failed == 0 ? .success("Removed \(values.count)") : .warning("Could not remove \(failed) of \(values.count)")
    }

    private static func clearAccountPolicies(_ context: MigrationContext) -> StepOutcome {
        let result = CommandRunner.run(Tool.pwpolicy, ["-n", "/Local/Default", "-u", context.user, "-clearaccountpolicies"])
        guard result.succeeded else { return .warning(result.output) }
        let remaining = readSnapshot(user: context.user)?.extraPolicyKeys ?? []
        return remaining.isEmpty ? .success("Cleared") : .warning("Policy keys remain: \(remaining.joined(separator: ", "))")
    }

    /// Runs in the user's session; as root, plain `kdestroy` only clears root's tickets.
    private static func destroyKerberosTickets(_ context: MigrationContext) -> StepOutcome {
        guard context.uid >= 0 else { return .warning("Unknown user ID.") }
        let result = CommandRunner.run(Tool.launchctl, ["asuser", String(context.uid), Tool.kdestroy, "-a"])
        if result.succeeded { return .success("Destroyed") }
        // No tickets, or the user isn't logged in: nothing to destroy.
        if result.output.localizedCaseInsensitiveContains("No credentials cache")
            || result.output.localizedCaseInsensitiveContains("Could not find") {
            return .success("No tickets found")
        }
        return .warning(result.output)
    }

    /// A fresh account is a member of staff through PrimaryGroupID 20, not through the group's member list.
    private static func removeStaffMembership(_ context: MigrationContext) -> StepOutcome {
        guard groupValues("staff", "GroupMembership").contains(context.user) else { return .success("Not a listed member") }
        let result = CommandRunner.run(Tool.dseditgroup, ["-o", "edit", "-d", context.user, "-t", "user", "staff"])
        return result.succeeded ? .success("Removed") : .warning(result.output)
    }

    private static func fixHomeOwnership(_ context: MigrationContext) -> StepOutcome {
        guard FileManager.default.fileExists(atPath: context.homeDirectory) else {
            return .warning("Home folder not found at \(context.homeDirectory).")
        }
        let result = CommandRunner.runWithRetry(Tool.chown, ["\(context.uid):\(AccountSnapshot.freshPrimaryGroupID)", context.homeDirectory])
        return protectedFilesOutcome(result, success: "Owner \(context.user), group staff")
    }

    /// Files created while the account was an AD user carry the AD primary group. Only those are
    /// touched; the UID is unchanged so user ownership is already correct.
    private static func fixHomeContentGroups(_ context: MigrationContext) -> StepOutcome {
        let fresh = AccountSnapshot.freshPrimaryGroupID
        guard let original = context.originalPrimaryGroupID, original != fresh else { return .success("Not needed") }
        guard HomeDirectoryValidator.isSafe(context.homeDirectory, forUser: context.user) else {
            return .warning("Skipped: '\(context.homeDirectory)' is not a home folder named for the user.")
        }
        let result = CommandRunner.runWithRetry(
            Tool.find,
            [context.homeDirectory, "-xdev", "-gid", String(original), "-exec", Tool.chgrp, "-h", String(fresh), "{}", "+"]
        )
        return protectedFilesOutcome(result, success: "Group \(original) changed to staff")
    }

    private static func fixHomePermissions(_ context: MigrationContext) -> StepOutcome {
        guard FileManager.default.fileExists(atPath: context.homeDirectory) else {
            return .warning("Home folder not found at \(context.homeDirectory).")
        }
        let home = homeState(context.homeDirectory)
        var notes: [String] = []
        if home.mode != HomeState.freshMode {
            let result = CommandRunner.runWithRetry(Tool.chmod, [String(HomeState.freshMode, radix: 8), context.homeDirectory])
            if !result.succeeded { return protectedFilesOutcome(result, success: "") }
            notes.append("mode 755")
        }
        if !home.hasDenyDeleteACL {
            let result = CommandRunner.runWithRetry(Tool.chmod, ["+a", HomeState.freshACL, context.homeDirectory])
            if !result.succeeded { return protectedFilesOutcome(result, success: "") }
            notes.append("ACL")
        }
        let publicFolder = context.homeDirectory + "/Public"
        if homeState(publicFolder).exists, homeState(publicFolder).mode != HomeState.freshMode {
            _ = CommandRunner.runWithRetry(Tool.chmod, [String(HomeState.freshMode, radix: 8), publicFolder])
            notes.append("Public 755")
        }
        return .success(notes.isEmpty ? "Already correct" : "Set " + notes.joined(separator: ", "))
    }

    private static func resetPrimaryGroup(_ context: MigrationContext) -> StepOutcome {
        let fresh = String(AccountSnapshot.freshPrimaryGroupID)
        let result = CommandRunner.run(Tool.dscl, [".", "-create", "/Users/\(context.user)", "PrimaryGroupID", fresh])
        return result.succeeded ? .success("PrimaryGroupID \(fresh) (staff)") : .warning(result.output)
    }

    private static func restartDirectoryServices() -> StepOutcome {
        // Fails when it isn't running, which is fine: launchd restarts it either way.
        _ = CommandRunner.run(Tool.killall, ["opendirectoryd"])
        Thread.sleep(forTimeInterval: 2)
        return .success("Restarted")
    }

    // MARK: - Verification

    /// Nil when FileVault unlock for this user is intact (or FileVault is off).
    private static func fileVaultViolation(_ context: MigrationContext) -> String? {
        if context.hadSecureToken, readSnapshot(user: context.user)?.hasSecureToken != true {
            return "Stopped: the SecureToken entry is gone. The user may not be able to unlock FileVault."
        }
        if context.fileVaultEnabled, let guid = context.generatedUID?.uppercased(),
           context.cryptoUsersBefore.contains(guid), !cryptoUsers().contains(guid) {
            return "Stopped: the user is no longer a FileVault crypto user."
        }
        return nil
    }

    private static func verifyAccount(_ context: MigrationContext) -> StepOutcome {
        if let violation = fileVaultViolation(context) { return .failure(violation) }
        guard let snapshot = readSnapshot(user: context.user) else { return .failure("Could not read the account record.") }
        let findings = FreshAccountProfile.findings(
            snapshot: snapshot, machineBound: isMachineBound(), home: homeState(context.homeDirectory),
            adminNestedGroups: groupValues("admin", "NestedGroups"),
            staffMembers: groupValues("staff", "GroupMembership"), userName: context.user
        )
        if findings.isEmpty { return .success("Matches a fresh local account") }
        return .warning(findings.map(\.message).joined(separator: " "))
    }

    // MARK: - Helpers

    /// SIP/TCC blocks some paths even for root; that isn't a failure of the migration.
    private static func protectedFilesOutcome(_ result: CommandResult, success: String) -> StepOutcome {
        if result.succeeded { return .success(success) }
        if result.output.contains("Operation not permitted") { return .success("Done (skipped protected files)") }
        return .warning(String(result.output.prefix(300)))
    }
}
