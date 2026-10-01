//
//  MigrationModel.swift
//  ADToLocal
//
//  Created by Noel Rodriguez-Lebron on 12/1/25.
//

import Foundation
import SystemConfiguration

// MARK: - Step Models

nonisolated enum MigrationStatus: Sendable {
    case pending
    case running
    case success
    case warning
    case failure
}

nonisolated struct MigrationStep: Identifiable, Sendable {
    let id = UUID()
    let action: StepAction
    var status: MigrationStatus = .pending
    var outputLog: String = ""

    var name: String { action.title }
}

nonisolated enum StepOutcome: Sendable {
    case success(String)
    case warning(String)
    case failure(String)
}

/// Facts captured before the first change, needed by later steps.
nonisolated struct MigrationContext: Sendable {
    let user: String
    let uid: Int
    let homeDirectory: String
    let originalPrimaryGroupID: Int?
    let generatedUID: String?
    /// Read before `original_shell` is removed with the other AD attributes.
    let adAssignedShell: String?
    let hadSecureToken: Bool
    let fileVaultEnabled: Bool
    let cryptoUsersBefore: Set<String>
}

/// Everything read from the system before deciding what to do.
nonisolated struct SystemAnalysis: Sendable {
    let snapshot: AccountSnapshot
    let machineBound: Bool
    let home: HomeState?
    let adminNestedGroups: [String]
    let staffMembers: [String]
    let context: MigrationContext
    let findings: [Finding]
    let plan: [StepAction]
}

// MARK: - Target Account

nonisolated enum TargetAccount {
    /// The account to convert: the `enrollmentUser` managed preference, else the console user.
    static func resolve() -> String {
        if let configured = UserDefaults.standard.string(forKey: "enrollmentUser"), !configured.isEmpty {
            return configured
        }
        return consoleUser()
    }

    /// The user who is actually logged in at the console.
    /// After `relaunchAsRoot()` the process user is `root`, so `NSUserName()` can't be used.
    static func consoleUser() -> String {
        if let name = SCDynamicStoreCopyConsoleUser(nil, nil, nil) as String?,
           !name.isEmpty, name != "root", name != "loginwindow" {
            return name
        }
        return NSUserName()
    }
}
