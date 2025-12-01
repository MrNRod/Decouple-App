//
//  MigrationModel.swift
//  ADAccountMigrator
//
//  Created by Noel Rodriguez-Lebron on 12/1/25.
//

import Foundation
// MARK: - Shared Models (Moved here to fix Scope errors)
enum MigrationStatus {
    case pending
    case running
    case success
    case failure
}
struct MigrationStep: Identifiable {
    let id = UUID()
    let name: String
    let command: String
    var status: MigrationStatus = .pending
    var outputLog: String = ""
}
// MARK: - Script Configuration
class ScriptConfig {
    static var User: String = ""
    static let LogFile = "/private/var/log/ad_to_local_migration.log"
}
// MARK: - Logging
class ScriptLogger {
    static func ScriptLogging(_ message: String) {
        let timestamp = ISO8601DateFormatter().string(from: Date())
        let logEntry = "\(timestamp): \(message)\n"
        print(logEntry, terminator: "")
        let fileURL = URL(fileURLWithPath: ScriptConfig.LogFile)
        do {
            if !FileManager.default.fileExists(atPath: ScriptConfig.LogFile) {
                try "".write(to: fileURL, atomically: true, encoding: .utf8)
            }
            let handle = try FileHandle(forWritingTo: fileURL)
            handle.seekToEndOfFile()
            if let data = logEntry.data(using: .utf8) {
                handle.write(data)
            }
            handle.closeFile()
        } catch {
            print("Error writing to log: \(error)")
        }
    }
}
// MARK: - Shell Execution
class Shell {
    static func execute(_ command: String) -> (Int32, String) {
        let task = Process()
        let pipe = Pipe()
        task.launchPath = "/bin/bash"
        task.arguments = ["-c", command]
        task.standardOutput = pipe
        task.standardError = pipe
        do {
            try task.run()
        } catch {
            return (-1, "Failed to launch: \(error)")
        }
        task.waitUntilExit()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        return (task.terminationStatus, output)
    }
}
