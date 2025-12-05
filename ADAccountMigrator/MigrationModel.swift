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
    case warning
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

    static func executeWithRetry(_ command: String, maxRetries: Int = 5, delay: UInt32 = 2) -> (Int32, String) {
        var attempts = 0
        var result: (Int32, String) = (-1, "")
        
        repeat {
            attempts += 1
            result = execute(command)
            
            // If success, return immediately
            if result.0 == 0 { return result }
            
            // Check for specific interruption errors
            // "Interrupted system call" is the standard message for EINTR
            if result.1.localizedCaseInsensitiveContains("Interrupted system call") || result.1.localizedCaseInsensitiveContains("fts_read") {
                ScriptLogger.ScriptLogging("Command interrupted (Attempt \(attempts)/\(maxRetries)). Retrying in \(delay)s...")
                sleep(delay)
            } else {
                // If it's a different error (e.g. Permission Denied), retrying likely won't help.
                // Return the result immediately.
                return result
            }
            
        } while attempts < maxRetries
        
        ScriptLogger.ScriptLogging("Command failed after \(maxRetries) attempts.")
        return result
    }
}
