//
//  CommandRunner.swift
//  Decouple
//
//  Runs system tools with an argument array (never through a shell) and logs to
//  the unified log and to /private/var/log/decouple.log.
//

import Foundation
import os

nonisolated struct CommandResult: Sendable {
    let status: Int32
    let output: String

    var succeeded: Bool { status == 0 }
}

nonisolated enum CommandRunner {
    /// Runs `executable` and blocks until it exits. Call from a background queue.
    static func run(_ executable: String, _ arguments: [String] = []) -> CommandResult {
        let task = Process()
        let pipe = Pipe()
        task.executableURL = URL(fileURLWithPath: executable)
        task.arguments = arguments
        task.standardOutput = pipe
        task.standardError = pipe
        do {
            try task.run()
        } catch {
            return CommandResult(status: -1, output: "Failed to launch \(executable): \(error.localizedDescription)")
        }
        // Drain the pipe before waiting: a child that fills the 64 KB pipe buffer
        // blocks on write and would never exit while we sit in waitUntilExit().
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        task.waitUntilExit()
        let output = String(decoding: data, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
        return CommandResult(status: task.terminationStatus, output: output)
    }

    /// Security software can interrupt file-system tools (`EINTR`, `fts_read`). Retry only those.
    static func runWithRetry(
        _ executable: String,
        _ arguments: [String],
        maxAttempts: Int = 5,
        delay: TimeInterval = 2
    ) -> CommandResult {
        var attempt = 0
        var result = CommandResult(status: -1, output: "")
        while attempt < maxAttempts {
            attempt += 1
            result = run(executable, arguments)
            if result.succeeded { return result }
            let interrupted = result.output.localizedCaseInsensitiveContains("Interrupted system call")
                || result.output.localizedCaseInsensitiveContains("fts_read")
            guard interrupted else { return result }
            AppLog.write("Command interrupted (attempt \(attempt)/\(maxAttempts)); retrying in \(delay)s.")
            if attempt < maxAttempts { Thread.sleep(forTimeInterval: delay) }
        }
        AppLog.write("Command failed after \(maxAttempts) attempts.")
        return result
    }
}

nonisolated enum AppLog {
    static let path = "/private/var/log/decouple.log"

    private static let logger = Logger(subsystem: "com.mrnrod45.Decouple", category: "migration")
    private static let lock = NSLock()

    static func write(_ message: String) {
        logger.notice("\(message, privacy: .public)")
        let entry = "\(Date().formatted(.iso8601)): \(message)\n"

        lock.lock()
        defer { lock.unlock() }
        let url = URL(fileURLWithPath: path)
        // World-readable like the script's /var/log/decouple.log, so an end user can
        // read and send it to IT. Upgrades files created as 0600 by earlier versions.
        if !FileManager.default.fileExists(atPath: path) {
            FileManager.default.createFile(atPath: path, contents: nil, attributes: [.posixPermissions: 0o644])
        } else if let attributes = try? FileManager.default.attributesOfItem(atPath: path),
                  let permissions = attributes[.posixPermissions] as? NSNumber,
                  permissions.int32Value != 0o644 {
            try? FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: path)
        }
        // Not root (verify mode, Xcode runs): the unified log above is still written.
        guard let handle = try? FileHandle(forWritingTo: url) else { return }
        defer { try? handle.close() }
        _ = try? handle.seekToEnd()
        try? handle.write(contentsOf: Data(entry.utf8))
    }
}
