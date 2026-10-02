//
//  SwiftDialogPresenter.swift
//  Decouple
//
//  Optional front end: shows progress in swiftDialog instead of the SwiftUI window.
//  swiftDialog is a separate, signed app that must be installed (it's a normal MDM package).
//

import Foundation

nonisolated final class SwiftDialogPresenter: @unchecked Sendable {
    static let executable = "/usr/local/bin/dialog"
    static var isInstalled: Bool { FileManager.default.isExecutableFile(atPath: executable) }

    private let commandFile: String
    private let lock = NSLock()
    private var process: Process?

    init(commandFile: String = "/private/var/tmp/adtolocal_dialog.log") {
        self.commandFile = commandFile
    }

    /// Opens the dialog. As root it has to be started inside the logged-in user's session,
    /// otherwise the window never appears; the command file stays writable by root only.
    func start(title: String, message: String, items: [String], consoleUID: uid_t?, onExit: @escaping @Sendable () -> Void) -> Bool {
        FileManager.default.createFile(atPath: commandFile, contents: nil, attributes: [.posixPermissions: 0o644])
        let dialogArguments = DialogCommands.launchArguments(title: title, message: message, items: items, commandFile: commandFile)

        let task = Process()
        if geteuid() == 0, let consoleUID {
            task.executableURL = URL(fileURLWithPath: "/bin/launchctl")
            task.arguments = ["asuser", String(consoleUID), Self.executable] + dialogArguments
        } else {
            task.executableURL = URL(fileURLWithPath: Self.executable)
            task.arguments = dialogArguments
        }
        task.standardOutput = FileHandle.nullDevice
        task.standardError = FileHandle.nullDevice
        task.terminationHandler = { _ in onExit() }
        do { try task.run() } catch { return false }
        lock.lock(); process = task; lock.unlock()
        return true
    }

    func send(_ lines: String...) { send(lines) }

    func send(_ lines: [String]) {
        lock.lock(); defer { lock.unlock() }
        guard let handle = FileHandle(forWritingAtPath: commandFile) else { return }
        defer { try? handle.close() }
        _ = try? handle.seekToEnd()
        try? handle.write(contentsOf: Data((lines.joined(separator: "\n") + "\n").utf8))
    }

    func close() { send(DialogCommands.quit) }
}

extension MigrationStatus {
    nonisolated var dialogStatus: DialogStatus {
        switch self {
        case .pending: .pending
        case .running: .wait
        case .success: .success
        // swiftDialog has no "warning" state; "error" is the closest visible one.
        case .warning: .error
        case .failure: .fail
        }
    }
}
