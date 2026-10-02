//
//  DialogCommands.swift
//  Decouple
//
//  Formats swiftDialog command-file lines and launch arguments. Pure (Foundation only) so it can
//  be unit tested. https://github.com/swiftDialog/swiftDialog
//

import Foundation

nonisolated enum DialogStatus: String, Sendable {
    case pending, wait, success, fail, error
}

nonisolated enum DialogCommands {
    static let quit = "quit:"

    /// The command file is line based and the parser splits on commas and colons. Keep text on one
    /// line and free of the separator so a message can't be read as another field or command.
    static func sanitize(_ text: String, limit: Int = 140) -> String {
        let flat = text
            .replacingOccurrences(of: "\r", with: " ")
            .replacingOccurrences(of: "\n", with: " ")
            .replacingOccurrences(of: ",", with: ";")
            .trimmingCharacters(in: .whitespaces)
        return flat.count > limit ? String(flat.prefix(limit - 1)) + "…" : flat
    }

    static func listItem(index: Int, status: DialogStatus, text: String) -> String {
        "listitem: index: \(index), status: \(status.rawValue), statustext: \(sanitize(text))"
    }

    static func progress(_ value: Int) -> String { "progress: \(max(0, value))" }
    static func progressText(_ text: String) -> String { "progresstext: \(sanitize(text))" }
    static func title(_ text: String) -> String { "title: \(sanitize(text))" }

    /// swiftDialog reads a literal `\n` as a line break in the message.
    static func message(_ text: String) -> String {
        "message: " + text.replacingOccurrences(of: "\r", with: "").replacingOccurrences(of: "\n", with: "\\n")
    }

    static func button(_ text: String, enabled: Bool) -> [String] {
        ["button1text: \(sanitize(text, limit: 40))", "button1: \(enabled ? "enable" : "disable")"]
    }

    static func launchArguments(
        title: String,
        message: String,
        items: [String],
        commandFile: String
    ) -> [String] {
        var arguments = [
            "--title", title,
            "--message", message.replacingOccurrences(of: "\n", with: "\\n"),
            "--icon", "SF=person.crop.circle.badge.checkmark",
            "--progress", String(items.count),
            "--progresstext", "Starting",
            "--button1text", "Working…", "--button1disabled",
            "--commandfile", commandFile,
            "--moveable", "--ontop",
            "--width", "620", "--height", "520"
        ]
        for item in items { arguments += ["--listitem", item] }
        return arguments
    }
}
