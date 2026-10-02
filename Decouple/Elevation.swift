//
//  Elevation.swift
//  Decouple
//
//  Requests administrator privileges for the elevated copy of the app.
//
//  Apple has no supported API to elevate a GUI process on demand. The pattern admin
//  utilities use is `do shell script ... with administrator privileges`. This file
//  moves that call out of the blocking NSAppleScript-in-init approach into an
//  osascript subprocess, so the authorization prompt never blocks the interface and
//  a cancelled prompt is a visible, retryable state instead of a silent fall-through.
//
//  The Apple-recommended architecture for privileged helpers (SMAppService daemon +
//  XPC) is a much larger rework and is unnecessary here: MDM can run this app's
//  binary directly as root, which skips elevation entirely.
//

import AppKit
import Observation
import SwiftUI

@MainActor
@Observable
final class ElevationManager {
    enum State: Equatable {
        /// Initial state; a root session (MDM, terminal) never elevates.
        case idle
        /// The authorization prompt is up.
        case requesting
        /// The user declined the prompt, or launching the elevated copy failed.
        case failed(String)
        /// The elevated copy is running; this instance exits.
        case handingOff
    }

    /// Flags carried over to the elevated copy.
    static let forwardedFlags: Set<String> = ["--verify", "--no-autostart"]

    private(set) var state: State = .idle
    private var process: Process?

    func start(arguments: [String]) {
        // Retry is allowed after a failure; only block while a request is in flight.
        guard state != .requesting, state != .handingOff else { return }
        if geteuid() == 0 {
            state = .handingOff // already root: nothing to elevate
            return
        }
        guard let executablePath = Bundle.main.executablePath else {
            state = .failed("Could not locate the app's executable.")
            return
        }

        let forwarded = arguments.dropFirst().filter { Self.forwardedFlags.contains($0) }
        let command = ([executablePath] + forwarded)
            .map { "\\\"\($0)\\\"" }
            .joined(separator: " ")

        state = .requesting
        let stderr = Pipe()
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        // The "&" is required: do shell script returns as soon as the elevated copy is
        // backgrounded, so this osascript exits quickly and its exit status tells us
        // whether the hand-off started (0) or the prompt was cancelled (not 0).
        task.arguments = ["-e", "do shell script \"\(command) &> /dev/null &\" with administrator privileges"]
        task.standardError = stderr
        task.standardOutput = FileHandle.nullDevice
        task.terminationHandler = { [weak self] completed in
            let errorText = String(
                decoding: (try? stderr.fileHandleForReading.readToEnd()) ?? Data(),
                as: UTF8.self
            )
            Task { @MainActor [weak self] in
                guard let self, case .requesting = self.state else { return }
                if completed.terminationStatus == 0 {
                    self.state = .handingOff
                    NSApplication.shared.terminate(nil) // the elevated copy is up
                    return
                }
                let cancelled = errorText.contains("User canceled") || errorText.contains("(-128)")
                self.state = .failed(
                    cancelled
                        ? "Administrator privileges were not granted."
                        : "Could not launch with administrator privileges:\n"
                          + (errorText.isEmpty
                              ? "osascript exit \(completed.terminationStatus)"
                              : String(errorText.prefix(200)))
                )
            }
        }
        do {
            try task.run()
            process = task
        } catch {
            state = .failed("Could not start the authorization prompt: \(error.localizedDescription)")
        }
    }
}

extension View {
    /// One shared window box for every app state (elevation, prompt, content), so the
    /// window is created at the ideal size and resizing stays in this range.
    /// Portrait proportions, like a standard macOS utility panel.
    func decoupleWindowFrame() -> some View {
        frame(minWidth: 460, idealWidth: 480, maxWidth: 520,
              minHeight: 600, idealHeight: 700, maxHeight: 840)
    }
}

/// Runs the app content only when the process is root. Otherwise it shows the
/// authorization flow: a progress state while the prompt is up, and retry controls
/// when the prompt was cancelled or the hand-off failed.
struct ElevationGate<Content: View>: View {
    @ViewBuilder let content: () -> Content
    @State private var elevation = ElevationManager()

    var body: some View {
        Group {
            if geteuid() == 0 || elevation.state == .handingOff {
                content()
            } else {
                switch elevation.state {
                case .idle:
                    // Starts elevation on first appearance (non-root sessions only).
                    Color.clear
                        .onAppear { elevation.start(arguments: CommandLine.arguments) }
                case .requesting:
                    ProgressView {
                        Text("Requesting administrator privileges…")
                    }
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                case .failed(let message):
                    VStack(spacing: 16) {
                        ContentUnavailableView {
                            Label("Administrator Privileges Required", systemImage: "lock")
                        } description: {
                            Text(message)
                                .multilineTextAlignment(.center)
                        }
                        .frame(maxHeight: .infinity)
                        HStack(spacing: 12) {
                            Button("Quit") { NSApplication.shared.terminate(nil) }
                            Button("Try Again") { elevation.start(arguments: CommandLine.arguments) }
                                .buttonStyle(.borderedProminent)
                                .keyboardShortcut(.defaultAction)
                        }
                        .padding(.bottom, 16)
                    }
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                case .handingOff:
                    Color.clear
                }
            }
        }
        .decoupleWindowFrame()
        .background(WindowAccessor(isBusy: false))
    }
}