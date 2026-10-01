//
//  ADToLocalApp.swift
//  ADToLocal
//
//  Created by Noel Rodriguez-Lebron on 12/1/25.
//

import SwiftUI

final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        // Quitting mid-migration would leave the account half converted.
        MigrationViewModel.shared?.isRunning == true ? .terminateCancel : .terminateNow
    }
}

/// Command-line flags that are passed on to the elevated copy of the app.
private let forwardedFlags: Set<String> = ["--verify", "--no-autostart", "--swiftdialog"]

func relaunchAsRoot(arguments: [String] = CommandLine.arguments) {
    guard geteuid() != 0, let executablePath = Bundle.main.executablePath else { return }
    let flags = arguments.dropFirst().filter { forwardedFlags.contains($0) }
    let command = ([executablePath] + flags).map { "\\\"\($0)\\\"" }.joined(separator: " ")
    let script = "do shell script \"\(command) &> /dev/null &\" with administrator privileges"

    var error: NSDictionary?
    NSAppleScript(source: script)?.executeAndReturnError(&error)

    if let error {
        print("Failed to relaunch as root: \(error)")
    } else {
        NSApplication.shared.terminate(nil)
    }
}

@main
struct ADToLocalApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate

    init() {
        NSApplication.shared.activate()
        // Also for --verify: the authentication data and other users' home folders are root-only,
        // so a check without root would miss differences.
        relaunchAsRoot()
    }

    var body: some Scene {
        WindowGroup {
            ContentView()
        }
        .windowResizability(.contentSize)
    }
}
