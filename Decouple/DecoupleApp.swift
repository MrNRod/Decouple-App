//
//  DecoupleApp.swift
//  Decouple
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

@main
struct DecoupleApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate

    init() {
        NSApplication.shared.activate()
    }

    var body: some Scene {
        WindowGroup {
            // Also gates --verify: authentication data and other users' home folders are
            // root-only, so a check without root would miss differences.
            ElevationGate {
                ContentView()
            }
        }
        .windowResizability(.contentSize)
    }
}