//
//  ADAccountMigratorApp.swift
//  ADAccountMigrator
//
//  Created by Noel Rodriguez-Lebron on 12/1/25.
//

import SwiftUI

class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        if let viewModel = MigrationViewModel.shared, viewModel.isRunning {
            return .terminateCancel
        }
        return .terminateNow
    }
}

func relaunchAsRoot() {
    let euid = geteuid()
    if euid != 0 {
        let executablePath = Bundle.main.executablePath!
        let script = "do shell script \"\\\"\(executablePath)\\\"\" with administrator privileges"
        
        let appleScript = NSAppleScript(source: script)
        var error: NSDictionary?
        appleScript?.executeAndReturnError(&error)
        
        if error != nil {
            print("Failed to relaunch as root: \(String(describing: error))")
        } else {
            NSApplication.shared.terminate(nil)
        }
    }
}

@main
struct ADAccountMigratorApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) var appDelegate
    
    init() {
        relaunchAsRoot()
    }

    var body: some Scene {
        WindowGroup {
            ContentView()
        }
        .windowResizability(.contentSize)
    }
}
