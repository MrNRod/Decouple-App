import AppKit
import Foundation
import Observation

@MainActor
@Observable
final class MigrationViewModel {
    enum Mode {
        /// Convert the account.
        case migrate
        /// Read-only: report what differs from a fresh local account.
        case verifyOnly
    }

    enum Phase: Equatable {
        case analyzing
        /// Nothing to do: already a local account with no AD traces.
        case clean
        case ready
        case running
        case completed(hasWarnings: Bool)
        case verified
        case failed(String)
    }

    static weak var shared: MigrationViewModel?

    let user: String
    let mode: Mode
    let autoStart: Bool
    /// Shows progress in swiftDialog instead of the SwiftUI window (`--swiftdialog`, if it's installed).
    let usesDialog: Bool

    private(set) var phase: Phase = .analyzing
    private(set) var steps: [MigrationStep] = []
    private(set) var findings: [Finding] = []
    private(set) var log = ""

    @ObservationIgnored private var analysis: SystemAnalysis?
    @ObservationIgnored private var hasPrepared = false
    @ObservationIgnored private var dialog: SwiftDialogPresenter?

    init(arguments: [String] = CommandLine.arguments) {
        user = TargetAccount.resolve()
        mode = arguments.contains("--verify") ? .verifyOnly : .migrate
        usesDialog = arguments.contains("--swiftdialog") && SwiftDialogPresenter.isInstalled
        // The dialog has no start button, so it always runs straight through.
        autoStart = usesDialog || !arguments.contains("--no-autostart")
    }

    var isRunning: Bool { phase == .running }

    var progress: Double {
        guard !steps.isEmpty else { return 0 }
        let finished = steps.filter { $0.status != .pending && $0.status != .running }.count
        return Double(finished) / Double(steps.count)
    }

    var warningSteps: [MigrationStep] { steps.filter { $0.status == .warning } }

    // MARK: - Analysis

    /// Reads the system and builds the plan. Safe to call more than once.
    func prepare() async {
        guard !hasPrepared else { return }
        hasPrepared = true
        Self.shared = self

        guard UsernameValidator.isValid(user) else {
            append("Refusing to continue: '\(user)' is not a valid account name.")
            phase = .failed("Invalid target user name.\nCheck the enrollmentUser setting.")
            presentResult(title: "Migration Not Started", message: "Invalid target user name. Check the enrollmentUser setting.")
            return
        }
        append("Analyzing system state for user: \(user)...")
        if geteuid() != 0 { append("Not running as root: read-only checks only.") }

        let name = user
        guard let result = await offMain({ AccountOperations.analyze(user: name) }) else {
            append("The account '\(user)' does not exist.")
            phase = .failed("The account '\(user)' was not found.")
            presentResult(title: "Migration Not Started", message: "The account '\(user)' was not found.")
            return
        }
        analysis = result
        findings = result.findings
        append("Machine bound: \(result.machineBound) | Mobile account: \(result.snapshot.isMobileAccount) | UID \(result.context.uid)")
        append("Home directory: \(result.context.homeDirectory)")
        append("FileVault: \(result.context.fileVaultEnabled ? "on" : "off") | SecureToken: \(result.context.hadSecureToken)")
        findings.forEach { append("Found: \($0.message)") }

        if mode == .verifyOnly {
            phase = .verified
            presentResult(
                title: findings.isEmpty ? "Matches a Fresh Local Account" : "\(findings.count) Difference(s) Found",
                message: findings.isEmpty ? "No Active Directory traces were found." : findings.map { "- \($0.message)" }.joined(separator: "\n") + "\n\nNothing was changed."
            )
            return
        }
        if result.plan.isEmpty {
            append("No actions required.")
            phase = .clean
            presentResult(title: "Already a Local Account", message: "No Active Directory traces were found. Nothing to change.")
            return
        }
        steps = result.plan.map { MigrationStep(action: $0) }
        phase = .ready
        if usesDialog { openDialog(items: steps.map(\.name)) }
    }

    // MARK: - Execution

    func startMigration() {
        guard phase == .ready, let analysis else { return }
        // Check once, up front, instead of guessing from "Permission denied" in command output.
        guard geteuid() == 0 else {
            fail("Administrator privileges are required.\nRelaunch the app and approve the prompt.")
            return
        }
        phase = .running
        AppLog.write("--- Starting migration for \(user) ---")
        let context = analysis.context

        Task {
            for index in steps.indices {
                steps[index].status = .running
                dialog?.send(
                    DialogCommands.listItem(index: index, status: .wait, text: "Running"),
                    DialogCommands.progressText(steps[index].name)
                )
                let action = steps[index].action
                let outcome = await offMain { AccountOperations.execute(action, context: context) }

                switch outcome {
                case .success(let message):
                    finish(index, .success, message)
                case .warning(let message):
                    finish(index, .warning, message)
                case .failure(let message):
                    if action.policy == .critical {
                        finish(index, .failure, message)
                        fail("Migration Failed.\n\(message)")
                        return
                    }
                    finish(index, .warning, message)
                }
            }
            let hasWarnings = !warningSteps.isEmpty
            append(hasWarnings ? "--- MIGRATION COMPLETED WITH WARNINGS ---" : "--- ALL TASKS COMPLETED SUCCESSFULLY ---")
            AppLog.write("--- Migration finished (warnings: \(hasWarnings)) ---")
            phase = .completed(hasWarnings: hasWarnings)
            dialogFinish(
                title: hasWarnings ? "Completed With Warnings" : "Migration Successful",
                message: hasWarnings
                    ? "Review the steps marked with a warning. Details: \(AppLog.path)"
                    : "\(user) is now a local account.\nRestart this Mac to confirm the login still works."
            )
        }
    }

    /// Restarts the Mac. A restart is the only way to prove the FileVault login still works.
    func restart() {
        Task { _ = await offMain { CommandRunner.run("/sbin/shutdown", ["-r", "now"]) } }
    }

    // MARK: - Helpers

    private func finish(_ index: Int, _ status: MigrationStatus, _ message: String) {
        steps[index].status = status
        steps[index].outputLog = message
        dialog?.send(
            DialogCommands.listItem(index: index, status: status.dialogStatus, text: message),
            DialogCommands.progress(steps.filter { $0.status != .pending && $0.status != .running }.count)
        )
        append("[\(steps[index].name)]\(status == .warning ? " [WARNING]" : ""): \(message)")
    }

    private func fail(_ message: String) {
        append("CRITICAL ERROR: \(message)")
        AppLog.write("CRITICAL ERROR: \(message)")
        phase = .failed(message)
        presentResult(title: "Migration Failed", message: message)
    }

    // MARK: - swiftDialog

    private func openDialog(items: [String]) {
        guard dialog == nil else { return }
        let presenter = SwiftDialogPresenter()
        let started = presenter.start(
            title: "AD to Local Migration",
            message: "Converting \(user) to a local account.\nDo not restart or power off this Mac.",
            items: items,
            consoleUID: TargetAccount.consoleUID()
        ) {
            // The user closed the dialog (its button is only enabled once the run is over).
            Task { @MainActor in NSApplication.shared.terminate(nil) }
        }
        if started { dialog = presenter } else { append("Could not start swiftDialog.") }
    }

    /// A result with no step list (clean, verify, early failure).
    private func presentResult(title: String, message: String) {
        guard usesDialog else { return }
        openDialog(items: [])
        dialogFinish(title: title, message: message)
    }

    private func dialogFinish(title: String, message: String) {
        dialog?.send([DialogCommands.title(title), DialogCommands.message(message), DialogCommands.progressText(title)]
                     + DialogCommands.button("Close", enabled: true))
    }

    private func append(_ message: String) {
        log.append(message + "\n")
    }
}

/// Runs blocking work on a background queue without tying up a cooperative-pool thread.
private nonisolated func offMain<T: Sendable>(_ work: @escaping @Sendable () -> T) async -> T {
    await withCheckedContinuation { continuation in
        DispatchQueue.global(qos: .userInitiated).async { continuation.resume(returning: work()) }
    }
}
