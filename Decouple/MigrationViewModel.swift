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
    /// The `grantAdmin` managed preference. Off unless the profile turns it on.
    let grantAdmin: Bool

    private(set) var phase: Phase = .analyzing
    private(set) var steps: [MigrationStep] = []
    private(set) var findings: [Finding] = []
    private(set) var log = ""

    @ObservationIgnored private var analysis: SystemAnalysis?
    @ObservationIgnored private var hasPrepared = false

    init(arguments: [String] = CommandLine.arguments) {
        user = TargetAccount.resolve()
        grantAdmin = UserDefaults.standard.bool(forKey: "grantAdmin")
        // The --verify flag and the verifyOnly preference do the same thing:
        // the flag for interactive use, the key for MDM (like VerifyOnly=true in the script).
        mode = (arguments.contains("--verify") || UserDefaults.standard.bool(forKey: "verifyOnly"))
            ? .verifyOnly : .migrate
        autoStart = !arguments.contains("--no-autostart")
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
            return
        }
        append("Analyzing system state for user: \(user)...")
        if geteuid() != 0 { append("Not running as root: read-only checks only.") }

        let name = user
        let admin = grantAdmin
        guard let result = await offMain({ AccountOperations.analyze(user: name, grantAdmin: admin) }) else {
            append("The account '\(user)' does not exist.")
            phase = .failed("The account '\(user)' was not found.")
            return
        }
        analysis = result
        findings = result.findings
        append("Machine bound: \(result.machineBound) | Mobile account: \(result.snapshot.isMobileAccount) | UID \(result.context.uid)")
        append("Home directory: \(result.context.homeDirectory)")
        if grantAdmin { append("grantAdmin is on: the user will be added to the admin group.") }
        append("FileVault: \(result.context.fileVaultEnabled ? "on" : "off") | SecureToken: \(result.context.hadSecureToken)")
        findings.forEach { append("Found: \($0.message)") }

        if mode == .verifyOnly {
            phase = .verified
            return
        }
        if result.plan.isEmpty {
            append("No actions required.")
            phase = .clean
            return
        }
        steps = result.plan.map { MigrationStep(action: $0) }
        phase = .ready
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
        append("[\(steps[index].name)]\(status == .warning ? " [WARNING]" : ""): \(message)")
    }

    private func fail(_ message: String) {
        append("CRITICAL ERROR: \(message)")
        AppLog.write("CRITICAL ERROR: \(message)")
        phase = .failed(message)
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
