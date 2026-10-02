//
//  ContentView.swift
//  Decouple
//
//  Created by Noel Rodriguez-Lebron on 12/1/25.
//

import SwiftUI

struct ContentView: View {
    @State private var viewModel = MigrationViewModel()
    @State private var showLog = false
    @State private var confirmRestart = false

    var body: some View {
        Group {
            if viewModel.usesDialog {
                // swiftDialog is the UI; this window stays hidden.
                Color.clear.frame(width: 1, height: 1).background(WindowAccessor(isBusy: false, isHidden: true))
            } else {
                mainContent
            }
        }
        .task {
            await viewModel.prepare()
            if viewModel.autoStart { viewModel.startMigration() }
        }
    }

    // MARK: - Layout

    private var mainContent: some View {
        VStack(alignment: .leading, spacing: 12) {
            header

            if !viewModel.steps.isEmpty {
                ProgressView(value: viewModel.progress)
                    .accessibilityLabel("Migration progress")
            }

            Divider()
            content
            logArea

            Divider()
            footer
        }
        .padding()
        .decoupleWindowFrame()
        .background(WindowAccessor(isBusy: viewModel.isRunning))
        .confirmationDialog("Restart this Mac now?", isPresented: $confirmRestart) {
            Button("Restart Now", role: .destructive) { viewModel.restart() }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("Unsaved work in other apps will be lost.")
        }
    }

    /// Form-style header: a small caption above the account name, mode label trailing.
    private var header: some View {
        VStack(alignment: .leading, spacing: 2) {
            HStack(alignment: .firstTextBaseline) {
                Text("Target user")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Spacer()
                if viewModel.mode == .verifyOnly {
                    Text("Verify only")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                } else if viewModel.usesDialog {
                    Text("swiftDialog")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            Text(viewModel.user)
                .font(.title3.weight(.semibold))
                .textSelection(.enabled)
        }
    }

    private var logArea: some View {
        Group {
            if showLog {
                ScrollView(showsIndicators: true) {
                    Text(viewModel.log)
                        .font(.system(.caption2, design: .monospaced))
                        .fixedSize(horizontal: false, vertical: true)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .textSelection(.enabled)
                }
                .frame(height: 170)
            }
        }
    }

    // MARK: - Content

    @ViewBuilder
    private var content: some View {
        switch viewModel.phase {
        case .analyzing:
            ProgressView("Analyzing account…")
                .controlSize(.large)
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        case .clean:
            ContentUnavailableView(
                "Already a Local Account",
                systemImage: "checkmark.shield",
                description: Text("No Active Directory traces were found. Nothing to change.")
            )
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        case .ready, .running:
            StepListView(steps: viewModel.steps)
        case .completed(let hasWarnings):
            VStack(spacing: 12) {
                ContentUnavailableView(
                    hasWarnings ? "Completed With Warnings" : "Migration Successful",
                    systemImage: hasWarnings ? "exclamationmark.triangle" : "checkmark.shield",
                    description: Text(hasWarnings
                        ? "Review the steps marked with a warning below."
                        : "\(viewModel.user) is now a local account. Restart to confirm the login still works.")
                )
                .frame(maxWidth: .infinity, maxHeight: .infinity)
                // swiftDialog-style: the full step list with its checkmarks stays visible.
                StepListView(steps: viewModel.steps)
            }
        case .verified:
            VerificationResultView(findings: viewModel.findings)
        case .failed(let message):
            VStack(spacing: 12) {
                ContentUnavailableView(
                    "Migration Failed",
                    systemImage: "xmark.octagon",
                    description: Text(message)
                )
                .frame(maxWidth: .infinity, maxHeight: .infinity)
                if !viewModel.steps.isEmpty { StepListView(steps: viewModel.steps) }
            }
        }
    }

    // MARK: - Footer

    private var footer: some View {
        HStack(spacing: 12) {
            Button {
                withAnimation { showLog.toggle() }
            } label: {
                Label(showLog ? "Hide Log" : "Show Log", systemImage: "text.justify.leading")
            }
            .help("Toggle the migration log")

            Spacer()

            switch viewModel.phase {
            case .analyzing:
                EmptyView()
            case .ready:
                Button("Start Migration") { viewModel.startMigration() }
                    .buttonStyle(.borderedProminent)
                    .keyboardShortcut(.defaultAction)
            case .running:
                ProgressView()
                    .controlSize(.small)
                Text("Migrating…")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            case .completed:
                Button("Restart Now") { confirmRestart = true }
                closeButton
            case .clean, .verified, .failed:
                closeButton
            }
        }
    }

    private var closeButton: some View {
        Button("Close") { NSApplication.shared.terminate(nil) }
            .keyboardShortcut(.defaultAction)
    }
}

// MARK: - Step List

struct StepListView: View {
    let steps: [MigrationStep]

    var body: some View {
        ScrollViewReader { proxy in
            ScrollView(showsIndicators: true) {
                VStack(alignment: .leading, spacing: 10) {
                    ForEach(steps) { step in
                        StepRow(step: step).id(step.id)
                    }
                }
                .padding(.vertical, 2)
            }
            .onChange(of: steps.first { $0.status == .running }?.id) { _, id in
                if let id { withAnimation { proxy.scrollTo(id, anchor: .center) } }
            }
        }
    }
}

struct StepRow: View {
    let step: MigrationStep

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            StatusIndicator(status: step.status)
            VStack(alignment: .leading, spacing: 2) {
                Text(step.name)
                    .font(.callout)
                if step.status == .warning || step.status == .failure, !step.outputLog.isEmpty {
                    Text(step.outputLog)
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                        .textSelection(.enabled)
                }
            }
            Spacer(minLength: 0)
        }
        .padding(.vertical, 1)
        .accessibilityElement(children: .combine)
    }
}

struct StatusIndicator: View {
    let status: MigrationStatus

    var body: some View {
        Group {
            switch status {
            case .pending:
                Image(systemName: "circle")
                    .foregroundStyle(.tertiary)
            case .running:
                ProgressView()
                    .controlSize(.small)
            case .success:
                Image(systemName: "checkmark.circle.fill")
                    .foregroundStyle(.green)
            case .warning:
                Image(systemName: "exclamationmark.triangle.fill")
                    .foregroundStyle(.orange)
            case .failure:
                Image(systemName: "xmark.octagon.fill")
                    .foregroundStyle(.red)
            }
        }
        .frame(width: 18, height: 18)
        .accessibilityLabel(label)
    }

    private var label: String {
        switch status {
        case .pending: "Pending"
        case .running: "Running"
        case .success: "Done"
        case .warning: "Warning"
        case .failure: "Failed"
        }
    }
}

struct VerificationResultView: View {
    let findings: [Finding]

    var body: some View {
        if findings.isEmpty {
            ContentUnavailableView(
                "Matches a Fresh Local Account",
                systemImage: "checkmark.shield",
                description: Text("No Active Directory traces were found.")
            )
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        } else {
            VStack(spacing: 12) {
                Text("\(findings.count) difference\(findings.count == 1 ? "" : "s") found. Nothing was changed.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, alignment: .leading)
                ScrollView(showsIndicators: true) {
                    VStack(alignment: .leading, spacing: 10) {
                        ForEach(findings, id: \.message) { finding in
                            Label(finding.message, systemImage: "exclamationmark.triangle")
                                .font(.callout)
                                .fixedSize(horizontal: false, vertical: true)
                                .frame(maxWidth: .infinity, alignment: .leading)
                        }
                    }
                    .padding(.vertical, 2)
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
                .frame(maxHeight: .infinity)
            }
        }
    }
}

struct WindowAccessor: NSViewRepresentable {
    /// While the migration runs the window can't be closed, and it stays above other windows.
    let isBusy: Bool
    var isHidden = false

    final class Coordinator {
        var centeredWindow: NSWindow?
    }

    func makeCoordinator() -> Coordinator { Coordinator() }

    func makeNSView(context: Context) -> NSView {
        let view = NSView()
        DispatchQueue.main.async { configure(view.window, context.coordinator) }
        return view
    }

    func updateNSView(_ nsView: NSView, context: Context) {
        configure(nsView.window, context.coordinator)
    }

    private func configure(_ window: NSWindow?, _ coordinator: Coordinator) {
        if isHidden {
            window?.orderOut(nil)
            return
        }
        window?.level = .floating
        // State restoration saves frames across the elevating relaunch and puts the
        // window wherever the old session left it. Don't save, and center each new window.
        if window !== coordinator.centeredWindow, let window {
            window.setFrameAutosaveName("")
            window.center()
            coordinator.centeredWindow = window
        }
        window?.standardWindowButton(.closeButton)?.isEnabled = !isBusy
    }
}