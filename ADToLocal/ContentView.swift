//
//  ContentView.swift
//  ADToLocal
//
//  Created by Noel Rodriguez-Lebron on 12/1/25.
//

import SwiftUI

struct ContentView: View {
    @State private var viewModel = MigrationViewModel()
    @State private var showLog = false
    @State private var confirmRestart = false

    var body: some View {
        VStack(spacing: 16) {
            VStack(spacing: 4) {
                Text(viewModel.mode == .verifyOnly ? "AD to Local Verification" : "AD to Local Migration")
                    .font(.title2.bold())
                Text("Target User: \(viewModel.user)")
                    .font(.headline)
                    .foregroundStyle(.secondary)
            }
            .padding(.top)

            if !viewModel.steps.isEmpty {
                ProgressView(value: viewModel.progress)
                    .accessibilityLabel("Migration progress")
            }

            Divider()
            content
            Divider()

            if showLog {
                ScrollView {
                    Text(viewModel.log)
                        .font(.system(.caption, design: .monospaced))
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .textSelection(.enabled)
                        .padding(6)
                }
                .frame(height: 150)
                .background(.quaternary.opacity(0.5), in: RoundedRectangle(cornerRadius: 6))
            }

            footer
                .padding(.bottom)
        }
        .padding()
        .frame(minWidth: 500, idealWidth: 500, minHeight: 500, idealHeight: 500)
        .background(WindowAccessor(isBusy: viewModel.isRunning))
        .task {
            await viewModel.prepare()
            if viewModel.autoStart { viewModel.startMigration() }
        }
        .confirmationDialog("Restart this Mac now?", isPresented: $confirmRestart) {
            Button("Restart Now", role: .destructive) { viewModel.restart() }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("Unsaved work in other apps will be lost.")
        }
    }

    // MARK: - Content

    @ViewBuilder
    private var content: some View {
        switch viewModel.phase {
        case .analyzing:
            ProgressView("Analyzing account…")
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        case .clean:
            StatusBanner(
                systemImage: "checkmark.shield.fill", tint: .green,
                title: "Already a Local Account",
                message: "No Active Directory traces were found.\nNothing to change."
            )
            .frame(maxHeight: .infinity)
        case .ready, .running:
            StepListView(steps: viewModel.steps)
        case .completed(let hasWarnings):
            VStack(spacing: 8) {
                StatusBanner(
                    systemImage: hasWarnings ? "exclamationmark.triangle.fill" : "checkmark.shield.fill",
                    tint: hasWarnings ? .orange : .green,
                    title: hasWarnings ? "Completed With Warnings" : "Migration Successful",
                    message: hasWarnings
                        ? "Review the highlighted steps below."
                        : "\(viewModel.user) is now a local account.\nRestart to confirm the login still works."
                )
                StepListView(steps: viewModel.steps)
            }
        case .verified:
            VerificationResultView(findings: viewModel.findings)
        case .failed(let message):
            VStack(spacing: 8) {
                StatusBanner(systemImage: "xmark.octagon.fill", tint: .red, title: "Migration Failed", message: message)
                if !viewModel.steps.isEmpty { StepListView(steps: viewModel.steps) }
            }
        }
    }

    private var footer: some View {
        HStack {
            Button(showLog ? "Hide Log" : "Show Log") { withAnimation { showLog.toggle() } }
            Spacer()
            switch viewModel.phase {
            case .analyzing:
                EmptyView()
            case .ready:
                Button("Start Migration") { viewModel.startMigration() }
                    .buttonStyle(.borderedProminent)
                    .keyboardShortcut(.defaultAction)
            case .running:
                ProgressView().controlSize(.small)
                Text("Processing…").font(.caption)
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

// MARK: - Subviews

struct StepListView: View {
    let steps: [MigrationStep]

    var body: some View {
        ScrollViewReader { proxy in
            ScrollView {
                VStack(alignment: .leading, spacing: 10) {
                    ForEach(steps) { step in
                        StepRow(step: step).id(step.id)
                    }
                }
                .padding()
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
        HStack(alignment: .top, spacing: 8) {
            StatusIndicator(status: step.status)
            VStack(alignment: .leading, spacing: 2) {
                Text(step.name).font(.callout)
                if step.status == .warning || step.status == .failure, !step.outputLog.isEmpty {
                    Text(step.outputLog)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .textSelection(.enabled)
                }
            }
            Spacer()
        }
        .accessibilityElement(children: .combine)
    }
}

struct StatusIndicator: View {
    let status: MigrationStatus

    var body: some View {
        Group {
            switch status {
            case .pending:
                Image(systemName: "circle").foregroundStyle(.secondary)
            case .running:
                ProgressView().controlSize(.small)
            case .success:
                Image(systemName: "checkmark.circle.fill").foregroundStyle(.green)
            case .warning:
                Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.orange)
            case .failure:
                Image(systemName: "xmark.octagon.fill").foregroundStyle(.red)
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

struct StatusBanner: View {
    let systemImage: String
    let tint: Color
    let title: String
    let message: String

    var body: some View {
        VStack(spacing: 6) {
            Image(systemName: systemImage)
                .font(.system(size: 36))
                .foregroundStyle(tint)
                .accessibilityHidden(true)
            Text(title).font(.headline)
            Text(message)
                .font(.callout)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
        }
        .padding(.vertical, 8)
        .frame(maxWidth: .infinity)
        .accessibilityElement(children: .combine)
    }
}

struct VerificationResultView: View {
    let findings: [Finding]

    var body: some View {
        if findings.isEmpty {
            StatusBanner(
                systemImage: "checkmark.shield.fill", tint: .green,
                title: "Matches a Fresh Local Account",
                message: "No Active Directory traces were found."
            )
            .frame(maxHeight: .infinity)
        } else {
            VStack(spacing: 8) {
                StatusBanner(
                    systemImage: "exclamationmark.triangle.fill", tint: .orange,
                    title: "\(findings.count) Difference\(findings.count == 1 ? "" : "s") Found",
                    message: "Nothing was changed."
                )
                ScrollView {
                    VStack(alignment: .leading, spacing: 8) {
                        ForEach(findings, id: \.message) { finding in
                            Label(finding.message, systemImage: "exclamationmark.triangle.fill")
                                .font(.callout)
                                .symbolRenderingMode(.multicolor)
                                .frame(maxWidth: .infinity, alignment: .leading)
                        }
                    }
                    .padding()
                }
            }
        }
    }
}

struct WindowAccessor: NSViewRepresentable {
    /// While the migration runs the window can't be closed, and it stays above other windows.
    let isBusy: Bool

    func makeNSView(context: Context) -> NSView {
        let view = NSView()
        DispatchQueue.main.async { configure(view.window) }
        return view
    }

    func updateNSView(_ nsView: NSView, context: Context) {
        configure(nsView.window)
    }

    private func configure(_ window: NSWindow?) {
        window?.level = .floating
        window?.standardWindowButton(.closeButton)?.isEnabled = !isBusy
    }
}
