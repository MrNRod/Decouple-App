//
//  ContentView.swift
//  ADAccountMigrator
//
//  Created by Noel Rodriguez-Lebron on 12/1/25.
//

import SwiftUI
struct ContentView: View {
    @StateObject private var viewModel = MigrationViewModel()
    @State private var showDetails: Bool = false
    var body: some View {
        VStack(spacing: 20) {
            Text("AD to Local Migration")
                .font(.title).fontWeight(.bold).padding(.top)
            Text("Target User: \(ScriptConfig.User)")
                .font(.headline).foregroundColor(.secondary)
            
            // Progress Bar
            if !viewModel.steps.isEmpty {
                ProgressView(value: viewModel.progress, total: Double(viewModel.steps.count))
                    .padding(.horizontal)
            }
            
            Divider()
            if viewModel.hasError {
                ErrorView(msg: "Please Contact IT Support.\nMigration Failed.")
            } else if viewModel.isComplete {
                SuccessView()
            } else {
                StepListView(steps: viewModel.steps)
            }
            Divider()
            if showDetails {
                ScrollView {
                    Text(viewModel.fullLogText)
                        .font(.custom("Menlo", size: 10))
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .textSelection(.enabled)
                        .padding(5)
                }
                .frame(height: 150)
                .background(Color.black.opacity(0.05))
                .cornerRadius(5)
            }
            HStack {
                Button(showDetails ? "Hide Log" : "Show Log") { withAnimation { showDetails.toggle() } }
                Spacer()
                if !viewModel.isRunning && !viewModel.isComplete && !viewModel.hasError {
                    Button("Start Migration") { viewModel.startMigration() }
                        .buttonStyle(.borderedProminent)
                } else if viewModel.isRunning {
                    ProgressView().scaleEffect(0.7)
                    Text("Processing...").font(.caption)
                } else {
                    Button("Close") { NSApplication.shared.terminate(nil) }
                }
            }
            .padding(.bottom)
        }
        .padding()
        .frame(width: 500, height: 500)
        .interactiveDismissDisabled(viewModel.isRunning)
        .background(WindowAccessor())
        .onAppear {
            // Auto-start migration when the window appears
            viewModel.startMigration()
        }
    }
}
// Subviews
struct StepListView: View {
    let steps: [MigrationStep]
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                ForEach(steps) { step in
                    HStack {
                        StatusIndicator(status: step.status)
                        Text(step.name).font(.system(size: 13))
                        Spacer()
                    }
                }
            }
            .padding()
        }
    }
}
struct StatusIndicator: View {
    let status: MigrationStatus
    var body: some View {
        switch status {
        case .pending: Image(systemName: "circle").foregroundColor(.gray)
        case .running: ProgressView().scaleEffect(0.5)
        case .success: Image(systemName: "checkmark.circle.fill").foregroundColor(.green)
        case .failure: Image(systemName: "xmark.octagon.fill").foregroundColor(.red)
        case .warning: Image(systemName: "exclamationmark.triangle.fill").foregroundColor(.orange)
        }
    }
}
struct ErrorView: View {
    let msg: String
    var body: some View {
        VStack {
            Image(systemName: "exclamationmark.triangle.fill").resizable().frame(width: 40, height: 40).foregroundColor(.red)
            Text(msg).multilineTextAlignment(.center).padding()
        }.frame(maxHeight: 200)
    }
}
struct SuccessView: View {
    var body: some View {
        VStack {
            Image(systemName: "checkmark.shield.fill").resizable().frame(width: 40, height: 45).foregroundColor(.green)
            Text("Migration Successful.\nUser is now Local.").multilineTextAlignment(.center).padding()
        }.frame(maxHeight: 200)
    }
}

struct WindowAccessor: NSViewRepresentable {
    func makeNSView(context: Context) -> NSView {
        let view = NSView()
        DispatchQueue.main.async {
            if let window = view.window {
                window.standardWindowButton(.closeButton)?.isEnabled = false
            }
        }
        return view
    }
    func updateNSView(_ nsView: NSView, context: Context) {}
}
