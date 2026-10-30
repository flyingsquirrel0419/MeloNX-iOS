//
//  NativePrepSheet.swift
//  MeloNX
//
//  Prepares a game for native mode (NativePrep) and shows its stages and log; the log can be shared, as the test builds need it back.
//

import SwiftUI

@available(iOS 16.0, *)
struct NativePrepSheet: View {
    let game: GameInfo
    @Environment(\.dismiss) private var dismiss

    @State private var running = false
    @State private var stage: NativePrepStage?
    @State private var fraction = 0.0
    @State private var log: [String] = []
    @State private var error: String?
    @State private var finished = false

    private var profile: NativeProfile? { NativePrep.profile(for: game.titleId) }

    var body: some View {
        NavigationStack {
            List {
                Section {
                    LabeledContent("Profile", value: profile?.name ?? "none")
                    LabeledContent("Title ID", value: game.titleId.uppercased())
                    LabeledContent("Prepared", value: NativePrep.isPrepared(game.titleId) ? "yes" : "no")
                }

                Section {
                    if running, let stage {
                        VStack(alignment: .leading, spacing: 6) {
                            Text(stageTitle(stage))
                            ProgressView(value: fraction)
                        }
                    } else if finished {
                        Label(error == nil ? "Done" : "Failed: \(error!)", systemImage: error == nil ? "checkmark.circle" : "xmark.octagon")
                            .foregroundStyle(error == nil ? .green : .red)
                    }
                    Button {
                        start()
                    } label: {
                        Label(NativePrep.isPrepared(game.titleId) ? "Prepare Again" : "Prepare", systemImage: "hammer")
                    }
                    .disabled(running || profile == nil)
                } footer: {
                    Text("Extracts the game's code and files with your keys and rewrites the code for native mode, into Documents/NativeGames. Keep the app open until it is done.")
                }

                if !log.isEmpty {
                    Section("Log") {
                        ForEach(Array(log.enumerated()), id: \.offset) { _, line in
                            Text(line)
                                .font(.caption.monospaced())
                                .foregroundStyle(line.hasPrefix("[RED]") ? .red : .primary)
                                .textSelection(.enabled)
                        }
                    }
                }
            }
            .navigationTitle("Native Mode")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Close") { dismiss() }.disabled(running)
                }
                ToolbarItem(placement: .primaryAction) {
                    ShareLink(item: log.joined(separator: "\n")) {
                        Image(systemName: "square.and.arrow.up")
                    }
                    .disabled(log.isEmpty)
                }
            }
        }
        .interactiveDismissDisabled(running)
    }

    private func stageTitle(_ stage: NativePrepStage) -> String {
        switch stage {
        case .identify: return "Reading the game file"
        case .extract: return "Extracting (\(Int(fraction * 100))%)"
        case .rewrite: return "Rewriting the code (\(Int(fraction * 100))%)"
        }
    }

    private func start() {
        running = true
        finished = false
        error = nil
        log = []
        UIApplication.shared.isIdleTimerDisabled = true
        NativePrep.prepare(gameURL: game.fileURL) { line in
            log.append(line)
        } onStage: { s, f in
            stage = s
            fraction = f
        } completion: { err in
            UIApplication.shared.isIdleTimerDisabled = false
            error = err
            running = false
            finished = true
        }
    }
}
