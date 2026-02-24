// DeviceListView.swift
// List of paired servers with pending approval badges.

import SwiftUI

/// Displays paired servers and any pending approval requests.
///
/// Each server row shows:
/// - Server name
/// - Connection status (reachable / unreachable)
/// - Number of pending approvals (badge)
/// - Last used date
struct DeviceListView: View {
    @EnvironmentObject var appState: AppState
    @State private var showingPairingSheet = false

    var body: some View {
        List {
            // Pending approvals section
            if !appState.pendingApprovals.isEmpty {
                Section("Pending Approvals") {
                    ForEach(appState.pendingApprovals) { request in
                        NavigationLink {
                            ApprovalView(request: request) { result in
                                handleApprovalResult(requestId: request.id, result: result)
                            }
                        } label: {
                            ApprovalRow(request: request)
                        }
                    }
                }
            }

            // Paired servers section
            Section("Paired Servers") {
                ForEach(appState.pairedServers) { server in
                    ServerRow(server: server)
                }
                .onDelete(perform: deleteServers)
            }
        }
        .navigationTitle("Opaque")
        .toolbar {
            ToolbarItem(placement: .navigationBarTrailing) {
                Button(action: { showingPairingSheet = true }) {
                    Image(systemName: "plus")
                }
            }
        }
        .sheet(isPresented: $showingPairingSheet) {
            NavigationStack {
                PairingView()
            }
        }
        .refreshable {
            // TODO: Refresh pending approvals from all paired servers.
            // TODO: Check server reachability via Bonjour / direct HTTPS.
        }
    }

    private func deleteServers(at offsets: IndexSet) {
        for index in offsets {
            let server = appState.pairedServers[index]
            appState.removeServer(id: server.id)
        }
    }

    private func handleApprovalResult(requestId: String, result: ApprovalResult) {
        // TODO: Send approval result to daemon.
        // TODO: Remove from pending list on success.
        appState.pendingApprovals.removeAll { $0.id == requestId }
    }
}

/// Row view for a paired server.
private struct ServerRow: View {
    let server: PairedServer

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(server.name)
                .font(.headline)

            HStack {
                Text("ID: \(String(server.id.prefix(8)))...")
                    .font(.caption)
                    .foregroundColor(.secondary)

                Spacer()

                if let lastUsed = server.lastUsed {
                    Text("Last used: \(lastUsed, style: .relative) ago")
                        .font(.caption2)
                        .foregroundColor(.secondary)
                } else {
                    Text("Never used")
                        .font(.caption2)
                        .foregroundColor(.secondary)
                }
            }
        }
        .padding(.vertical, 4)
    }
}

/// Row view for a pending approval request.
private struct ApprovalRow: View {
    let request: ApprovalRequest

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Image(systemName: "exclamationmark.shield.fill")
                    .foregroundColor(.orange)
                Text(request.operationName)
                    .font(.headline)
            }

            Text(request.operationSummary)
                .font(.subheadline)
                .foregroundColor(.secondary)
                .lineLimit(2)

            HStack {
                Image(systemName: "clock")
                    .font(.caption2)
                Text(request.timeRemaining)
                    .font(.caption)
            }
            .foregroundColor(request.isExpired ? .red : .secondary)
        }
        .padding(.vertical, 4)
    }
}

#if DEBUG
struct DeviceListView_Previews: PreviewProvider {
    static var previews: some View {
        NavigationStack {
            DeviceListView()
                .environmentObject({
                    let state = AppState()
                    state.pairedServers = [
                        PairedServer(
                            serverId: "server-001",
                            serverPublicKey: "abcd1234",
                            deviceKeyId: "dev-001",
                            endpoint: "https://192.168.1.100:8443"
                        )
                    ]
                    return state
                }())
        }
    }
}
#endif
