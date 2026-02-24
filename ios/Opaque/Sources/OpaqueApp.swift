// OpaqueApp.swift
// Opaque iOS Companion App
//
// Entry point for the SwiftUI application.
// Provides QR-based pairing with the opaqued daemon and Face ID / Touch ID
// approval for sensitive operations.

import SwiftUI

@main
struct OpaqueApp: App {
    @StateObject private var appState = AppState()

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(appState)
        }
    }
}

/// Root content view that switches between pairing and device list.
struct ContentView: View {
    @EnvironmentObject var appState: AppState

    var body: some View {
        NavigationStack {
            if appState.pairedServers.isEmpty {
                PairingView()
            } else {
                DeviceListView()
            }
        }
    }
}

/// Global application state.
///
/// Tracks paired servers and pending approval requests.
class AppState: ObservableObject {
    /// List of servers this device is paired with.
    @Published var pairedServers: [PairedServer] = []

    /// Pending approval requests from paired servers.
    @Published var pendingApprovals: [ApprovalRequest] = []

    init() {
        // TODO: Load paired servers from Keychain/UserDefaults on launch.
        // TODO: Start Bonjour discovery for local servers.
    }

    /// Add a newly paired server.
    func addServer(_ server: PairedServer) {
        pairedServers.append(server)
        // TODO: Persist to Keychain.
    }

    /// Remove a paired server.
    func removeServer(id: String) {
        pairedServers.removeAll { $0.id == id }
        // TODO: Remove from Keychain and revoke device key on server.
    }
}

#if DEBUG
struct ContentView_Previews: PreviewProvider {
    static var previews: some View {
        ContentView()
            .environmentObject(AppState())
    }
}
#endif
