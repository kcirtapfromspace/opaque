// BonjourDiscovery.swift
// mDNS / Bonjour discovery of local opaqued daemons.

import Foundation
import Network

/// Discovers local opaqued daemons on the network using Bonjour (mDNS).
///
/// The daemon advertises itself as `_opaque._tcp.` on the local network.
/// This class discovers those services and resolves their endpoints.
///
/// Usage:
/// ```swift
/// let discovery = BonjourDiscovery()
/// discovery.onServerFound = { endpoint in
///     print("Found server at \(endpoint)")
/// }
/// discovery.start()
/// ```
final class BonjourDiscovery: ObservableObject {
    /// Discovered opaqued endpoints.
    @Published var discoveredServers: [DiscoveredServer] = []

    /// Callback when a new server is found.
    var onServerFound: ((DiscoveredServer) -> Void)?

    /// The Bonjour service type for opaqued.
    private static let serviceType = "_opaque._tcp."

    /// The NWBrowser for mDNS discovery.
    private var browser: NWBrowser?

    /// A discovered opaqued daemon on the local network.
    struct DiscoveredServer: Identifiable {
        let id: String
        let name: String
        let host: String
        let port: UInt16
    }

    /// Start browsing for opaqued daemons.
    func start() {
        // TODO: Implement NWBrowser-based Bonjour discovery.
        //
        // let params = NWParameters()
        // params.includePeerToPeer = true
        //
        // let browser = NWBrowser(for: .bonjour(type: Self.serviceType, domain: nil), using: params)
        // browser.stateUpdateHandler = { state in
        //     switch state {
        //     case .ready:
        //         print("Bonjour browser ready")
        //     case .failed(let error):
        //         print("Bonjour browser failed: \(error)")
        //     default:
        //         break
        //     }
        // }
        // browser.browseResultsChangedHandler = { results, changes in
        //     for result in results {
        //         // Resolve endpoint and notify
        //     }
        // }
        // browser.start(queue: .main)
        // self.browser = browser
    }

    /// Stop browsing.
    func stop() {
        browser?.cancel()
        browser = nil
    }
}
