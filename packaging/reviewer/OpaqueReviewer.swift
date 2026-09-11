import AppKit
import Foundation
import Darwin

// The URL is a reference only. Enrollment, executable paths and arguments are
// selected locally, never by a link. Rust validates the same reference again.
struct Notice: Equatable {
    let link: String
    let broker: String
    let id: String
    init?(_ link: String) {
        guard link.utf8.count <= 256, link.hasPrefix("opaque-approval://review/") else { return nil }
        let parts = String(link.dropFirst("opaque-approval://review/".count)).split(separator: "/", omittingEmptySubsequences: false)
        guard parts.count == 2, (1...128).contains(parts[0].utf8.count),
              parts[0].utf8.allSatisfy({ (65...90).contains($0) || (97...122).contains($0) || (48...57).contains($0) || [95,46,58,45].contains($0) }),
              parts[1].count == 36, UUID(uuidString: String(parts[1])) != nil else { return nil }
        self.link = link; broker = String(parts[0]); id = String(parts[1])
    }
}
struct NoticeQueue {
    private(set) var items: [Notice] = []
    private var recent: [String] = []
    mutating func append(_ notice: Notice) -> Bool {
        guard !recent.contains(notice.link), !items.contains(notice), items.count < 16 else { return false }
        items.append(notice); return true
    }
    mutating func finish() {
        guard !items.isEmpty else { return }
        recent.append(items.removeFirst().link)
        if recent.count > 128 { recent.removeFirst() }
    }
}

// This mode never creates NSApplication, accesses custody, runs a subprocess,
// registers a URL handler, opens a window or requests authentication.
if CommandLine.arguments == [CommandLine.arguments[0], "--self-test"] {
    let good = "opaque-approval://review/opq-lab/00000000-0000-4000-8000-000000000001"
    precondition(Notice(good) != nil)
    for bad in [good + "?endpoint=https://evil.test", good + "#token", good + "/extra", good.replacingOccurrences(of: "opq-lab", with: "../../tmp"), "https://evil.test", good + "\n", good.replacingOccurrences(of: "opq-lab", with: String(repeating: "x", count: 129))] {
        precondition(Notice(bad) == nil)
    }
    var queue = NoticeQueue()
    for _ in 0..<100 { _ = queue.append(Notice(good)!) }
    precondition(queue.items.count == 1)
    queue.finish(); precondition(!queue.append(Notice(good)!))
    for _ in 0..<30 { _ = queue.append(Notice("opaque-approval://review/opq-lab/\(UUID().uuidString)")!) }
    precondition(queue.items.count == 16)
    print("reviewer-launcher: strict references, 100 duplicate opens, completed deduplication and 16-item bound passed; native UI not invoked")
    exit(0)
}

final class ReviewerApp: NSObject, NSApplicationDelegate {
    private var window: NSWindow!
    private let status = NSTextField(wrappingLabelWithString: "Choose a trusted custody folder to begin.")
    private let detail = NSTextField(wrappingLabelWithString: "Only a locally enrolled broker can supply review content. Notifications cannot approve work.")
    private let countdown = NSTextField(labelWithString: "No active request")
    private let folder = NSTextField(labelWithString: "No custody selected")
    private let name = NSTextField(string: "Release workstation")
    private let endpoint = NSTextField(string: "")
    private let broker = NSTextField(string: "")
    private let fingerprint = NSTextField(string: "")
    private let publicKey = NSTextField(wrappingLabelWithString: "")
    private var reviewButton: NSButton!
    private var receiptButton: NSButton!
    private var setupButtons: [NSButton] = []
    private var stateDir: String?
    private var queue = NoticeQueue()
    private var active: Notice?
    private var expiry: Double?
    private var verified = false
    private var busy = false
    private var lockFD: Int32 = -1
    private var timer: Timer?

    func applicationDidFinishLaunching(_ notification: Notification) {
        guard ProcessInfo.processInfo.environment["OPAQUE_SESSION_TOKEN"] == nil else { NSApp.terminate(nil); return }
        guard lockInstance() else {
            NSRunningApplication.runningApplications(withBundleIdentifier: "com.opaque.reviewer").first(where: { $0.processIdentifier != getpid() })?.activate()
            NSApp.terminate(nil); return
        }
        buildWindow()
        if let saved = UserDefaults.standard.string(forKey: "trustedCustodyPath") { select(saved) }
        timer = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { [weak self] _ in self?.tick() }
        window.makeKeyAndOrderFront(nil); NSApp.activate(ignoringOtherApps: true)
        inspectNext()
    }
    func application(_ application: NSApplication, open urls: [URL]) {
        for url in urls.prefix(16) {
            if let notice = Notice(url.absoluteString) { _ = queue.append(notice) }
        }
        if window != nil { window.makeKeyAndOrderFront(nil); NSApp.activate(ignoringOtherApps: true); inspectNext() }
    }
    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        window?.makeKeyAndOrderFront(nil); return true
    }
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { false }
    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        if busy { status.stringValue = "Finish the current operation before quitting. Review expires automatically."; window.makeKeyAndOrderFront(nil); return .terminateCancel }
        return .terminateNow
    }
    private func lockInstance() -> Bool {
        let fm = FileManager.default
        let root = fm.homeDirectoryForCurrentUser.appendingPathComponent("Library/Application Support/Opaque Reviewer", isDirectory: true)
        do { try fm.createDirectory(at: root, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700]) } catch { return false }
        var info = stat()
        guard lstat(root.path, &info) == 0, info.st_uid == geteuid(), info.st_mode & 0o077 == 0, info.st_mode & S_IFMT == S_IFDIR else { return false }
        lockFD = open(root.appendingPathComponent("instance.lock").path, O_CREAT | O_RDWR | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard lockFD >= 0, fstat(lockFD, &info) == 0, info.st_uid == geteuid(), info.st_nlink == 1, info.st_mode & 0o077 == 0, info.st_mode & S_IFMT == S_IFREG else { return false }
        return flock(lockFD, LOCK_EX | LOCK_NB) == 0
    }
    private func buildWindow() {
        window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 740, height: 740), styleMask: [.titled, .closable, .miniaturizable, .resizable], backing: .buffered, defer: false)
        window.title = "Opaque Reviewer"; window.minSize = NSSize(width: 740, height: 600); window.center()
        let scroll = NSScrollView(); scroll.hasVerticalScroller = true; scroll.translatesAutoresizingMaskIntoConstraints = false
        window.contentView!.addSubview(scroll)
        NSLayoutConstraint.activate([scroll.leadingAnchor.constraint(equalTo: window.contentView!.leadingAnchor), scroll.trailingAnchor.constraint(equalTo: window.contentView!.trailingAnchor), scroll.topAnchor.constraint(equalTo: window.contentView!.topAnchor), scroll.bottomAnchor.constraint(equalTo: window.contentView!.bottomAnchor)])
        let stack = NSStackView(); stack.orientation = .vertical; stack.alignment = .leading; stack.spacing = 12
        stack.edgeInsets = NSEdgeInsets(top: 28, left: 28, bottom: 28, right: 28)
        stack.translatesAutoresizingMaskIntoConstraints = false
        scroll.documentView = stack
        stack.widthAnchor.constraint(equalTo: scroll.contentView.widthAnchor).isActive = true
        let title = NSTextField(labelWithString: "OPAQUE / REVIEWER")
        title.font = NSFont.monospacedSystemFont(ofSize: 22, weight: .semibold); stack.addArrangedSubview(title)
        let subtitle = NSTextField(wrappingLabelWithString: "Review exact authority. Keep the signing key outside the agent’s account.")
        subtitle.textColor = .secondaryLabelColor; stack.addArrangedSubview(subtitle)
        stack.addArrangedSubview(folder)
        let choose = button("Choose custody folder…", #selector(chooseFolder)); setupButtons.append(choose); stack.addArrangedSubview(choose)
        for (label, field) in [("Workstation name", name), ("Broker HTTPS origin", endpoint), ("Operator-verified broker ID", broker), ("Operator-verified certificate SHA-256", fingerprint)] {
            let row = NSStackView(); row.orientation = .horizontal; row.spacing = 12
            let caption = NSTextField(labelWithString: label); caption.widthAnchor.constraint(equalToConstant: 235).isActive = true
            field.widthAnchor.constraint(equalToConstant: 400).isActive = true
            row.addArrangedSubview(caption); row.addArrangedSubview(field); stack.addArrangedSubview(row)
        }
        let actions = NSStackView()
        for (label, selector) in [("Create workstation key", #selector(initializeKey)), ("Enroll pinned broker", #selector(enroll)), ("Check native capability", #selector(checkNative))] {
            let b = button(label, selector); setupButtons.append(b); actions.addArrangedSubview(b)
        }
        stack.addArrangedSubview(actions)
        publicKey.font = NSFont.monospacedSystemFont(ofSize: 11, weight: .regular); publicKey.isSelectable = true; stack.addArrangedSubview(publicKey)
        let rule = NSBox(); rule.boxType = .separator; rule.widthAnchor.constraint(equalToConstant: 680).isActive = true; stack.addArrangedSubview(rule)
        countdown.font = NSFont.monospacedSystemFont(ofSize: 13, weight: .medium); stack.addArrangedSubview(countdown)
        detail.font = NSFont.systemFont(ofSize: 14); detail.isSelectable = true; stack.addArrangedSubview(detail)
        let decisions = NSStackView()
        reviewButton = button("Review complete task…", #selector(review)); reviewButton.isEnabled = false
        receiptButton = button("Look up decision receipt", #selector(lookup)); receiptButton.isEnabled = false
        decisions.addArrangedSubview(reviewButton); decisions.addArrangedSubview(receiptButton)
        decisions.addArrangedSubview(button("Dismiss notice", #selector(dismissNotice))); stack.addArrangedSubview(decisions)
        status.textColor = .secondaryLabelColor; status.isSelectable = true; stack.addArrangedSubview(status)
        for label in [subtitle, publicKey, detail, status] { label.widthAnchor.constraint(equalTo: stack.widthAnchor, constant: -56).isActive = true }
        let menu = NSMenu(); let item = NSMenuItem(); menu.addItem(item)
        let appMenu = NSMenu(); appMenu.addItem(withTitle: "Quit Opaque Reviewer", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q"); item.submenu = appMenu; NSApp.mainMenu = menu
    }
    private func button(_ title: String, _ selector: Selector) -> NSButton { NSButton(title: title, target: self, action: selector) }
    @objc private func chooseFolder() {
        guard !busy else { return }
        let panel = NSOpenPanel(); panel.canChooseDirectories = true; panel.canChooseFiles = false; panel.canCreateDirectories = true
        panel.message = "Select an existing private enrollment folder, or its parent for a new workstation. The agent must not control this account or these files."
        if panel.runModal() == .OK, let url = panel.url { select(url.path) }
    }
    private func select(_ path: String) {
        stateDir = path; folder.stringValue = path; verified = false; active = nil; expiry = nil
        UserDefaults.standard.set(path, forKey: "trustedCustodyPath")
        publicKey.stringValue = "The public key is printed after creation. Share it with the broker operator; never share custody files."
        inspectNext()
    }
    @objc private func initializeKey() {
        guard !busy, let parent = stateDir else { return }
        let destination = URL(fileURLWithPath: parent).appendingPathComponent("opaque-workstation").path
        run(["init", "--state-dir", destination, "--name", name.stringValue]) { code, value, _ in
            if code == 0, let key = value?["public_key_hex"] as? String {
                self.select(destination); self.publicKey.stringValue = "Public enrollment key:\n\(key)"
                self.status.stringValue = "Ask the operator to allowlist this public key, then enter the independently verified broker details."
            } else { self.status.stringValue = "Key creation failed. Choose an existing private parent folder; existing keys are never overwritten." }
        }
    }
    @objc private func enroll() {
        guard !busy, let state = stateDir else { return }
        run(["enroll", "--state-dir", state, "--broker", endpoint.stringValue, "--broker-id", broker.stringValue, "--tls-fingerprint", fingerprint.stringValue]) { code, _, _ in
            self.status.stringValue = code == 0 ? "Enrolled. Open an opaque notification to queue a task for review." : "Enrollment failed. Verify the allowlisted key, broker ID and certificate fingerprint through the operator’s trusted channel."
            if code == 0 { self.inspectNext() }
        }
    }
    @objc private func checkNative() {
        guard !busy else { return }
        run(["check-native"]) { code, _, _ in self.status.stringValue = code == 0 ? "Native capability available. No review or authentication was performed." : "Native capability unavailable. Check the signed-in desktop session and installed helper." }
    }
    private func inspectNext() {
        guard window != nil, !busy, active == nil, let state = stateDir, let notice = queue.items.first else { return }
        active = notice; verified = false; expiry = nil
        run(["inspect", "--state-dir", state, "--notice", notice.link]) { code, value, _ in
            guard self.active == notice else { return }
            if code == 0, let value, let expires = value["expires_at"] as? Double,
               value["broker_id"] as? String == notice.broker, value["approval_id"] as? String == notice.id {
                self.expiry = expires; self.verified = true
                self.detail.stringValue = "Broker: \(notice.broker)\nOperation: \(value["operation"] as? String ?? "")\nTenant: \(value["tenant"] as? String ?? "Legacy ceremony")\nRequester: \(value["requester"] as? String ?? "See complete review")\nReviewer: \(value["reviewer"] as? String ?? "Enrolled workstation")\nApproval: \(notice.id)"
                self.status.stringValue = "Reference verified against this enrollment. Choose Review to read every action and limit before native authentication."
            } else { self.detail.stringValue = "This notice is unavailable, expired, revoked, or belongs to another enrollment."; self.status.stringValue = "No review or decision occurred. Dismiss it or select its previously enrolled custody folder." }
            self.tick()
        }
    }
    @objc private func review() {
        guard !busy, verified, let notice = active, let state = stateDir, let expiry, expiry > Date().timeIntervalSince1970 else { return }
        run(["open", "--state-dir", state, "--notice", notice.link], timeout: 310) { code, value, _ in
            self.verified = false
            if code == 0, let message = value?["message"] as? String { self.status.stringValue = message }
            else { self.status.stringValue = "Review did not complete. It may have expired or authority may have changed. Read the receipt for this exact round; never infer execution success." }
            self.tick()
        }
    }
    @objc private func lookup() {
        guard !busy, let notice = active, let state = stateDir else { return }
        run(["receipt", "--state-dir", state, "--approval-id", notice.id]) { code, value, _ in
            if code == 0, let response = value?["response"] as? [String: Any], let decision = response["decision"] as? String {
                self.status.stringValue = "Retained signed decision: \(decision). Broker acceptance metadata is not independently signed. Execution outcome remains unobserved here."
            } else { self.status.stringValue = "No verifiable receipt is available through this enrollment. Decision acknowledgment remains unknown; no operation was retried." }
        }
    }
    @objc private func dismissNotice() {
        guard !busy else { return }
        queue.finish(); active = nil; expiry = nil; verified = false
        detail.stringValue = "No active request. Notifications only queue references."; status.stringValue = "Notice dismissed locally; no decision sent."; tick(); inspectNext()
    }
    private func tick() {
        let seconds = expiry.map { max(0, Int(ceil($0 - Date().timeIntervalSince1970))) }
        countdown.stringValue = seconds.map { $0 > 0 ? "\($0)s remaining / \(queue.items.count) queued" : "Expired / a fresh request needs fresh review" } ?? "\(queue.items.count) queued"
        reviewButton?.isEnabled = !busy && verified && (seconds ?? 0) > 0
        receiptButton?.isEnabled = !busy && active != nil
        setupButtons.forEach { $0.isEnabled = !busy }
    }
    private func run(_ arguments: [String], timeout: Double = 55, completion: @escaping (Int32, [String: Any]?, String) -> Void) {
        guard !busy, let executable = Bundle.main.executableURL?.deletingLastPathComponent().appendingPathComponent("opaque-approver") else { return }
        busy = true; tick()
        let process = Process(); process.executableURL = executable; process.arguments = arguments
        let pipe = Pipe(); process.standardOutput = pipe; process.standardError = pipe; process.standardInput = FileHandle.nullDevice
        process.environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "en_US.UTF-8"]
        do { try process.run() } catch { busy = false; tick(); completion(-1, nil, ""); return }
        DispatchQueue.global().asyncAfter(deadline: .now() + timeout) { if process.isRunning { process.terminate() } }
        DispatchQueue.global().async {
            var data = Data()
            while true {
                let chunk = pipe.fileHandleForReading.readData(ofLength: 4096)
                if chunk.isEmpty { break }
                if data.count + chunk.count > 262144 { process.terminate(); break }
                data.append(chunk)
            }
            process.waitUntilExit()
            let text = String(data: data, encoding: .utf8) ?? ""
            // Init/inspect/decision output is one JSON line; receipt is pretty JSON.
            let json = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
                ?? text.split(separator: "\n").reversed().compactMap { line -> [String: Any]? in
                    (try? JSONSerialization.jsonObject(with: Data(line.utf8))) as? [String: Any]
                }.first
            DispatchQueue.main.async { self.busy = false; self.tick(); completion(process.terminationStatus, json, text) }
        }
    }
}

let app = NSApplication.shared
let delegate = ReviewerApp()
app.delegate = delegate
app.setActivationPolicy(.regular)
app.run()
