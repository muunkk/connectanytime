// ConnectAnytime: a menu-bar Connect/Disconnect for Cisco Secure Client.
// Drives Cisco's own CLI over a pty; the password goes Keychain -> pty, nowhere else.
import AppKit
import CryptoKit
import Network
import Security
import ServiceManagement
import UserNotifications

let vpnPath = "/opt/cisco/secureclient/bin/vpn"
let ciscoGUIBundleID = "com.cisco.secureclient.gui"
let keychainService = "connectanytime"
let connectTimeout: TimeInterval = 120
let logPath = NSHomeDirectory() + "/Library/Logs/ConnectAnytime.log"
/// Local-only command channel (used by the Raycast script). Web pages can't post these,
/// unlike a URL scheme.
let commandNotification = Notification.Name("local.connectanytime.command")
let commands = ["connect", "disconnect", "toggle"]

/// Appends to ~/Library/Logs/ConnectAnytime.log. Never pass it anything typed into the CLI.
func log(_ message: String) {
    let line = "\(ISO8601DateFormatter().string(from: Date())) \(message)\n"
    if let h = FileHandle(forWritingAtPath: logPath) {
        h.seekToEndOfFile(); h.write(Data(line.utf8)); try? h.close()
    } else {
        FileManager.default.createFile(atPath: logPath, contents: Data(line.utf8), attributes: [.posixPermissions: 0o600])
    }
}

// MARK: - Settings (host + username from Cisco's own saved preferences)

struct Prefs {
    var host = "vpn.shanghai.nyu.edu"
    var user = "" // read from Cisco's prefs; never hard-coded

    static func load() -> Prefs {
        var p = Prefs()
        let path = NSHomeDirectory() + "/.vpn/.anyconnect"
        guard let xml = try? String(contentsOfFile: path, encoding: .utf8) else { return p }
        func tag(_ name: String) -> String? {
            guard let r = xml.range(of: "(?<=<\(name)>)[^<]+", options: .regularExpression) else { return nil }
            return String(xml[r])
        }
        if let h = serverAddress(name: tag("DefaultHostName"), address: tag("DefaultHostAddress"), profiles: ciscoProfiles()) { p.host = h }
        if let u = tag("DefaultUser") { p.user = u }
        return p
    }
}

/// Cisco saves the server you picked by its display name when it comes from a VPN profile
/// (e.g. "3 - Shanghai VPN"), which the CLI can't connect to. Resolve it to the address.
func serverAddress(name: String?, address: String?, profiles: [String]) -> String? {
    func trimmed(_ s: String?) -> String? {
        s.map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }.flatMap { $0.isEmpty ? nil : $0 }
    }
    if let address = trimmed(address) { return address }
    guard let name = trimmed(name) else { return nil }
    for xml in profiles {
        for entry in xml.components(separatedBy: "<HostEntry>").dropFirst() {
            func field(_ tag: String) -> String? {
                trimmed(entry.range(of: "(?<=<\(tag)>)[^<]+", options: .regularExpression).map { String(entry[$0]) })
            }
            if field("HostName") == name { return field("HostAddress") ?? name }
        }
    }
    return name.contains(where: \.isWhitespace) ? nil : name
}

/// VPN profiles installed by the organisation (XML), used to look up server addresses.
func ciscoProfiles() -> [String] {
    let dir = "/opt/cisco/secureclient/vpn/profile"
    let files = (try? FileManager.default.contentsOfDirectory(atPath: dir)) ?? []
    return files.filter { $0.hasSuffix(".xml") }.compactMap { try? String(contentsOfFile: dir + "/" + $0, encoding: .utf8) }
}

// MARK: - Keychain

enum Keychain {
    static func read(account: String) -> String? {
        let q: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
        ]
        var out: AnyObject?
        guard SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess, let d = out as? Data else { return nil }
        return String(data: d, encoding: .utf8)
    }

    @discardableResult
    static func save(_ password: String, account: String) -> Bool {
        let base: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: account,
        ]
        SecItemDelete(base as CFDictionary)
        var add = base
        add[kSecValueData as String] = Data(password.utf8)
        add[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        return SecItemAdd(add as CFDictionary, nil) == errSecSuccess
    }
}

// MARK: - One-shot CLI calls (state, disconnect)

@discardableResult
func runVPN(_ args: [String]) -> String { run(vpnPath, args) }

/// Cisco's state as of now, e.g. "Connected"; "Unknown" if the CLI didn't say.
func currentVPNState() -> String { parseState(runVPN(["state"])) ?? "Unknown" }

/// Runs a command and returns its output. Killed after `timeout` seconds (nil: never), so a
/// stuck CLI can't leave the menu stuck on "Disconnecting…".
@discardableResult
func run(_ path: String, _ args: [String], timeout: TimeInterval? = 30) -> String {
    let p = Process()
    p.executableURL = URL(fileURLWithPath: path)
    p.arguments = args
    let pipe = Pipe()
    p.standardOutput = pipe
    p.standardError = pipe
    p.standardInput = FileHandle.nullDevice
    // Read until EOF in the background, and give output and exit one shared deadline, so it
    // holds whether the command hangs, closes its output and then hangs, or leaves a process
    // behind that keeps the pipe open.
    var data = Data()
    let lock = NSLock(), eof = DispatchSemaphore(value: 0), exited = DispatchSemaphore(value: 0)
    let reader = pipe.fileHandleForReading
    reader.readabilityHandler = { h in
        let chunk = h.availableData
        if chunk.isEmpty { h.readabilityHandler = nil; eof.signal() }
        else { lock.lock(); data.append(chunk); lock.unlock() }
    }
    p.terminationHandler = { _ in exited.signal() }
    guard (try? p.run()) != nil else { reader.readabilityHandler = nil; return "" }
    let deadline: DispatchTime = timeout.map { .now() + $0 } ?? .distantFuture
    var timedOut = false
    if eof.wait(timeout: deadline) == .timedOut || exited.wait(timeout: deadline) == .timedOut {
        timedOut = true
        log("run: \(path) timed out")
        reader.readabilityHandler = nil
        p.terminate() // Foundation signals only its own, still-unreaped child
        for _ in 0..<20 where p.isRunning { usleep(100_000) }
        if p.isRunning { kill(p.processIdentifier, SIGKILL) } // ignored SIGTERM
    }
    p.waitUntilExit()
    if timedOut { return "" } // partial output isn't trusted, e.g. a state printed before a hang
    lock.lock(); defer { lock.unlock() }
    return String(decoding: data, as: UTF8.self)
}

/// Last ">> state: X" line, e.g. "Connected", "Disconnected", "Reconnecting".
func parseState(_ output: String) -> String? {
    let lines = output.components(separatedBy: .newlines)
    for line in lines.reversed() {
        if let r = line.range(of: "(?<=>> state: )\\w+", options: .regularExpression) { return String(line[r]) }
    }
    return nil
}

// MARK: - Network identity (no Location permission needed)

struct SavedNetwork: Codable {
    var name: String
    var router: String // router hardware address
}

/// Hardware address of the default router on `interface`, e.g. "00:11:22:33:44:55".
/// Stands in for the Wi-Fi name, which macOS hides without Location access.
func routerAddress(on interface: String) -> String? {
    let route = run("/sbin/route", ["-n", "get", "-ifscope", interface, "default"])
    guard let gw = route.range(of: "(?<=gateway: )\\S+", options: .regularExpression).map({ String(route[$0]) }) else { return nil }
    run("/sbin/ping", ["-c", "1", "-t", "1", gw]) // make sure the router is in the ARP table
    let arp = run("/usr/sbin/arp", ["-n", gw])
    return arp.range(of: "(?<= at )[0-9a-f]{1,2}(:[0-9a-f]{1,2}){5}", options: .regularExpression).map { String(arp[$0]) }
}

/// A host route to the VPN server through a router other than the current one.
/// Cisco pins the server to the router it connected through; an interrupted reconnect
/// can leave that route behind after a network change, and then the server is unreachable.
/// Returns the route's destination address.
func staleServerRoute(_ host: String) -> String? {
    func field(_ out: String, _ name: String) -> String? {
        out.range(of: "(?<=\(name): )\\S+", options: .regularExpression).map { String(out[$0]) }
    }
    let server = run("/sbin/route", ["-n", "get", String(host.split(separator: "/").first ?? "")])
    let current = run("/sbin/route", ["-n", "get", "default"])
    guard let dest = field(server, "destination"), dest.range(of: "^\\d{1,3}(\\.\\d{1,3}){3}$", options: .regularExpression) != nil,
          let gw = field(server, "gateway"), let currentGW = field(current, "gateway"), gw != currentGW else { return nil }
    return dest
}

/// Deletes the route after the standard macOS admin password prompt.
func removeRoute(_ dest: String) {
    let script = "do shell script \"/sbin/route -n delete \(dest)\" with prompt \"ConnectAnytime needs to remove a stale route to the VPN server.\" with administrator privileges"
    run("/usr/bin/osascript", ["-e", script], timeout: nil) // waits for the admin password
}

// MARK: - Interactive connect

/// Runs `vpn` interactively on a pty and answers each prompt exactly once.
/// Any repeated or unknown-order prompt aborts, so a bad password is never retried.
final class ConnectSession {
    enum Outcome { case connected, failed(String) }

    private let host: String, user: String, password: String
    private let onDuo: () -> Void
    private let onStopping: () -> Void
    private let onDone: (Outcome) -> Void
    private let queue = DispatchQueue(label: "connectanytime.session")
    private let process = Process()
    private var master: Int32 = -1
    private var source: DispatchSourceRead?
    private var buffer = ""
    private var lineBuffer = ""
    private var answered = Set<String>()
    private var finished = false
    private var answeredDuoNotice = false

    init(host: String, user: String, password: String,
         onDuo: @escaping () -> Void, onStopping: @escaping () -> Void, onDone: @escaping (Outcome) -> Void) {
        self.host = host; self.user = user; self.password = password
        self.onDuo = onDuo; self.onStopping = onStopping; self.onDone = onDone
    }

    func start() {
        queue.async { self.launch() }
    }

    private func launch() {
        var m: Int32 = 0, s: Int32 = 0
        guard openpty(&m, &s, nil, nil, nil) == 0 else { return finish(.failed("Could not open a pty.")) }
        var t = termios()
        tcgetattr(s, &t)
        t.c_lflag &= ~tcflag_t(ECHO) // never echo what we type, password included
        tcsetattr(s, TCSANOW, &t)
        master = m

        let slave = FileHandle(fileDescriptor: s, closeOnDealloc: true)
        process.executableURL = URL(fileURLWithPath: vpnPath)
        process.standardInput = slave
        process.standardOutput = slave
        process.standardError = slave
        process.terminationHandler = { [weak self] _ in
            self?.queue.async { self?.finish(.failed("The VPN client exited unexpectedly.")) }
        }
        do { try process.run() } catch { return finish(.failed("Could not start \(vpnPath).")) }
        try? slave.close()
        log("session: started vpn pid \(process.processIdentifier)")

        let src = DispatchSource.makeReadSource(fileDescriptor: m, queue: queue)
        src.setEventHandler { [weak self] in
            guard let self else { return }
            var buf = [UInt8](repeating: 0, count: 4096)
            let n = read(m, &buf, buf.count)
            if n <= 0 { self.source?.cancel(); return }
            self.feed(String(decoding: buf[0..<n], as: UTF8.self))
        }
        src.resume()
        source = src

        queue.asyncAfter(deadline: .now() + connectTimeout) { [weak self] in
            self?.finish(.failed("Timed out (Duo not approved?)."))
        }
    }

    /// Process id of the running CLI, for cleanup on app quit.
    var pid: Int32 { process.isRunning ? process.processIdentifier : 0 }

    func cancel() {
        queue.async { self.finish(.failed("Cancelled.")) }
    }

    private func feed(_ text: String) {
        guard !finished else { return }
        let clean = text.replacingOccurrences(of: "\r", with: "")
        buffer += clean
        logStatusLines(clean)

        if buffer.contains(">> state: Connected") { return finish(.connected) }
        if let line = firstLine(containing: ["Login failed", ">> error:"]) { return finish(.failed(line)) }

        if !answered.contains("connect"), buffer.contains("registered with local VPN subsystem") {
            return answer("connect", "connect \(host)")
        }
        // Only answer the prompt the CLI is currently waiting on (the end of its output).
        // Order matters: "Second Password:" also ends with "Password:".
        let tail = buffer.trimmingCharacters(in: .whitespaces)
        // Some accounts get NYU's Duo notice as the prompt, with no "Second Password:" label.
        if buffer.trimmingCharacters(in: .whitespacesAndNewlines).hasSuffix("The second password uses DUO for MFA") {
            answeredDuoNotice = true
            onDuo(); return answer("second", "push")
        }
        if tail.hasSuffix("Second Password:") {
            // A label right after the notice is the same prompt; the "push" already sent answers it.
            if answeredDuoNotice { answeredDuoNotice = false; buffer = ""; return }
            onDuo(); return answer("second", "push")
        }
        if tail.hasSuffix("Password:") { return answer("password", password) }
        if tail.range(of: "Username:( \\[[^\\]]*\\])?$", options: .regularExpression) != nil {
            return answer("username", user)
        }
        if tail.hasSuffix("accept? [y/n]:") { return answer("banner", "y") }
    }

    /// Logs only Cisco's own ">>" / "**" status lines, never echoed input.
    private func logStatusLines(_ text: String) {
        lineBuffer += text
        var lines = lineBuffer.components(separatedBy: "\n")
        lineBuffer = lines.removeLast()
        for l in lines {
            let t = l.trimmingCharacters(in: .whitespaces)
            if t.hasPrefix(">>") || t.hasPrefix("**") || t.hasPrefix("VPN> >>") { log("cli: \(t)") }
        }
    }

    private func answer(_ key: String, _ line: String) {
        guard !answered.contains(key) else {
            return finish(.failed("Asked for \(key) twice. Check your saved password."))
        }
        answered.insert(key)
        buffer = ""
        log("session: answered \(key) prompt")
        send(line)
    }

    private func send(_ line: String) {
        let bytes = Array((line + "\n").utf8)
        _ = bytes.withUnsafeBytes { write(master, $0.baseAddress, $0.count) }
    }

    private func firstLine(containing needles: [String]) -> String? {
        buffer.components(separatedBy: "\n").first { l in needles.contains { l.contains($0) } }?
            .trimmingCharacters(in: .whitespaces)
    }

    private func finish(_ outcome: Outcome) {
        guard !finished else { return }
        finished = true
        DispatchQueue.main.async { self.onStopping() } // Cancel does nothing from here on
        switch outcome {
        case .connected: log("session: connected")
        case .failed(let why): log("session: failed after \(answered.sorted()) - \(why)")
        }
        if process.isRunning {
            if case .connected = outcome { send("quit") } // leaves the tunnel up
            else { kill(process.processIdentifier, SIGKILL) } // must not keep holding the connect slot
        }
        if case .failed = outcome, answered.contains("connect") {
            runVPN(["disconnect"]) // reset any half-open attempt
        }
        queue.asyncAfter(deadline: .now() + 1) { [self] in
            source?.cancel()
            if process.isRunning { kill(process.processIdentifier, SIGKILL) }
            if master >= 0 { close(master); master = -1 }
        }
        DispatchQueue.main.async { self.onDone(outcome) }
    }
}

// MARK: - Updates (GitHub releases, no update framework)

let latestReleaseAPI = URL(string: "https://api.github.com/repos/muunkk/connectanytime/releases/latest")!
let releaseDownloadPrefix = "https://github.com/muunkk/connectanytime/releases/download/"

struct Release {
    var version: String
    var zip: URL
    var sha256: String // published by GitHub for the asset
    var notes: String // Markdown body from the GitHub release
}

private struct GitHubRelease: Decodable {
    struct Asset: Decodable { let name: String; let browser_download_url: URL; let digest: String? }
    let tag_name: String
    let body: String?
    let assets: [Asset]
}

/// Numeric dotted versions: "0.1.10" is newer than "0.1.9".
func isVersion(_ a: String, newerThan b: String) -> Bool {
    let x = a.split(separator: ".").map { Int($0) ?? 0 }, y = b.split(separator: ".").map { Int($0) ?? 0 }
    for i in 0..<max(x.count, y.count) where (i < x.count ? x[i] : 0) != (i < y.count ? y[i] : 0) {
        return (i < x.count ? x[i] : 0) > (i < y.count ? y[i] : 0)
    }
    return false
}

func fetchLatestRelease() async throws -> Release {
    var req = URLRequest(url: latestReleaseAPI, timeoutInterval: 20)
    req.setValue("application/vnd.github+json", forHTTPHeaderField: "Accept")
    let (data, resp) = try await URLSession.shared.data(for: req)
    guard (resp as? HTTPURLResponse)?.statusCode == 200 else { throw UpdateError("GitHub didn't answer. Try again later.") }
    let r = try JSONDecoder().decode(GitHubRelease.self, from: data)
    let version = r.tag_name.hasPrefix("v") ? String(r.tag_name.dropFirst()) : r.tag_name
    guard version.range(of: "^\\d+(\\.\\d+)*$", options: .regularExpression) != nil,
          let asset = r.assets.first(where: { $0.name == "ConnectAnytime.zip" }),
          asset.browser_download_url.absoluteString.hasPrefix(releaseDownloadPrefix),
          let digest = asset.digest, digest.range(of: "^sha256:[0-9a-f]{64}$", options: .regularExpression) != nil
    else { throw UpdateError("The latest release doesn't have a verifiable ConnectAnytime.zip.") }
    return Release(version: version, zip: asset.browser_download_url, sha256: String(digest.dropFirst(7)),
                   notes: r.body?.trimmingCharacters(in: .whitespacesAndNewlines) ?? "")
}

struct UpdateError: LocalizedError {
    let errorDescription: String?
    init(_ message: String) { errorDescription = message }
}

/// Code-signing requirement for updates: Apple-issued Developer ID certificate of our team.
let updateRequirement = #"anchor apple generic and identifier "local.connectanytime" and certificate leaf[subject.OU] = "GSDM59X25M""#

/// Downloads and checks the release, then swaps it in for the running app.
/// The zip must match GitHub's SHA-256 for it; the app inside must have our bundle ID, the
/// release's version and an intact code signature from our Developer ID. Nothing is replaced
/// unless all pass.
func installUpdate(_ release: Release) async throws {
    let (download, _) = try await URLSession.shared.download(from: release.zip)
    defer { try? FileManager.default.removeItem(at: download) }
    let hash = SHA256.hash(data: try Data(contentsOf: download)).map { String(format: "%02x", $0) }.joined()
    guard hash == release.sha256 else { throw UpdateError("The download didn't match GitHub's checksum.") }

    let dir = FileManager.default.temporaryDirectory.appendingPathComponent("ConnectAnytime-update-\(UUID().uuidString)")
    defer { try? FileManager.default.removeItem(at: dir) }
    guard succeeds("/usr/bin/ditto", ["-x", "-k", download.path, dir.path]) else { throw UpdateError("Couldn't unzip the update.") }

    let newApp = dir.appendingPathComponent("ConnectAnytime.app")
    guard let info = Bundle(url: newApp)?.infoDictionary,
          info["CFBundleIdentifier"] as? String == Bundle.main.bundleIdentifier,
          let version = info["CFBundleShortVersionString"] as? String,
          !isVersion(version, newerThan: release.version), !isVersion(release.version, newerThan: version),
          succeeds("/usr/bin/codesign", ["--verify", "--deep", "--strict", "-R=\(updateRequirement)", newApp.path])
    else { throw UpdateError("The update didn't pass its checks.") }

    _ = try FileManager.default.replaceItemAt(Bundle.main.bundleURL, withItemAt: newApp)
}

/// Starts the app again once this process has exited.
func relaunchAfterExit() {
    let p = Process()
    p.executableURL = URL(fileURLWithPath: "/bin/sh")
    p.arguments = ["-c", "while kill -0 \"$1\" 2>/dev/null; do sleep 0.2; done; /usr/bin/open \"$2\"", "sh",
                   String(ProcessInfo.processInfo.processIdentifier), Bundle.main.bundlePath]
    try? p.run()
}

func succeeds(_ path: String, _ args: [String]) -> Bool {
    let p = Process()
    p.executableURL = URL(fileURLWithPath: path)
    p.arguments = args
    p.standardOutput = FileHandle.nullDevice
    p.standardError = FileHandle.nullDevice
    guard (try? p.run()) != nil else { return false }
    p.waitUntilExit()
    return p.terminationStatus == 0
}

/// A small native release-notes panel for the update alert. GitHub's common headings,
/// bullets and inline Markdown are made readable without embedding a web view.
func releaseNotesView(_ markdown: String) -> NSView? {
    guard !markdown.isEmpty else { return nil }

    let width: CGFloat = 440, notesHeight: CGFloat = 170, headingHeight: CGFloat = 20
    let container = NSView(frame: NSRect(x: 0, y: 0, width: width, height: headingHeight + 8 + notesHeight))
    let heading = NSTextField(labelWithString: "What’s New")
    heading.font = .boldSystemFont(ofSize: NSFont.systemFontSize)
    heading.frame = NSRect(x: 0, y: notesHeight + 8, width: width, height: headingHeight)

    let scroll = NSScrollView(frame: NSRect(x: 0, y: 0, width: width, height: notesHeight))
    scroll.borderType = .bezelBorder
    scroll.hasVerticalScroller = true
    scroll.autohidesScrollers = true

    let text = NSTextView(frame: NSRect(origin: .zero, size: scroll.contentSize))
    text.isEditable = false
    text.isSelectable = true
    text.drawsBackground = false
    text.textContainerInset = NSSize(width: 8, height: 8)
    text.isHorizontallyResizable = false
    text.isVerticallyResizable = true
    text.autoresizingMask = [.width]
    text.textContainer?.widthTracksTextView = true
    text.textContainer?.containerSize = NSSize(width: scroll.contentSize.width, height: .greatestFiniteMagnitude)
    text.linkTextAttributes = [.foregroundColor: NSColor.linkColor, .underlineStyle: NSUnderlineStyle.single.rawValue]
    text.textStorage?.setAttributedString(formatReleaseNotes(markdown))
    scroll.documentView = text

    container.addSubview(heading)
    container.addSubview(scroll)
    return container
}

func formatReleaseNotes(_ markdown: String) -> NSAttributedString {
    let result = NSMutableAttributedString()
    let body = NSFont.systemFont(ofSize: NSFont.systemFontSize)
    let heading = NSFont.boldSystemFont(ofSize: NSFont.systemFontSize + 1)

    func append(_ source: String, font: NSFont) {
        let parsed = try? AttributedString(markdown: source,
            options: .init(interpretedSyntax: .inlineOnlyPreservingWhitespace))
        let text = parsed.map(NSAttributedString.init) ?? NSAttributedString(string: source)
        let styled = NSMutableAttributedString(attributedString: text)
        let all = NSRange(location: 0, length: styled.length)
        styled.addAttributes([.font: font, .foregroundColor: NSColor.labelColor], range: all)
        // The parser marks **bold**, *italic*, `code` and ~~struck~~ spans but sets no fonts.
        styled.enumerateAttribute(.inlinePresentationIntent, in: all) { value, range, _ in
            guard let raw = (value as? NSNumber)?.uintValue else { return }
            let intent = InlinePresentationIntent(rawValue: raw)
            var traits: NSFontDescriptor.SymbolicTraits = []
            if intent.contains(.stronglyEmphasized) { traits.insert(.bold) }
            if intent.contains(.emphasized) { traits.insert(.italic) }
            let base = intent.contains(.code) ? NSFont.monospacedSystemFont(ofSize: font.pointSize, weight: .regular) : font
            let descriptor = base.fontDescriptor.withSymbolicTraits(base.fontDescriptor.symbolicTraits.union(traits))
            styled.addAttribute(.font, value: NSFont(descriptor: descriptor, size: base.pointSize) ?? base, range: range)
            if intent.contains(.strikethrough) {
                styled.addAttribute(.strikethroughStyle, value: NSUnderlineStyle.single.rawValue, range: range)
            }
        }
        result.append(styled)
    }

    let lines = markdown.split(separator: "\n", omittingEmptySubsequences: false)
    for (index, raw) in lines.enumerated() {
        let line = String(raw)
        let trimmed = line.trimmingCharacters(in: .whitespaces)
        let headingMarks = trimmed.prefix(while: { $0 == "#" })
        let afterHeading = trimmed.dropFirst(headingMarks.count)
        if (1...6).contains(headingMarks.count), afterHeading.first?.isWhitespace == true {
            append(afterHeading.drop(while: { $0.isWhitespace }).description, font: heading)
        } else if trimmed.hasPrefix("- ") || trimmed.hasPrefix("* ") {
            append("• " + String(trimmed.dropFirst(2)), font: body)
        } else {
            append(line, font: body)
        }
        if index < lines.count - 1 {
            result.append(NSAttributedString(string: "\n", attributes: [.font: body]))
        }
    }
    return result
}

// MARK: - App

final class App: NSObject, NSApplicationDelegate, NSMenuDelegate {
    let item = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
    let menu = NSMenu()
    let prefs = Prefs.load()
    var state = "Unknown"
    var busy: String?
    var session: ConnectSession?
    let pathMonitor = NWPathMonitor()
    var networkCheck: DispatchWorkItem?
    var currentRouter: String?
    var availableUpdate: Release?
    /// The release being installed. Kept apart from `busy`, which is only about the VPN.
    var updating: Release?
    /// A manual update check is running (its row reads "Checking for Updates…").
    var checkingForUpdates = false
    /// Numbers update checks; only the latest one's result is used.
    var updateCheck = 0
    /// Changes when a VPN operation starts or ends; a state check from an earlier one is dropped.
    var operationEpoch = 0
    /// State checks are numbered so an older one finishing late can't undo a newer one.
    var lastCheckStarted = 0, lastCheckApplied = 0
    /// A connect or disconnect started since the last network change. It counts as that
    /// network's one attempt, so auto-connect doesn't follow it.
    var actedSinceNetworkChange = false

    var isConnected: Bool { state == "Connected" }
    /// Connected or on the way there, including Cisco's own reconnects after a network change.
    var isActive: Bool { !["Disconnected", "Unknown"].contains(state) }

    var savedNetworks: [SavedNetwork] {
        get {
            guard let d = UserDefaults.standard.data(forKey: "autoConnectNetworks") else { return [] }
            return (try? JSONDecoder().decode([SavedNetwork].self, from: d)) ?? []
        }
        set { UserDefaults.standard.set(try? JSONEncoder().encode(newValue), forKey: "autoConnectNetworks") }
    }

    func applicationDidFinishLaunching(_ n: Notification) {
        // Restarted by an update: the network it was on isn't a fresh join to auto-connect on.
        currentRouter = UserDefaults.standard.string(forKey: "routerBeforeUpdate")
        UserDefaults.standard.removeObject(forKey: "routerBeforeUpdate")
        menu.delegate = self
        item.menu = menu
        render()
        refresh()
        Timer.scheduledTimer(withTimeInterval: 10, repeats: true) { [weak self] _ in self?.refresh() }
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound]) { ok, _ in
            log("app: notifications \(ok ? "allowed" : "not allowed")")
        }
        log("app: launched")
        listenForCommands()
        watchNetwork()
        checkForUpdatesQuietly()
        Timer.scheduledTimer(withTimeInterval: 24 * 60 * 60, repeats: true) { [weak self] _ in self?.checkForUpdatesQuietly() }
    }

    func applicationWillTerminate(_ n: Notification) {
        if let pid = session?.pid, pid > 0 { kill(pid, SIGKILL) }
    }

    // Sent by `ConnectAnytime --connect | --disconnect | --toggle` (the Raycast script).
    func listenForCommands() {
        DistributedNotificationCenter.default().addObserver(forName: commandNotification, object: nil, queue: .main) { [weak self] n in
            guard let self, let cmd = n.object as? String else { return }
            log("app: command \(cmd)")
            // Disconnect needs no state, and starting it now beats an auto-connect check in flight.
            if cmd == "disconnect" { return disconnect() }
            run(command: cmd)
        }
    }

    func menuNeedsUpdate(_ menu: NSMenu) {
        refresh()
        buildMenu()
    }

    /// Runs a command on Cisco's current state, not the last poll. A connect or disconnect
    /// that starts or ends meanwhile drops the command.
    func run(command cmd: String) {
        checkState { s in
            guard let s else { return log("app: command \(cmd) dropped, the VPN state changed") }
            switch cmd {
            case "connect": self.connect()
            case "toggle" where s == "Unknown":
                self.notify("Couldn't read the VPN state", "Choose Connect or Disconnect in the menu.")
            case "toggle": self.isActive ? self.disconnect() : self.connect()
            default: break
            }
        }
    }

    // MARK: State

    func refresh() { checkState { _ in } }

    /// Checks Cisco's state off the main thread, applies it, and calls `done` on the main
    /// thread with it. Calls `done` with nil instead if a VPN operation is running or started
    /// or ended meanwhile. If a newer check got in first, `done` gets its result.
    /// A non-nil result is always `state`.
    func checkState(_ done: @escaping (String?) -> Void) {
        guard busy == nil else { return done(nil) }
        lastCheckStarted += 1
        let check = lastCheckStarted, epoch = operationEpoch
        DispatchQueue.global().async {
            let s = currentVPNState()
            DispatchQueue.main.async {
                guard self.busy == nil, epoch == self.operationEpoch else { return done(nil) }
                // An older check finishing late can't undo a newer one.
                guard check > self.lastCheckApplied else { return done(self.state) }
                self.lastCheckApplied = check
                if s != self.state { self.state = s; self.render() } // unchanged: leave the open menu alone
                done(s)
            }
        }
    }

    func render() {
        let symbol: String
        if isConnected && busy == nil { symbol = "network" }
        else if busy == nil && ["Disconnected", "Unknown"].contains(state) { symbol = "network.slash" }
        else { symbol = "network.badge.shield.half.filled" } // connecting, Duo, reconnecting, disconnecting
        item.button?.image = NSImage(systemSymbolName: symbol, accessibilityDescription: "VPN")?
            .withSymbolConfiguration(.init(pointSize: 15, weight: .regular))
        item.button?.toolTip = statusTitle
        buildMenu()
    }

    /// The menu's first line: always the VPN, never the app's own update.
    var statusTitle: String { busy ?? "VPN: \(state)" }

    func buildMenu() {
        menu.removeAllItems()
        menu.addItem(withTitle: statusTitle, action: nil, keyEquivalent: "")
        menu.addItem(.separator())
        // Always one action row; it's greyed out (no action) while it can't be used.
        if session != nil {
            add("Cancel", #selector(cancelConnect))
        } else {
            // Nothing starts during an update: the restart that finishes it would cut it off.
            let idle = busy == nil && updating == nil
            if isActive { add("Disconnect", idle ? #selector(disconnect) : nil) }
            else { add("Connect", idle ? #selector(connect) : nil) }
        }
        menu.addItem(.separator())
        menu.addItem(autoConnectMenu())
        add("Set Password…", #selector(setPassword))
        // Connecting quits Cisco's app, which can't be open at the same time.
        add("Open Cisco Secure Client", busy == nil ? #selector(openCisco) : nil)
        let login = add("Launch at Login", #selector(toggleLogin))
        login.state = SMAppService.mainApp.status == .enabled ? .on : .off
        if let updating {
            add("Updating to \(updating.version)…", nil)
        } else if checkingForUpdates {
            add("Checking for Updates…", nil)
        } else {
            add(availableUpdate.map { "Update to \($0.version)…" } ?? "Check for Updates…", #selector(checkForUpdates))
        }
        menu.addItem(.separator())
        add("Quit", #selector(NSApplication.terminate(_:)), target: NSApp)
    }

    @discardableResult
    func add(_ title: String, _ action: Selector?, target: AnyObject? = nil) -> NSMenuItem {
        let i = menu.addItem(withTitle: title, action: action, keyEquivalent: "")
        i.target = target ?? self
        return i
    }

    func setBusy(_ text: String?) {
        busy = text
        operationEpoch += 1 // drop any state check started before this
        render()
    }

    /// Ends a VPN operation showing the state Cisco reports now, never the state from before
    /// it; `known` is used if Cisco can't say. Call off the main thread.
    func endOperation(known: String? = nil) {
        let s = currentVPNState()
        DispatchQueue.main.async {
            self.state = s == "Unknown" ? known ?? s : s
            self.setBusy(nil)
        }
    }

    // MARK: Actions

    @objc func connect() {
        guard busy == nil, updating == nil, !isActive else { return }
        guard !prefs.user.isEmpty else {
            notify("No Cisco username found", "Connect once with Cisco Secure Client so it remembers your username.")
            return
        }
        guard let password = Keychain.read(account: prefs.user) else {
            if promptForPassword() { connect() }
            return
        }
        actedSinceNetworkChange = true; pendingJoin = nil // any attempt, manual or not, is the join's one try
        setBusy("VPN: Connecting…")
        log("app: connect requested")
        DispatchQueue.global().async {
            if let dest = staleServerRoute(self.prefs.host) {
                log("app: stale route to the server, asking to remove it")
                removeRoute(dest)
                if staleServerRoute(self.prefs.host) != nil {
                    log("app: stale route still there")
                    DispatchQueue.main.async {
                        self.notify("Can't reach the VPN server", "Turn Wi-Fi off and on, then connect again.")
                    }
                    return self.endOperation()
                }
            }
            self.quitCiscoGUI()
            let s = ConnectSession(
                host: self.prefs.host, user: self.prefs.user, password: password,
                onDuo: { DispatchQueue.main.async {
                    self.setBusy("VPN: Approve Duo on your phone…")
                    self.notify("Approve Duo on your phone")
                } },
                onStopping: { // main thread; the attempt may still be cleaning up
                    self.session = nil
                    self.setBusy("VPN: Checking…")
                },
                onDone: { outcome in // main thread
                    var known: String?
                    switch outcome {
                    case .connected: known = "Connected"
                    case .failed(let why): self.notify("VPN connect failed", why)
                    }
                    DispatchQueue.global().async { self.endOperation(known: known) }
                })
            DispatchQueue.main.async { self.session = s; self.render(); s.start() } // shows Cancel
        }
    }

    @objc func cancelConnect() { session?.cancel() }

    @objc func disconnect() {
        guard busy == nil, updating == nil else { return }
        actedSinceNetworkChange = true; pendingJoin = nil // a manual disconnect isn't undone by an auto-connect
        setBusy("VPN: Disconnecting…")
        log("app: disconnect requested")
        DispatchQueue.global().async {
            runVPN(["disconnect"])
            self.endOperation()
        }
    }

    /// The CLI can't connect while the Cisco GUI is open.
    func quitCiscoGUI() {
        let apps = NSRunningApplication.runningApplications(withBundleIdentifier: ciscoGUIBundleID)
        guard !apps.isEmpty else { return }
        apps.forEach { $0.terminate() }
        for _ in 0..<50 where apps.contains(where: { !$0.isTerminated }) { usleep(100_000) }
        log("app: Cisco GUI \(apps.allSatisfy(\.isTerminated) ? "quit" : "did NOT quit")")
    }

    @objc func setPassword() { _ = promptForPassword() }

    func promptForPassword() -> Bool {
        NSApp.activate(ignoringOtherApps: true)
        let alert = NSAlert()
        alert.messageText = "NYU password for \(prefs.user)"
        alert.informativeText = "Stored in your macOS Keychain. Used only to answer Cisco's password prompt."
        let field = NSSecureTextField(frame: NSRect(x: 0, y: 0, width: 240, height: 24))
        alert.accessoryView = field
        alert.addButton(withTitle: "Save")
        alert.addButton(withTitle: "Cancel")
        alert.window.initialFirstResponder = field
        guard alert.runModal() == .alertFirstButtonReturn, !field.stringValue.isEmpty else { return false }
        return Keychain.save(field.stringValue, account: prefs.user)
    }

    // MARK: Auto-connect

    /// On joining a saved network, connect once. Re-arms only when the network changes,
    /// so a manual disconnect or an ignored Duo push isn't retried.
    func watchNetwork() {
        pathMonitor.pathUpdateHandler = { [weak self] path in
            let iface = path.availableInterfaces.first { $0.type == .wifi || $0.type == .wiredEthernet }?.name
            DispatchQueue.main.async { self?.networkChanged(iface) }
        }
        pathMonitor.start(queue: .global())
    }

    /// Bumped on every network change, so a lookup for a network you've since left is dropped.
    var networkGeneration = 0
    /// A saved network whose auto-connect check a path update cut short. The next lookup
    /// tries again if it finds the same router, since the update may have been a move elsewhere.
    var pendingJoin: String?
    /// The latest network generations whose lookup finished, and whose lookup found a router
    /// (now `currentRouter`).
    var lookedUpGeneration = -1, confirmedGeneration = -1

    func networkChanged(_ iface: String?) {
        networkCheck?.cancel()
        networkGeneration += 1
        actedSinceNetworkChange = busy != nil // an operation already running is this network's try
        guard let iface else { currentRouter = nil; pendingJoin = nil; return }
        let generation = networkGeneration
        let work = DispatchWorkItem { [weak self] in self?.identifyNetwork(iface, generation: generation) }
        networkCheck = work
        DispatchQueue.main.asyncAfter(deadline: .now() + 3, execute: work) // let DHCP settle
    }

    func identifyNetwork(_ iface: String, generation: Int) {
        DispatchQueue.global().async {
            var router: String?
            for _ in 0..<3 {
                router = routerAddress(on: iface)
                if router != nil { break }
                sleep(2)
            }
            DispatchQueue.main.async {
                guard generation == self.networkGeneration else { return } // the network changed again
                let pending = self.pendingJoin
                self.pendingJoin = nil
                self.lookedUpGeneration = generation
                guard let router else { return }
                self.confirmedGeneration = generation
                // Same router means same network (e.g. the VPN itself changed the path).
                guard router != self.currentRouter else {
                    if pending == router { self.autoConnect(router: router, generation: generation) }
                    return
                }
                self.currentRouter = router
                self.render() // the checkmark in Auto-Connect Networks
                guard let net = self.savedNetworks.first(where: { $0.router == router }) else { return }
                log("auto: joined saved network \"\(net.name)\"")
                self.autoConnect(router: router, generation: generation)
            }
        }
    }

    /// The one connect attempt for joining a saved network, made only if a fresh state check
    /// says the VPN is off and nothing else happened since the join: no connect or disconnect,
    /// no move to another network, no update, the network still saved. Otherwise the join is
    /// dropped, except that a path update waits for the next lookup to confirm the network.
    func autoConnect(router: String, generation: Int) {
        let skip = { (why: String) in log("auto: not connecting, \(why)") }
        guard !actedSinceNetworkChange else { return skip("a connect or disconnect already ran") }
        guard updating == nil else { return skip("an update is installing") }
        checkState { s in
            guard router == self.currentRouter else { return skip("the network changed") }
            guard self.savedNetworks.contains(where: { $0.router == router }) else { return skip("the network was removed") }
            guard !self.actedSinceNetworkChange, self.updating == nil, let s else { return skip("something else happened first") }
            guard s == "Disconnected" else { return skip("the VPN is \(s)") }
            // A path update: same network (DNS, IPv6, the VPN) or a move. Go ahead only once the
            // lookup for the latest change finds this router; if it hasn't run, it decides.
            if generation != self.networkGeneration {
                guard self.lookedUpGeneration == self.networkGeneration else {
                    self.pendingJoin = router
                    return log("auto: the network path changed, waiting for the next lookup")
                }
                guard self.confirmedGeneration == self.networkGeneration else { return skip("the network wasn't identified") }
            }
            guard Keychain.read(account: self.prefs.user) != nil else { return skip("no saved password") } // never prompt unasked
            self.connect()
        }
    }

    func autoConnectMenu() -> NSMenuItem {
        let root = NSMenuItem(title: "Auto-Connect Networks", action: nil, keyEquivalent: "")
        let sub = NSMenu()
        let nets = savedNetworks
        if nets.isEmpty {
            sub.addItem(withTitle: "No saved networks", action: nil, keyEquivalent: "")
        }
        for (i, n) in nets.enumerated() {
            let row = NSMenuItem(title: n.name, action: nil, keyEquivalent: "")
            if n.router == currentRouter { row.state = .on } // the network you're on now
            let actions = NSMenu()
            let rename = actions.addItem(withTitle: "Rename…", action: #selector(renameNetwork(_:)), keyEquivalent: "")
            let remove = actions.addItem(withTitle: "Remove", action: #selector(removeNetwork(_:)), keyEquivalent: "")
            for a in [rename, remove] { a.tag = i; a.target = self }
            row.submenu = actions
            sub.addItem(row)
        }
        sub.addItem(.separator())
        let canAdd = currentRouter != nil && !nets.contains { $0.router == currentRouter }
        let addItem = sub.addItem(withTitle: "Add Current Network…", action: canAdd ? #selector(addNetwork) : nil, keyEquivalent: "")
        addItem.target = self
        root.submenu = sub
        return root
    }

    @objc func addNetwork() {
        guard let router = currentRouter,
              let name = promptForName("Name this network", defaultName: "Network \(savedNetworks.count + 1)") else { return }
        savedNetworks.append(SavedNetwork(name: name, router: router))
        log("auto: saved network \"\(name)\"")
    }

    @objc func renameNetwork(_ sender: NSMenuItem) {
        var nets = savedNetworks
        guard nets.indices.contains(sender.tag),
              let name = promptForName("Rename network", defaultName: nets[sender.tag].name) else { return }
        nets[sender.tag].name = name
        savedNetworks = nets
    }

    @objc func removeNetwork(_ sender: NSMenuItem) {
        var nets = savedNetworks
        guard nets.indices.contains(sender.tag) else { return }
        log("auto: removed network \"\(nets[sender.tag].name)\"")
        nets.remove(at: sender.tag)
        savedNetworks = nets
    }

    func promptForName(_ title: String, defaultName: String) -> String? {
        NSApp.activate(ignoringOtherApps: true)
        let alert = NSAlert()
        alert.messageText = title
        alert.informativeText = "The VPN connects automatically when you join this network."
        let field = NSTextField(frame: NSRect(x: 0, y: 0, width: 240, height: 24))
        field.stringValue = defaultName
        alert.accessoryView = field
        alert.addButton(withTitle: "Save")
        alert.addButton(withTitle: "Cancel")
        alert.window.initialFirstResponder = field
        guard alert.runModal() == .alertFirstButtonReturn else { return nil }
        let entered = field.stringValue.trimmingCharacters(in: .whitespaces)
        return entered.isEmpty ? defaultName : entered
    }

    @objc func openCisco() {
        if let url = NSWorkspace.shared.urlForApplication(withBundleIdentifier: ciscoGUIBundleID) {
            NSWorkspace.shared.openApplication(at: url, configuration: .init())
        }
    }

    @objc func toggleLogin() {
        let svc = SMAppService.mainApp
        do { svc.status == .enabled ? try svc.unregister() : try svc.register() }
        catch { notify("Launch at Login failed", error.localizedDescription) }
    }

    // MARK: Updates

    var currentVersion: String { Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "0" }

    /// Daily background check: updates the menu item and notifies once per new version.
    func checkForUpdatesQuietly() {
        guard !checkingForUpdates, updating == nil else { return }
        updateCheck += 1
        let check = updateCheck
        Task { @MainActor in
            let r = try? await fetchLatestRelease()
            guard check == updateCheck, updating == nil, let r else { return } // a newer check owns the row
            guard isVersion(r.version, newerThan: currentVersion) else {
                if availableUpdate != nil { availableUpdate = nil; buildMenu() }
                return
            }
            guard availableUpdate?.version != r.version else { return }
            notify("ConnectAnytime \(r.version) is available", "Choose Update in the menu to install it.")
            availableUpdate = r
            buildMenu()
        }
    }

    @objc func checkForUpdates() {
        guard !checkingForUpdates, updating == nil else { return }
        checkingForUpdates = true
        updateCheck += 1 // supersedes a quiet check still in flight
        buildMenu()
        Task { @MainActor in
            let release: Release
            do {
                release = try await fetchLatestRelease()
                checkingForUpdates = false
            } catch {
                checkingForUpdates = false
                buildMenu()
                return showAlert("Couldn't check for updates", error.localizedDescription)
            }
            guard isVersion(release.version, newerThan: currentVersion) else {
                availableUpdate = nil
                buildMenu()
                return showAlert("You're up to date", "ConnectAnytime \(currentVersion) is the latest version.")
            }
            availableUpdate = release
            buildMenu()
            NSApp.activate(ignoringOtherApps: true)
            let alert = NSAlert()
            alert.messageText = "ConnectAnytime \(release.version) is available"
            alert.informativeText = "You have \(currentVersion). The app restarts to finish; the VPN stays as it is."
            alert.accessoryView = releaseNotesView(release.notes)
            alert.addButton(withTitle: "Install and Restart")
            alert.addButton(withTitle: "Later")
            switch alert.runModal() {
            case .alertFirstButtonReturn: install(release)
            default: break
            }
        }
    }

    func install(_ release: Release) {
        guard updating == nil else { return }
        guard busy == nil else { return showAlert("Try again in a moment", "Wait for the VPN to finish connecting or disconnecting.") }
        guard FileManager.default.isWritableFile(atPath: Bundle.main.bundleURL.deletingLastPathComponent().path) else {
            return showAlert("Can't update here", "Move ConnectAnytime to your Applications folder, then try again.")
        }
        updating = release
        buildMenu()
        log("update: installing \(release.version)")
        Task { @MainActor in
            do {
                try await installUpdate(release)
                log("update: installed \(release.version), restarting")
                UserDefaults.standard.set(currentRouter, forKey: "routerBeforeUpdate") // the last one identified
                relaunchAfterExit()
                NSApp.terminate(nil)
            } catch {
                log("update: failed - \(error.localizedDescription)")
                updating = nil
                buildMenu()
                let intact = FileManager.default.fileExists(atPath: Bundle.main.bundlePath)
                showAlert("Update failed", intact
                    ? "\(error.localizedDescription) Your current version is unchanged."
                    : "\(error.localizedDescription) ConnectAnytime is no longer at \(Bundle.main.bundlePath). Download it again from GitHub.")
            }
        }
    }

    func showAlert(_ title: String, _ text: String) {
        NSApp.activate(ignoringOtherApps: true)
        let alert = NSAlert()
        alert.messageText = title
        alert.informativeText = text
        alert.runModal()
    }

    func notify(_ title: String, _ body: String = "") {
        let c = UNMutableNotificationContent()
        c.title = title
        c.body = body
        UNUserNotificationCenter.current().add(UNNotificationRequest(identifier: UUID().uuidString, content: c, trigger: nil))
    }
}

// CLI mode: forward a command to the running menu-bar app (launching it if needed), then exit.
// Only "--" switches count, so stray launch arguments from macOS can't stop the app starting.
if let arg = CommandLine.arguments.dropFirst().first(where: { $0.hasPrefix("--") }) {
    let cmd = String(arg.dropFirst(2))
    guard commands.contains(cmd) else {
        FileHandle.standardError.write(Data("usage: ConnectAnytime --connect | --disconnect | --toggle\n".utf8))
        exit(2)
    }
    let me = ProcessInfo.processInfo.processIdentifier
    let running = NSRunningApplication.runningApplications(withBundleIdentifier: Bundle.main.bundleIdentifier ?? "")
        .contains { $0.processIdentifier != me }
    if !running {
        NSWorkspace.shared.openApplication(at: Bundle.main.bundleURL, configuration: .init())
        sleep(2) // give it time to start listening
    }
    DistributedNotificationCenter.default().postNotificationName(commandNotification, object: cmd, userInfo: nil, deliverImmediately: true)
    exit(0)
}

let app = NSApplication.shared
let delegate = App()
app.delegate = delegate
app.setActivationPolicy(.accessory)
app.run()
