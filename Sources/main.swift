// ConnectAnytime: a menu-bar Connect/Disconnect for Cisco Secure Client.
// Drives Cisco's own CLI over a pty; the password goes Keychain -> pty, nowhere else.
import AppKit
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
        if let h = tag("DefaultHostName") { p.host = h }
        if let u = tag("DefaultUser") { p.user = u }
        return p
    }
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

@discardableResult
func run(_ path: String, _ args: [String]) -> String {
    let p = Process()
    p.executableURL = URL(fileURLWithPath: path)
    p.arguments = args
    let pipe = Pipe()
    p.standardOutput = pipe
    p.standardError = pipe
    p.standardInput = FileHandle.nullDevice
    guard (try? p.run()) != nil else { return "" }
    let data = pipe.fileHandleForReading.readDataToEndOfFile()
    p.waitUntilExit()
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
    let server = run("/sbin/route", ["-n", "get", host])
    let current = run("/sbin/route", ["-n", "get", "default"])
    guard let dest = field(server, "destination"), dest.range(of: "^\\d{1,3}(\\.\\d{1,3}){3}$", options: .regularExpression) != nil,
          let gw = field(server, "gateway"), let currentGW = field(current, "gateway"), gw != currentGW else { return nil }
    return dest
}

/// Deletes the route after the standard macOS admin password prompt.
func removeRoute(_ dest: String) {
    let script = "do shell script \"/sbin/route -n delete \(dest)\" with prompt \"ConnectAnytime needs to remove a stale route to the VPN server.\" with administrator privileges"
    run("/usr/bin/osascript", ["-e", script])
}

// MARK: - Interactive connect

/// Runs `vpn` interactively on a pty and answers each prompt exactly once.
/// Any repeated or unknown-order prompt aborts, so a bad password is never retried.
final class ConnectSession {
    enum Outcome { case connected, failed(String) }

    private let host: String, user: String, password: String
    private let onDuo: () -> Void
    private let onDone: (Outcome) -> Void
    private let queue = DispatchQueue(label: "connectanytime.session")
    private let process = Process()
    private var master: Int32 = -1
    private var source: DispatchSourceRead?
    private var buffer = ""
    private var lineBuffer = ""
    private var answered = Set<String>()
    private var finished = false

    init(host: String, user: String, password: String,
         onDuo: @escaping () -> Void, onDone: @escaping (Outcome) -> Void) {
        self.host = host; self.user = user; self.password = password
        self.onDuo = onDuo; self.onDone = onDone
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
        if tail.hasSuffix("Second Password:") { onDuo(); return answer("second", "push") }
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
    }

    func applicationWillTerminate(_ n: Notification) {
        if let pid = session?.pid, pid > 0 { kill(pid, SIGKILL) }
    }

    // Sent by `ConnectAnytime --connect | --disconnect | --toggle` (the Raycast script).
    func listenForCommands() {
        DistributedNotificationCenter.default().addObserver(forName: commandNotification, object: nil, queue: .main) { [weak self] n in
            guard let self, let cmd = n.object as? String else { return }
            log("app: command \(cmd)")
            switch cmd {
            case "connect": connect()
            case "disconnect": disconnect()
            case "toggle": isActive ? disconnect() : connect()
            default: break
            }
        }
    }

    func menuNeedsUpdate(_ menu: NSMenu) {
        refresh()
        buildMenu()
    }

    // MARK: State

    func refresh() {
        guard busy == nil else { return }
        DispatchQueue.global().async {
            let s = parseState(runVPN(["state"])) ?? "Unknown"
            DispatchQueue.main.async {
                guard self.busy == nil else { return }
                self.state = s
                self.render()
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
        item.button?.toolTip = "NYU VPN: \(busy ?? state)"
        buildMenu()
    }

    func buildMenu() {
        menu.removeAllItems()
        menu.addItem(withTitle: busy ?? state, action: nil, keyEquivalent: "")
        menu.addItem(.separator())
        if busy == nil {
            if isActive { add("Disconnect", #selector(disconnect)) }
            else { add("Connect", #selector(connect)) }
        } else if session != nil {
            add("Cancel", #selector(cancelConnect))
        }
        menu.addItem(.separator())
        menu.addItem(autoConnectMenu())
        add("Set Password…", #selector(setPassword))
        add("Open Cisco Secure Client", #selector(openCisco))
        let login = add("Launch at Login", #selector(toggleLogin))
        login.state = SMAppService.mainApp.status == .enabled ? .on : .off
        menu.addItem(.separator())
        add("Quit", #selector(NSApplication.terminate(_:)), target: NSApp)
    }

    @discardableResult
    func add(_ title: String, _ action: Selector, target: AnyObject? = nil) -> NSMenuItem {
        let i = menu.addItem(withTitle: title, action: action, keyEquivalent: "")
        i.target = target ?? self
        return i
    }

    func setBusy(_ text: String?) {
        busy = text
        render()
    }

    // MARK: Actions

    @objc func connect() {
        guard busy == nil, !isActive else { return }
        guard !prefs.user.isEmpty else {
            notify("No Cisco username found", "Connect once with Cisco Secure Client so it remembers your username.")
            return
        }
        guard let password = Keychain.read(account: prefs.user) else {
            if promptForPassword() { connect() }
            return
        }
        setBusy("Connecting…")
        log("app: connect requested")
        DispatchQueue.global().async {
            if let dest = staleServerRoute(self.prefs.host) {
                log("app: stale route to the server, asking to remove it")
                removeRoute(dest)
                if staleServerRoute(self.prefs.host) != nil {
                    log("app: stale route still there")
                    return DispatchQueue.main.async {
                        self.setBusy(nil)
                        self.notify("Can't reach the VPN server", "Turn Wi-Fi off and on, then connect again.")
                    }
                }
            }
            self.quitCiscoGUI()
            let s = ConnectSession(
                host: self.prefs.host, user: self.prefs.user, password: password,
                onDuo: { DispatchQueue.main.async {
                    self.setBusy("Approve Duo on your phone…")
                    self.notify("Approve Duo on your phone")
                } },
                onDone: { outcome in
                    self.session = nil
                    self.setBusy(nil)
                    if case .failed(let why) = outcome { self.notify("VPN connect failed", why) }
                    self.refresh()
                })
            DispatchQueue.main.async { self.session = s; s.start() }
        }
    }

    @objc func cancelConnect() { session?.cancel() }

    @objc func disconnect() {
        guard busy == nil else { return }
        setBusy("Disconnecting…")
        log("app: disconnect requested")
        DispatchQueue.global().async {
            runVPN(["disconnect"])
            DispatchQueue.main.async { self.setBusy(nil); self.refresh() }
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

    func networkChanged(_ iface: String?) {
        networkCheck?.cancel()
        guard let iface else { currentRouter = nil; return }
        let work = DispatchWorkItem { [weak self] in self?.identifyNetwork(iface) }
        networkCheck = work
        DispatchQueue.main.asyncAfter(deadline: .now() + 3, execute: work) // let DHCP settle
    }

    func identifyNetwork(_ iface: String) {
        DispatchQueue.global().async {
            var router: String?
            for _ in 0..<3 {
                router = routerAddress(on: iface)
                if router != nil { break }
                sleep(2)
            }
            DispatchQueue.main.async {
                // Same router means same network (e.g. the VPN itself changed the path).
                guard let router, router != self.currentRouter else { return }
                self.currentRouter = router
                guard let net = self.savedNetworks.first(where: { $0.router == router }) else { return }
                log("auto: joined saved network \"\(net.name)\"")
                if self.state == "Disconnected", self.busy == nil, Keychain.read(account: self.prefs.user) != nil {
                    self.connect()
                }
            }
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
