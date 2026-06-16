// Alpaca Menu Bar — icona di stato e controlli per il proxy alpaca.
//
// App AppKit a file singolo, compilata da setup.sh con swiftc e installata in
// "~/Applications/Alpaca Menu Bar.app". Resta sempre attiva nella barra menu
// (LaunchAgent alpaca.menubar) e ogni 5 secondi controlla:
//   - il proxy locale (GET http://127.0.0.1:<porta>/alpaca.pac)
//   - il ticket Kerberos (klist -s)
//   - la raggiungibilità del PAC aziendale (fuori VPN alpaca va in bypass)
//
// La configurazione (porta, label launchd, URL PAC, percorsi log) viene letta
// dalle chiavi Alpaca* dell'Info.plist, scritte da setup.sh; i default qui sotto
// valgono solo se l'app viene lanciata fuori dal bundle.

import AppKit
import Foundation

// MARK: - Configurazione

enum Config {
    private static let info = Bundle.main.infoDictionary ?? [:]

    static let proxyPort = info["AlpacaProxyPort"] as? Int ?? 3128
    static let proxyLabel = info["AlpacaProxyLabel"] as? String ?? "alpaca.background"
    static let proxyPlist = info["AlpacaProxyPlist"] as? String
        ?? NSString(string: "~/Library/LaunchAgents/alpaca.background.plist").expandingTildeInPath
    static let pacURL = info["AlpacaPACURL"] as? String ?? "http://wpadu.ha.servizi.gr-u.it/wpadu.dat"
    static let outLog = info["AlpacaOutLog"] as? String
        ?? NSString(string: "~/Library/Logs/alpaca.out.log").expandingTildeInPath
    static let errLog = info["AlpacaErrLog"] as? String
        ?? NSString(string: "~/Library/Logs/alpaca.err.log").expandingTildeInPath

    static var guiDomain: String { "gui/\(getuid())" }
    static var serviceTarget: String { "\(guiDomain)/\(proxyLabel)" }
}

// MARK: - Esecuzione comandi

struct CommandResult {
    let status: Int32
    let output: String
}

@discardableResult
func runCommand(_ executable: String, _ arguments: [String], timeout: TimeInterval = 10) -> CommandResult {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: executable)
    process.arguments = arguments
    let pipe = Pipe()
    process.standardOutput = pipe
    process.standardError = pipe
    do {
        try process.run()
    } catch {
        return CommandResult(status: -1, output: "")
    }
    let deadline = Date().addingTimeInterval(timeout)
    while process.isRunning && Date() < deadline {
        usleep(50_000)
    }
    if process.isRunning {
        process.terminate()
    }
    let data = pipe.fileHandleForReading.readDataToEndOfFile()
    process.waitUntilExit()
    return CommandResult(status: process.terminationStatus,
                         output: String(data: data, encoding: .utf8) ?? "")
}

/// GET diretto (mai attraverso il proxy di sistema), true se risponde 2xx/3xx.
func httpReachable(_ urlString: String, timeout: TimeInterval) -> Bool {
    guard let url = URL(string: urlString) else { return false }
    let configuration = URLSessionConfiguration.ephemeral
    configuration.timeoutIntervalForRequest = timeout
    configuration.timeoutIntervalForResource = timeout
    configuration.connectionProxyDictionary = [:]
    let session = URLSession(configuration: configuration)
    defer { session.invalidateAndCancel() }
    var reachable = false
    let semaphore = DispatchSemaphore(value: 0)
    session.dataTask(with: url) { _, response, _ in
        if let http = response as? HTTPURLResponse, (200..<400).contains(http.statusCode) {
            reachable = true
        }
        semaphore.signal()
    }.resume()
    _ = semaphore.wait(timeout: .now() + timeout + 1)
    return reachable
}

// MARK: - Stato

enum ProxyState {
    case running   // proxy su, in rete aziendale, ticket ok
    case bypass    // proxy su, fuori rete aziendale (connessione diretta): per l'utente è tutto ok
    case degraded  // proxy su, in rete aziendale, ma ticket assente/scaduto
    case stopped   // porta non risponde
}

struct Status {
    var proxyAlive = false
    var ticketValid = false
    var pacReachable = false
    var systemProxyEnabled: Bool?  // nil = non determinabile
    var loginEnabled = true

    var state: ProxyState {
        if !proxyAlive { return .stopped }
        if !pacReachable { return .bypass }
        if !ticketValid { return .degraded }
        return .running
    }

    var alpacaLine: String {
        proxyAlive ? "Alpaca: attivo (porta \(Config.proxyPort))" : "Alpaca: non attivo"
    }

    var networkLine: String {
        pacReachable ? "Rete rilevata: aziendale" : "Rete rilevata: esterna"
    }

    var ticketLine: String {
        ticketValid ? "Ticket Kerberos: OK" : "Ticket Kerberos: assente o scaduto (kinit)"
    }
}

func probeStatus() -> Status {
    var status = Status()
    status.proxyAlive = httpReachable("http://127.0.0.1:\(Config.proxyPort)/alpaca.pac", timeout: 2)
    status.ticketValid = runCommand("/usr/bin/klist", ["-s"], timeout: 5).status == 0
    status.pacReachable = httpReachable(Config.pacURL, timeout: 3)
    status.systemProxyEnabled = systemProxyEnabled()
    status.loginEnabled = loginItemEnabled()
    return status
}

// MARK: - networksetup / launchctl

/// Network service della connessione di default (es. "Wi-Fi"); sotto VPN
/// l'interfaccia di default è una utun senza hardware port, quindi Wi-Fi è il fallback.
func activeNetworkService() -> String {
    let route = runCommand("/sbin/route", ["-n", "get", "default"], timeout: 3).output
    guard let interfaceLine = route.split(separator: "\n").first(where: { $0.contains("interface:") }),
          let interface = interfaceLine.split(separator: ":").last
              .map({ $0.trimmingCharacters(in: .whitespaces) })
    else { return "Wi-Fi" }

    let ports = runCommand("/usr/sbin/networksetup", ["-listallhardwareports"], timeout: 5).output
    var currentPort: String?
    for line in ports.split(separator: "\n").map(String.init) {
        if line.hasPrefix("Hardware Port:") {
            currentPort = line.dropFirst("Hardware Port:".count).trimmingCharacters(in: .whitespaces)
        } else if line.hasPrefix("Device:") {
            let device = line.dropFirst("Device:".count).trimmingCharacters(in: .whitespaces)
            if device == interface, let port = currentPort {
                return port
            }
        }
    }
    return "Wi-Fi"
}

func systemProxyEnabled() -> Bool? {
    let result = runCommand("/usr/sbin/networksetup",
                            ["-getautoproxyurl", activeNetworkService()], timeout: 5)
    guard result.status == 0 else { return nil }
    return result.output.contains("Enabled: Yes")
}

func loginItemEnabled() -> Bool {
    let result = runCommand("/bin/launchctl", ["print-disabled", Config.guiDomain], timeout: 5)
    guard result.status == 0 else { return true }
    for line in result.output.split(separator: "\n")
    where line.contains("\"\(Config.proxyLabel)\"") {
        return !(line.contains("disabled") || line.contains("true"))
    }
    return true
}

// MARK: - App

@main
enum Main {
    static let delegate = AppDelegate()

    static func main() {
        let app = NSApplication.shared
        app.setActivationPolicy(.accessory)
        app.delegate = delegate
        app.run()
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate, NSMenuDelegate {
    private var statusItem: NSStatusItem!
    private var timer: Timer?
    private var status = Status()
    private var previousState: ProxyState?
    private var polling = false
    private var menuIsOpen = false

    func applicationDidFinishLaunching(_ notification: Notification) {
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
        statusItem.menu = NSMenu()
        statusItem.menu?.delegate = self
        applyStatus(Status())  // icona iniziale "fermo" finché il primo poll non risponde

        poll()
        timer = Timer.scheduledTimer(withTimeInterval: 5, repeats: true) { [weak self] _ in
            self?.poll()
        }
    }

    // MARK: Polling

    private func poll() {
        guard !polling else { return }
        polling = true
        DispatchQueue.global(qos: .utility).async { [weak self] in
            let status = probeStatus()
            DispatchQueue.main.async {
                self?.polling = false
                self?.applyStatus(status)
            }
        }
    }

    private func applyStatus(_ newStatus: Status) {
        status = newStatus
        updateIcon()
        if !menuIsOpen, let menu = statusItem.menu {
            rebuildMenu(menu)
        }
        notifyOnTransition(to: newStatus.state)
        previousState = newStatus.state
    }

    private func updateIcon() {
        guard let button = statusItem.button else { return }
        let symbol: String
        switch status.state {
        case .running, .bypass: symbol = "checkmark.shield"
        case .degraded: symbol = "exclamationmark.triangle"
        case .stopped: symbol = "shield.slash"
        }
        let image = NSImage(systemSymbolName: symbol, accessibilityDescription: "Alpaca")
        image?.isTemplate = true
        button.image = image
        button.toolTip = "\(status.alpacaLine)\n\(status.networkLine)\n\(status.ticketLine)"
    }

    private func notifyOnTransition(to state: ProxyState) {
        guard let previous = previousState, previous != state else { return }
        switch state {
        case .stopped:
            notify(title: "Alpaca proxy fermo",
                   body: "Il proxy su 127.0.0.1:\(Config.proxyPort) non risponde.")
        case .bypass:
            notify(title: "Alpaca fuori rete aziendale",
                   body: "Le richieste vanno in connessione diretta (bypass).")
        case .degraded:
            notify(title: "Alpaca in stato degradato",
                   body: "Ticket Kerberos assente o scaduto: esegui kinit.")
        case .running:
            notify(title: "Alpaca proxy attivo",
                   body: "Proxy funzionante su 127.0.0.1:\(Config.proxyPort).")
        }
    }

    private func notify(title: String, body: String) {
        let notification = NSUserNotification()
        notification.title = title
        notification.informativeText = body
        NSUserNotificationCenter.default.deliver(notification)
    }

    // MARK: Menu

    func menuWillOpen(_ menu: NSMenu) {
        menuIsOpen = true
        rebuildMenu(menu)
        poll()  // aggiorna lo stato mostrato alla prossima apertura
    }

    func menuDidClose(_ menu: NSMenu) {
        menuIsOpen = false
    }

    private func rebuildMenu(_ menu: NSMenu) {
        menu.removeAllItems()

        menu.addItem(disabledItem(status.alpacaLine))
        menu.addItem(disabledItem(status.networkLine))
        menu.addItem(disabledItem(status.ticketLine))
        menu.addItem(.separator())

        menu.addItem(actionItem("Avvia proxy", #selector(startProxy), enabled: !status.proxyAlive))
        menu.addItem(actionItem("Ferma proxy", #selector(stopProxy), enabled: status.proxyAlive))
        menu.addItem(actionItem("Riavvia proxy", #selector(restartProxy), enabled: status.proxyAlive))
        menu.addItem(.separator())

        menu.addItem(actionItem("Test connettività…", #selector(testConnectivity)))
        menu.addItem(actionItem("Apri log", #selector(openLogs)))
        menu.addItem(actionItem("Pulisci log…", #selector(clearLogs)))
        menu.addItem(.separator())

        let systemProxy = actionItem("Proxy di sistema (PAC)", #selector(toggleSystemProxy),
                                     enabled: status.systemProxyEnabled != nil)
        systemProxy.state = status.systemProxyEnabled == true ? .on : .off
        menu.addItem(systemProxy)

        let login = actionItem("Avvia proxy al login", #selector(toggleLoginItem))
        login.state = status.loginEnabled ? .on : .off
        menu.addItem(login)
        menu.addItem(.separator())

        menu.addItem(actionItem("Esci", #selector(quit)))
    }

    private func disabledItem(_ title: String) -> NSMenuItem {
        let item = NSMenuItem(title: title, action: nil, keyEquivalent: "")
        item.isEnabled = false
        return item
    }

    private func actionItem(_ title: String, _ action: Selector, enabled: Bool = true) -> NSMenuItem {
        let item = NSMenuItem(title: title, action: enabled ? action : nil, keyEquivalent: "")
        item.target = self
        item.isEnabled = enabled
        return item
    }

    // MARK: Azioni

    @objc private func startProxy() {
        runInBackgroundThenPoll {
            // kickstart se il job è già caricato, altrimenti bootstrap del plist.
            if runCommand("/bin/launchctl", ["kickstart", Config.serviceTarget]).status != 0 {
                runCommand("/bin/launchctl", ["bootstrap", Config.guiDomain, Config.proxyPlist])
            }
        }
    }

    @objc private func stopProxy() {
        runInBackgroundThenPoll {
            runCommand("/bin/launchctl", ["bootout", Config.serviceTarget])
        }
    }

    @objc private func restartProxy() {
        runInBackgroundThenPoll {
            if runCommand("/bin/launchctl", ["kickstart", "-k", Config.serviceTarget]).status != 0 {
                runCommand("/bin/launchctl", ["bootstrap", Config.guiDomain, Config.proxyPlist])
            }
        }
    }

    @objc private func testConnectivity() {
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            let result = runCommand("/usr/bin/curl",
                                    ["-s", "-o", "/dev/null", "-w", "%{http_code}",
                                     "-x", "http://127.0.0.1:\(Config.proxyPort)",
                                     "--connect-timeout", "5", "-m", "20",
                                     "https://google.com"],
                                    timeout: 25)
            let code = result.output.trimmingCharacters(in: .whitespacesAndNewlines)
            let success = code.hasPrefix("2") || code.hasPrefix("3")
            DispatchQueue.main.async {
                self?.showAlert(
                    title: success ? "Proxy funzionante ✅" : "Test fallito ❌",
                    body: success
                        ? "https://google.com raggiunto attraverso 127.0.0.1:\(Config.proxyPort) (HTTP \(code))."
                        : "Nessuna risposta valida attraverso il proxy (HTTP \(code.isEmpty ? "n/d" : code)).\nControlla VPN, ticket Kerberos (kinit) e i log.")
            }
        }
    }

    @objc private func openLogs() {
        for path in [Config.outLog, Config.errLog] where FileManager.default.fileExists(atPath: path) {
            NSWorkspace.shared.open(URL(fileURLWithPath: path))
        }
    }

    @objc private func clearLogs() {
        let paths = [Config.outLog, Config.errLog]
        let existing = paths.filter { FileManager.default.fileExists(atPath: $0) }
        guard !existing.isEmpty else {
            showAlert(title: "Nessun log da pulire",
                      body: "Non è stato trovato alcun file di log.")
            return
        }
        guard confirm(title: "Pulire i log?",
                      body: "I file di log verranno svuotati:\n\(existing.joined(separator: "\n"))\n\nL'operazione non è reversibile.",
                      confirmButton: "Pulisci")
        else { return }

        var failed: [String] = []
        for path in existing {
            // Tronca il file in-place mantenendo lo stesso inode: il descrittore
            // già aperto da alpaca continua a scrivere sullo stesso file, senza
            // riavviare il proxy. NB: createFile/rimozione creerebbero un nuovo
            // inode lasciando il proxy a scrivere su un file orfano.
            guard let handle = FileHandle(forWritingAtPath: path) else {
                failed.append(path)
                continue
            }
            do {
                try handle.truncate(atOffset: 0)
                try handle.close()
            } catch {
                failed.append(path)
            }
        }
        if failed.isEmpty {
            showAlert(title: "Log puliti ✅",
                      body: "I file di log sono stati svuotati.")
        } else {
            showAlert(title: "Pulizia parziale ❌",
                      body: "Impossibile svuotare:\n\(failed.joined(separator: "\n"))")
        }
    }

    @objc private func toggleSystemProxy() {
        let enable = status.systemProxyEnabled != true
        runInBackgroundThenPoll { [weak self] in
            let service = activeNetworkService()
            let result = runCommand("/usr/sbin/networksetup",
                                    ["-setautoproxystate", service, enable ? "on" : "off"])
            if result.status != 0 {
                DispatchQueue.main.async {
                    self?.showAlert(title: "Operazione non riuscita",
                                    body: "Impossibile modificare il proxy di sistema su \"\(service)\" (servono privilegi di amministratore?).")
                }
            }
        }
    }

    @objc private func toggleLoginItem() {
        let enable = !status.loginEnabled
        runInBackgroundThenPoll {
            runCommand("/bin/launchctl",
                       [enable ? "enable" : "disable", Config.serviceTarget])
        }
    }

    @objc private func quit() {
        NSApp.terminate(nil)
    }

    private func runInBackgroundThenPoll(_ work: @escaping () -> Void) {
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            work()
            // launchd ci mette un attimo a (ri)avviare il job: piccolo respiro prima del poll.
            Thread.sleep(forTimeInterval: 1)
            DispatchQueue.main.async { self?.poll() }
        }
    }

    private func showAlert(title: String, body: String) {
        NSApp.activate(ignoringOtherApps: true)
        let alert = NSAlert()
        alert.messageText = title
        alert.informativeText = body
        alert.runModal()
    }

    /// Mostra una conferma con due pulsanti; true se l'utente conferma.
    private func confirm(title: String, body: String, confirmButton: String) -> Bool {
        NSApp.activate(ignoringOtherApps: true)
        let alert = NSAlert()
        alert.messageText = title
        alert.informativeText = body
        alert.alertStyle = .warning
        alert.addButton(withTitle: confirmButton)
        alert.addButton(withTitle: "Annulla")
        return alert.runModal() == .alertFirstButtonReturn
    }
}
