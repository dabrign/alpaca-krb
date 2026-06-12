#!/bin/bash
#
# Setup di Alpaca come proxy locale Kerberos per i Mac aziendali a dominio.
#
# Esegue, in ordine:
#   1. verifica dei prerequisiti (Xcode CLT, Go >= 1.24)
#   2. checkout del branch e build di alpaca (CGO, GSS-API nativo)
#   3. installazione del binario in ~/Library/Application Support/Alpaca
#   4. configurazione proxy nella shell (~/.zshrc)
#   5. configurazione del proxy automatico di sistema (PAC)
#   6. LaunchAgent per avviare alpaca al login (KeepAlive)
#   7. build + installazione della menu bar app (Alpaca Menu Bar.app)
#   8. fase finale sotto VPN: kinit interattivo (se manca il ticket) e test curl via proxy
#
# Idempotente: puo' essere rieseguito senza effetti collaterali.
#
# Uso:  ./setup/setup.sh [--port N]   (default: 3128)
set -euo pipefail

# --- Configurazione aziendale -------------------------------------------------
KRB_SPN="HTTP/proxyu.ha.servizi.gr-u.it"
KRB_REALM="DIREZIONE.GR-U.IT"
PAC_URL="http://wpadu.ha.servizi.gr-u.it/wpadu.dat"
PROXY_PORT=3128 # default, sovrascrivibile con --port
NO_PROXY_DOMAINS=".servizi.gr-u.it,.gr-u.it"
BRANCH="feature/gssapi-native"
MIN_GO_MINOR=24 # Go >= 1.24

# --- Percorsi -------------------------------------------------------------------
INSTALL_DIR="$HOME/Library/Application Support/Alpaca"
ALPACA_BIN="$INSTALL_DIR/alpaca"
APP_DIR="$HOME/Applications/Alpaca Menu Bar.app"
LAUNCH_AGENTS_DIR="$HOME/Library/LaunchAgents"
PROXY_LABEL="alpaca.background"
PROXY_PLIST="$LAUNCH_AGENTS_DIR/$PROXY_LABEL.plist"
MENUBAR_LABEL="alpaca.menubar"
MENUBAR_PLIST="$LAUNCH_AGENTS_DIR/$MENUBAR_LABEL.plist"
LOG_DIR="$HOME/Library/Logs"
OUT_LOG="$LOG_DIR/alpaca.out.log"
ERR_LOG="$LOG_DIR/alpaca.err.log"
ZSHRC="$HOME/.zshrc"
MARKER_BEGIN="# >>> alpaca proxy >>>"
MARKER_END="# <<< alpaca proxy <<<"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GUI_DOMAIN="gui/$(id -u)"

# --- Output ---------------------------------------------------------------------
if [ -t 1 ]; then
    C_STEP=$'\033[1;36m'; C_OK=$'\033[1;32m'; C_WARN=$'\033[1;33m'; C_ERR=$'\033[1;31m'; C_OFF=$'\033[0m'
else
    C_STEP=""; C_OK=""; C_WARN=""; C_ERR=""; C_OFF=""
fi
step() { printf '\n%s==> %s%s\n' "$C_STEP" "$*" "$C_OFF"; }
ok()   { printf '%s    ✔ %s%s\n' "$C_OK" "$*" "$C_OFF"; }
warn() { printf '%s    ⚠ %s%s\n' "$C_WARN" "$*" "$C_OFF"; }
die()  { printf '%s    ✘ %s%s\n' "$C_ERR" "$*" "$C_OFF" >&2; exit 1; }

# --- Argomenti --------------------------------------------------------------------
while [ $# -gt 0 ]; do
    case "$1" in
        --port)
            [ $# -ge 2 ] || die "--port richiede un valore (es. --port 8080)."
            PROXY_PORT="$2"; shift 2 ;;
        --port=*)
            PROXY_PORT="${1#--port=}"; shift ;;
        -h|--help)
            printf 'Uso: %s [--port N]   (default: 3128)\n' "$0"; exit 0 ;;
        *)
            die "Argomento sconosciuto: $1 (uso: $0 [--port N])" ;;
    esac
done

[[ "$PROXY_PORT" =~ ^[0-9]+$ ]] && [ "$PROXY_PORT" -ge 1 ] && [ "$PROXY_PORT" -le 65535 ] \
    || die "Porta non valida: \"$PROXY_PORT\" (intero tra 1 e 65535)."
[ "$PROXY_PORT" -ge 1024 ] \
    || warn "Porta $PROXY_PORT < 1024: richiede privilegi che il LaunchAgent utente non ha."

# --- 1. Prerequisiti --------------------------------------------------------------
step "Verifica prerequisiti"

[ "$(uname -s)" = "Darwin" ] || die "Questo script funziona solo su macOS."

if ! xcode-select -p >/dev/null 2>&1; then
    die "Xcode Command Line Tools non installati. Esegui:  xcode-select --install  e rilancia lo script."
fi
ok "Xcode Command Line Tools: $(xcode-select -p)"

if ! command -v go >/dev/null 2>&1; then
    die "Go non installato. Installa Go >= 1.$MIN_GO_MINOR da https://go.dev/dl/ (oppure: brew install go) e rilancia."
fi
GO_VERSION="$(go version | sed -E 's/.*go([0-9]+\.[0-9]+).*/\1/')"
GO_MAJOR="${GO_VERSION%%.*}"
GO_MINOR="${GO_VERSION#*.}"
if [ "$GO_MAJOR" -lt 1 ] || { [ "$GO_MAJOR" -eq 1 ] && [ "$GO_MINOR" -lt "$MIN_GO_MINOR" ]; }; then
    die "Go $GO_VERSION trovato, serve >= 1.$MIN_GO_MINOR. Aggiorna Go e rilancia."
fi
ok "Go $GO_VERSION"

if ! xcrun --find swiftc >/dev/null 2>&1; then
    die "swiftc non trovato (dovrebbe arrivare con gli Xcode Command Line Tools)."
fi
ok "swiftc disponibile"

REPO_ROOT="$(git -C "$SCRIPT_DIR" rev-parse --show-toplevel 2>/dev/null)" \
    || die "Lo script deve trovarsi dentro al clone della repo alpaca-krb."
[ -f "$REPO_ROOT/go.mod" ] || die "Repo inattesa in $REPO_ROOT: manca go.mod."
ok "Repo: $REPO_ROOT"

# --- 2. Build ---------------------------------------------------------------------
step "Build di alpaca (CGO + GSS-API nativo)"
SDKROOT="$(xcrun --sdk macosx --show-sdk-path)" \
    go build -C "$REPO_ROOT" -o "$REPO_ROOT/alpaca" .
ok "Build completata: $REPO_ROOT/alpaca"

# --- 3. Installazione binario ------------------------------------------------------
step "Installazione binario in $INSTALL_DIR"
# Ferma gli agent prima di sostituire binario e app (idempotenza).
launchctl bootout "$GUI_DOMAIN/$PROXY_LABEL"   2>/dev/null || true
launchctl bootout "$GUI_DOMAIN/$MENUBAR_LABEL" 2>/dev/null || true
mkdir -p "$INSTALL_DIR"
cp "$REPO_ROOT/alpaca" "$ALPACA_BIN"
ok "Binario installato"

# --- 4. ~/.zshrc --------------------------------------------------------------------
step "Configurazione proxy in $ZSHRC"
touch "$ZSHRC"
if grep -qF "$MARKER_BEGIN" "$ZSHRC"; then
    TMP_ZSHRC="$(mktemp)"
    awk -v b="$MARKER_BEGIN" -v e="$MARKER_END" '
        $0 == b { skip = 1; next }
        $0 == e { skip = 0; next }
        !skip' "$ZSHRC" > "$TMP_ZSHRC"
    mv "$TMP_ZSHRC" "$ZSHRC"
fi
cat >> "$ZSHRC" <<EOF
$MARKER_BEGIN
# Generato da alpaca-krb/setup/setup.sh — non modificare a mano questo blocco.
export HTTP_PROXY=http://127.0.0.1:$PROXY_PORT
export HTTPS_PROXY=http://127.0.0.1:$PROXY_PORT
export http_proxy=http://127.0.0.1:$PROXY_PORT
export https_proxy=http://127.0.0.1:$PROXY_PORT
export no_proxy=$NO_PROXY_DOMAINS
export NO_PROXY=$NO_PROXY_DOMAINS
$MARKER_END
EOF
ok "Blocco proxy scritto (vale per le nuove shell; per quella corrente: source ~/.zshrc)"

# --- 5. Proxy automatico di sistema (PAC) -------------------------------------------
step "Configurazione proxy automatico di sistema (PAC)"

# Mappa l'interfaccia di default (es. en0) sul network service (es. "Wi-Fi").
service_for_interface() {
    networksetup -listallhardwareports | awk -v dev="$1" '
        /^Hardware Port:/ { port = substr($0, index($0, ": ") + 2) }
        $1 == "Device:" && $2 == dev { print port }'
}

DEFAULT_IFACE="$(route -n get default 2>/dev/null | awk '/interface:/ { print $2 }' || true)"
ACTIVE_SERVICE=""
if [ -n "$DEFAULT_IFACE" ]; then
    ACTIVE_SERVICE="$(service_for_interface "$DEFAULT_IFACE")"
fi

SERVICES_TO_CONFIGURE=()
[ -n "$ACTIVE_SERVICE" ] && SERVICES_TO_CONFIGURE+=("$ACTIVE_SERVICE")
if [ "$ACTIVE_SERVICE" != "Wi-Fi" ] \
    && networksetup -listallnetworkservices | grep -qx "Wi-Fi"; then
    SERVICES_TO_CONFIGURE+=("Wi-Fi")
fi
[ ${#SERVICES_TO_CONFIGURE[@]} -gt 0 ] || die "Nessun network service attivo trovato (sei connesso a una rete?)."

for service in "${SERVICES_TO_CONFIGURE[@]}"; do
    if networksetup -setautoproxyurl "$service" "$PAC_URL" \
        && networksetup -setautoproxystate "$service" on; then
        ok "PAC configurato su \"$service\" → $PAC_URL"
    else
        warn "Impossibile configurare il PAC su \"$service\" (serve un utente amministratore?). Configuralo a mano da System Settings → Network → Proxies."
    fi
done

# --- 6. LaunchAgent del proxy --------------------------------------------------------
step "LaunchAgent $PROXY_LABEL (avvio al login, KeepAlive)"
mkdir -p "$LAUNCH_AGENTS_DIR" "$LOG_DIR"
cat > "$PROXY_PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
    <dict>
        <key>Label</key>
        <string>$PROXY_LABEL</string>

        <key>ProgramArguments</key>
        <array>
            <string>$ALPACA_BIN</string>
            <string>--auth-type=kerberos</string>
            <string>--krb-native</string>
            <string>--krb-spn</string>
            <string>$KRB_SPN</string>
            <string>--krb-debug</string>
            <string>-p</string>
            <string>$PROXY_PORT</string>
            <string>-C</string>
            <string>$PAC_URL</string>
        </array>

        <key>RunAtLoad</key>
        <true/>

        <key>KeepAlive</key>
        <true/>

        <key>StandardOutPath</key>
        <string>$OUT_LOG</string>

        <key>StandardErrorPath</key>
        <string>$ERR_LOG</string>
    </dict>
</plist>
EOF
launchctl bootstrap "$GUI_DOMAIN" "$PROXY_PLIST"
ok "Proxy avviato (porta $PROXY_PORT) e registrato per l'avvio al login"

# --- 7. Menu bar app -------------------------------------------------------------------
step "Build e installazione di Alpaca Menu Bar.app"
rm -rf "$APP_DIR"
mkdir -p "$APP_DIR/Contents/MacOS"
SDKROOT="$(xcrun --sdk macosx --show-sdk-path)" \
    swiftc -O -parse-as-library -suppress-warnings \
        -o "$APP_DIR/Contents/MacOS/AlpacaMenuBar" "$SCRIPT_DIR/AlpacaMenuBar.swift"

# Info.plist: LSUIElement nasconde l'app dal Dock; le chiavi Alpaca* sono la
# configurazione letta a runtime dalla app (stessi valori usati da questo script).
cat > "$APP_DIR/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
    <dict>
        <key>CFBundleIdentifier</key>
        <string>eu.leitha.alpaca.menubar</string>
        <key>CFBundleName</key>
        <string>Alpaca Menu Bar</string>
        <key>CFBundleExecutable</key>
        <string>AlpacaMenuBar</string>
        <key>CFBundlePackageType</key>
        <string>APPL</string>
        <key>CFBundleShortVersionString</key>
        <string>1.0</string>
        <key>LSUIElement</key>
        <true/>
        <key>NSHighResolutionCapable</key>
        <true/>
        <!-- Il PAC aziendale è http://: senza questa eccezione ATS blocca il
             probe di raggiungibilità e la rete risulta sempre "esterna" -->
        <key>NSAppTransportSecurity</key>
        <dict>
            <key>NSAllowsArbitraryLoads</key>
            <true/>
        </dict>

        <key>AlpacaProxyPort</key>
        <integer>$PROXY_PORT</integer>
        <key>AlpacaProxyLabel</key>
        <string>$PROXY_LABEL</string>
        <key>AlpacaProxyPlist</key>
        <string>$PROXY_PLIST</string>
        <key>AlpacaPACURL</key>
        <string>$PAC_URL</string>
        <key>AlpacaOutLog</key>
        <string>$OUT_LOG</string>
        <key>AlpacaErrLog</key>
        <string>$ERR_LOG</string>
    </dict>
</plist>
EOF
codesign --force -s - "$APP_DIR" >/dev/null 2>&1 || warn "codesign ad-hoc fallito (la app funziona comunque)"

cat > "$MENUBAR_PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
    <dict>
        <key>Label</key>
        <string>$MENUBAR_LABEL</string>

        <key>ProgramArguments</key>
        <array>
            <string>$APP_DIR/Contents/MacOS/AlpacaMenuBar</string>
        </array>

        <key>RunAtLoad</key>
        <true/>

        <key>KeepAlive</key>
        <false/>
    </dict>
</plist>
EOF
launchctl bootstrap "$GUI_DOMAIN" "$MENUBAR_PLIST"
ok "Menu bar app installata e avviata (icona nella barra in alto)"

# --- 8. Fase VPN: verifica finale ---------------------------------------------------------
step "Verifica finale (richiede la VPN Check Point attiva)"
if [ -t 0 ]; then
    printf '%s' "    Collega la VPN Check Point e premi INVIO per avviare il test (Ctrl-C per saltarlo)... "
    read -r _
else
    warn "stdin non interattivo: procedo subito con il test."
fi

PAC_REACHABLE=false
printf '    Attendo che il PAC aziendale sia raggiungibile'
for _ in $(seq 1 10); do
    if curl --noproxy '*' -sf -m 3 -o /dev/null "$PAC_URL"; then
        PAC_REACHABLE=true
        break
    fi
    printf '.'
    sleep 3
done
printf '\n'

if [ "$PAC_REACHABLE" = false ]; then
    warn "PAC non raggiungibile ($PAC_URL): VPN non attiva?"
    warn "Setup completato comunque. Quando sei sotto VPN, ottieni il ticket e testa con:"
    warn "    kinit LEIXXXXX@$KRB_REALM"
    warn "    curl -v -x http://127.0.0.1:$PROXY_PORT https://google.com"
    exit 0
fi
ok "PAC raggiungibile"

if klist -s 2>/dev/null; then
    ok "Ticket Kerberos già valido: $(klist 2>/dev/null | awk '/Principal:/ { print $2; exit }')"
elif [ -t 0 ]; then
    KINIT_DONE=false
    for _ in 1 2 3; do
        read -r -p "    Inserisci la tua LEI (es. lei12345): " LEI_INPUT
        LEI="$(printf '%s' "$LEI_INPUT" | tr -d '[:space:]' | tr '[:lower:]' '[:upper:]')"
        if ! [[ "$LEI" =~ ^LEI[0-9]+$ ]]; then
            warn "LEI non valida: \"$LEI_INPUT\" (formato atteso: lei seguita da numeri, es. lei12345)."
            continue
        fi
        printf '    kinit %s (ti verrà chiesta la password di dominio)\n' "$LEI@$KRB_REALM"
        if kinit "$LEI@$KRB_REALM"; then
            KINIT_DONE=true
            break
        fi
        warn "kinit fallito (password errata?). Riprova."
    done
    if [ "$KINIT_DONE" = true ]; then
        ok "Ticket Kerberos ottenuto per $LEI@$KRB_REALM"
    else
        warn "Nessun ticket Kerberos ottenuto. Puoi riprovare a mano con:  kinit LEIXXXXX@$KRB_REALM"
    fi
else
    warn "Nessun ticket Kerberos valido e stdin non interattivo: esegui a mano  kinit LEIXXXXX@$KRB_REALM"
fi

printf '    Test: curl -x http://127.0.0.1:%s https://google.com\n' "$PROXY_PORT"
HTTP_CODE="$(curl -s -o /dev/null -w '%{http_code}' \
    -x "http://127.0.0.1:$PROXY_PORT" --connect-timeout 10 -m 30 https://google.com || true)"
case "$HTTP_CODE" in
    2*|3*)
        ok "Proxy funzionante (HTTP $HTTP_CODE attraverso il tunnel CONNECT)"
        ;;
    *)
        warn "Test fallito (HTTP code: ${HTTP_CODE:-nessuna risposta}). Ultime righe di log:"
        tail -n 15 "$ERR_LOG" 2>/dev/null | sed 's/^/      /' || true
        die "Controlla i log completi in $OUT_LOG e $ERR_LOG, oppure usa la voce 'Apri log' della menu bar app."
        ;;
esac

step "Setup completato 🎉"
ok "Proxy attivo su http://127.0.0.1:$PROXY_PORT (riparte da solo al login)"
ok "Menu bar app attiva: stato, start/stop, log e test dalla barra in alto"
ok "Apri un nuovo terminale (o esegui: source ~/.zshrc) per usare le variabili proxy"
