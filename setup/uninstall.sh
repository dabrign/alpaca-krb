#!/bin/bash
#
# Rimuove tutto quello che setup.sh ha installato/configurato:
# LaunchAgent, binario, menu bar app, blocco proxy in ~/.zshrc, PAC di sistema.
# Non tocca il clone della repo.
#
# Uso:  ./setup/uninstall.sh
set -euo pipefail

PAC_URL="http://wpadu.ha.servizi.gr-u.it/wpadu.dat"

INSTALL_DIR="$HOME/Library/Application Support/Alpaca"
APP_DIR="$HOME/Applications/Alpaca Menu Bar.app"
LAUNCH_AGENTS_DIR="$HOME/Library/LaunchAgents"
PROXY_LABEL="alpaca.background"
PROXY_PLIST="$LAUNCH_AGENTS_DIR/$PROXY_LABEL.plist"
MENUBAR_LABEL="alpaca.menubar"
MENUBAR_PLIST="$LAUNCH_AGENTS_DIR/$MENUBAR_LABEL.plist"
OUT_LOG="$HOME/Library/Logs/alpaca.out.log"
ERR_LOG="$HOME/Library/Logs/alpaca.err.log"
ZSHRC="$HOME/.zshrc"
MARKER_BEGIN="# >>> alpaca proxy >>>"
MARKER_END="# <<< alpaca proxy <<<"

GUI_DOMAIN="gui/$(id -u)"

if [ -t 1 ]; then
    C_OK=$'\033[1;32m'; C_WARN=$'\033[1;33m'; C_OFF=$'\033[0m'
else
    C_OK=""; C_WARN=""; C_OFF=""
fi
ok()   { printf '%s✔ %s%s\n' "$C_OK" "$*" "$C_OFF"; }
warn() { printf '%s⚠ %s%s\n' "$C_WARN" "$*" "$C_OFF"; }

# LaunchAgent
launchctl bootout "$GUI_DOMAIN/$PROXY_LABEL"   2>/dev/null || true
launchctl bootout "$GUI_DOMAIN/$MENUBAR_LABEL" 2>/dev/null || true
rm -f "$PROXY_PLIST" "$MENUBAR_PLIST"
ok "LaunchAgent fermati e rimossi"

# Binario e menu bar app
rm -rf "$INSTALL_DIR" "$APP_DIR"
rm -f "$OUT_LOG" "$ERR_LOG"
ok "Binario, menu bar app e log rimossi"

# Blocco proxy in ~/.zshrc
if [ -f "$ZSHRC" ] && grep -qF "$MARKER_BEGIN" "$ZSHRC"; then
    TMP_ZSHRC="$(mktemp)"
    awk -v b="$MARKER_BEGIN" -v e="$MARKER_END" '
        $0 == b { skip = 1; next }
        $0 == e { skip = 0; next }
        !skip' "$ZSHRC" > "$TMP_ZSHRC"
    mv "$TMP_ZSHRC" "$ZSHRC"
    ok "Blocco proxy rimosso da $ZSHRC (vale per le nuove shell)"
fi

# PAC di sistema: disattiva l'automatic proxy configuration solo sui servizi
# che puntano ancora al PAC aziendale configurato da setup.sh.
networksetup -listallnetworkservices 2>/dev/null | tail -n +2 | sed 's/^\*//' \
| while IFS= read -r service; do
    if networksetup -getautoproxyurl "$service" 2>/dev/null | grep -qF "$PAC_URL"; then
        if networksetup -setautoproxystate "$service" off; then
            ok "PAC di sistema disattivato su \"$service\""
        else
            warn "Impossibile disattivare il PAC su \"$service\": fallo da System Settings → Network → Proxies."
        fi
    fi
done

ok "Disinstallazione completata"
