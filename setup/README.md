# Setup proxy aziendale (alpaca) per macOS

Configura un Mac aziendale a dominio per usare **alpaca** come proxy locale su
`127.0.0.1:3128`, con autenticazione Kerberos nativa (ticket del dominio dal
Keychain, nessuna password da inserire).

## Prerequisiti

- Mac a dominio, utente amministratore
- **Xcode Command Line Tools**: `xcode-select --install`
- **Go ≥ 1.24**: `brew install go` oppure da <https://go.dev/dl/>

## Installazione

Da **wifi esterno, senza VPN e senza proxy configurati**:

```sh
git clone https://github.com/dabrign/alpaca-krb.git
cd alpaca-krb
./setup/setup.sh
```

Lo script fa tutto da solo (build, configurazione, avvio) e alla fine si ferma
chiedendo di **collegare la VPN Check Point**: collegala, premi INVIO e parte la
fase finale. Se manca un ticket Kerberos valido, lo script chiede la **LEI**
(va bene anche minuscola, es. `lei12345`) ed esegue
`kinit LEI12345@DIREZIONE.GR-U.IT` chiedendo la **password di dominio**; poi
parte il test (`curl https://google.com` attraverso il proxy).

Lo script è **idempotente**: si può rieseguire in qualsiasi momento, ad esempio
per aggiornare alpaca dopo un `git pull`.

### Cosa installa

| Cosa | Dove |
|---|---|
| Binario alpaca | `~/Library/Application Support/Alpaca/alpaca` |
| Menu bar app | `~/Applications/Alpaca Menu Bar.app` |
| Avvio automatico proxy | `~/Library/LaunchAgents/alpaca.background.plist` (KeepAlive: riparte se crasha) |
| Avvio automatico menu bar | `~/Library/LaunchAgents/alpaca.menubar.plist` |
| Variabili proxy shell | blocco marcato in `~/.zshrc` (`HTTP_PROXY`, `HTTPS_PROXY`, `no_proxy`, …) |
| Proxy automatico di sistema | PAC `http://wpadu.ha.servizi.gr-u.it/wpadu.dat` via `networksetup` |
| Log | `~/Library/Logs/alpaca.out.log` e `alpaca.err.log` |

## Menu bar app

Dopo il setup compare un'icona nella barra in alto, sempre attiva:

- 🛡️✓ **scudo con spunta** — tutto ok: proxy attivo. In rete aziendale significa
  ticket Kerberos valido; fuori VPN alpaca manda le richieste in connessione
  diretta (bypass): è normale, non serve fare nulla (il dettaglio è nel menu)
- ⚠️ **triangolo** — problema: in rete aziendale ma ticket Kerberos assente o
  scaduto → `kinit`
- 🛡️🚫 **scudo barrato** — proxy fermo

Dal menu: stato proxy e ticket, **avvia/ferma/riavvia** il proxy, **test
connettività**, **apertura log**, attivazione/disattivazione del **proxy di
sistema (PAC)** e dell'**avvio al login**. Ai cambi di stato (proxy caduto,
ticket scaduto, ripristino) arriva una notifica.

## Verifica manuale

```sh
curl -v -x http://127.0.0.1:3128 https://google.com
# atteso: "HTTP/1.1 200 Connection Established" e poi la risposta del sito
```

## Troubleshooting

- **`407 Proxy Authentication Required` / test fallito con VPN attiva**: ticket
  Kerberos assente o scaduto → `kinit LEIXXXXX@DIREZIONE.GR-U.IT` (poi `klist`
  per verificare).
- **Il proxy non parte**: guarda i log (`Apri log` dal menu, oppure
  `tail -f ~/Library/Logs/alpaca.err.log`). Stato del job:
  `launchctl print gui/$(id -u)/alpaca.background`.
- **Le variabili proxy non ci sono nel terminale**: apri una nuova finestra o
  esegui `source ~/.zshrc`.
- **`networksetup` fallisce nel setup**: serve un utente amministratore; in
  alternativa configura a mano System Settings → Network → *connessione in
  uso* → Details… → Proxies → Automatic proxy configuration con l'URL del PAC.

## Disinstallazione

```sh
./setup/uninstall.sh
```

Ferma e rimuove LaunchAgent, binario, menu bar app, log, blocco in `~/.zshrc` e
disattiva il PAC di sistema. Il clone della repo non viene toccato.
