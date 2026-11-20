# MDM Watch

Kleine macOS-App, um zu sehen, was Intune/MDM auf einem Mac gerade tut. Entstanden beim Testen des Mac-Rollouts über Intune.

Die App **liest nur**. Sie ändert keine Profile, Einstellungen oder Dateien des Systems.

## Was sie zeigt

| Reiter | Inhalt |
|---|---|
| **Übersicht** | Enrollment-Status, Kennzahlen und alle Auffälligkeiten auf einen Blick |
| **MDM-Befehle** | Jeder Befehl vom MDM-Server live (InstallProfile, RemoveProfile, InstallApplication …) mit Antwort `Acknowledged` / `Error` / `NotNow` und Fehlertext |
| **MDM-Log** | Unified Log von `mdmclient` / `ManagedClient` live, filterbar |
| **Intune-Agent** | Apps und Skripte aus `/Library/Logs/Microsoft/Intune`, je Richtlinie mit Fehlerzähler, dazu der Live-Log |
| **Profile** | Alle installierten Konfigurationsprofile mit Payload-Inhalt (Passwörter und Schlüssel geschwärzt) |
| **VPN & DNS** | VPN-Verbindungen im Abgleich mit dem Profil, aus dem sie stammen (erkennt z. B. verloren gegangene DNS-Match-Domänen oder verwaiste Verbindungen), DNS-Resolver und ein Test der Namensauflösung |
| **Änderungen** | Alle 30 s wird der Zustand verglichen; jede Änderung an Profilen, VPN-Konfigurationen und Enrollment wird mit vorher/nachher protokolliert |
| **Verlauf** | Bis zu 7 Tage MDM-Log nachladen: Befehle und wiederholte Fehler |

## Installation

1. Unter **Releases** (oder bei einem Build unter **Actions → Artifacts**) die `MDM-Watch-….zip` laden und entpacken.
2. `MDM Watch.app` nach `/Applications` ziehen (braucht Admin-Rechte).
3. Die App ist nicht mit einem Apple-Developer-Zertifikat signiert. Beim ersten Start daher **Rechtsklick → Öffnen**, oder im Terminal:

   ```bash
   xattr -dr com.apple.quarantine "/Applications/MDM Watch.app"
   ```

## Admin-Zugriff

Ohne Admin-Rechte sieht die App die Benutzer-Profile, VPN/DNS und das Intune-Agent-Log.

Für das **MDM-Log** und die **Geräte-Profile** braucht es root. Dafür oben **„Admin-Zugriff aktivieren“** klicken: macOS fragt nach Name und Passwort eines Admin-Kontos und startet einen kleinen Helfer (dieselbe Binärdatei mit `--helper`) als root. Der Helfer

- liest `log stream` für `mdmclient` und alle 30 s `profiles show -all`,
- schreibt die Ergebnisse nach `~/Library/Application Support/MDMWatch/run/` (Dateien gehören dem Benutzer, Zugriffe ohne Symlinks zu folgen),
- beendet sich, sobald die App geschlossen wird oder „Admin beenden“ geklickt wird.

## Daten

`~/Library/Application Support/MDMWatch/`

- `changes.jsonl`: Änderungsprotokoll
- `snapshot.json`: letzter Zustand (Vergleichsbasis)
- `hosts.json`: Namen für den DNS-Test
- `run/`: Ausgaben des Admin-Helfers

## Selbst bauen

Voraussetzung: Rust (`rustup`), Xcode Command Line Tools.

```bash
./bundle.sh                 # target/MDM Watch.app für diese Architektur
UNIVERSAL=1 ./bundle.sh     # Apple Silicon + Intel
cargo test --release
```

Screenshots aller Reiter für Doku/Fehlersuche:

```bash
MDMWATCH_SHOTS=/tmp/shots ./target/release/mdmwatch
```

## Build & Release

GitHub Actions baut bei jedem Push auf `main` ein Universal-Binary (Artefakt am Workflow-Lauf). Ein Tag `v*` erzeugt zusätzlich ein Release mit der Zip:

```bash
git tag v0.1.0 && git push origin v0.1.0
```

## Aufbau

| Datei | Inhalt |
|---|---|
| `src/app.rs` | Zustand, Hintergrund-Threads, Oberfläche (eframe/egui) |
| `src/data.rs` | Profile, Netzwerk-Erweiterungen (NSKeyedArchiver-Plist), Drift-Prüfung, DNS |
| `src/mdm.rs` | Auswertung des mdmclient-Logs, Befehls-Tracking |
| `src/intune.rs` | Intune-Agent-Logs lesen und verfolgen |
| `src/helper.rs` | root-Helfer |
