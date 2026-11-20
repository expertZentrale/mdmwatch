#!/bin/sh
# Baut MDM Watch und packt es als macOS-App.
#
#   ./bundle.sh                  -> target/MDM Watch.app (aktuelle Architektur)
#   UNIVERSAL=1 ./bundle.sh      -> Universal-Binary (Apple Silicon + Intel)
#   VERSION=1.2.0 ./bundle.sh    -> Versionsnummer setzen
#   ./bundle.sh /Applications    -> zusätzlich dorthin kopieren
set -e
cd "$(dirname "$0")"
VERSION="${VERSION:-0.1.0}"
APP="target/MDM Watch.app"

if [ -n "$UNIVERSAL" ]; then
  cargo build --release --target aarch64-apple-darwin
  cargo build --release --target x86_64-apple-darwin
  mkdir -p target/universal
  lipo -create -output target/universal/mdmwatch \
    target/aarch64-apple-darwin/release/mdmwatch \
    target/x86_64-apple-darwin/release/mdmwatch
  BIN=target/universal/mdmwatch
else
  cargo build --release
  BIN=target/release/mdmwatch
fi

rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "$BIN" "$APP/Contents/MacOS/MDMWatch"
cat > "$APP/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key><string>MDM Watch</string>
  <key>CFBundleDisplayName</key><string>MDM Watch</string>
  <key>CFBundleIdentifier</key><string>com.github.expertzentrale.mdmwatch</string>
  <key>CFBundleExecutable</key><string>MDMWatch</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>${VERSION}</string>
  <key>CFBundleVersion</key><string>${VERSION}</string>
  <key>LSMinimumSystemVersion</key><string>13.0</string>
  <key>NSHighResolutionCapable</key><true/>
  <key>LSApplicationCategoryType</key><string>public.app-category.utilities</string>
</dict>
</plist>
EOF
# ad-hoc signieren (kein Developer-ID-Zertifikat)
codesign --force --deep --sign - "$APP" >/dev/null 2>&1 || true
echo "fertig: $APP"
if [ -n "$1" ]; then
  rm -rf "$1/MDM Watch.app"
  cp -R "$APP" "$1/"
  echo "kopiert nach: $1/MDM Watch.app"
fi
