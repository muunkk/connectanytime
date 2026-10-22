#!/bin/zsh
# Build ConnectAnytime.app (Apple Silicon + Intel, macOS 13+).
#   ./build.sh            build and install to ~/Applications
#   ./build.sh --release  build and zip to build/ConnectAnytime.zip
set -euo pipefail
cd "${0:A:h}"
APP=build/ConnectAnytime.app
BIN="$APP/Contents/MacOS/ConnectAnytime"

rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS"
cp Info.plist "$APP/Contents/"
for arch in arm64 x86_64; do
  swiftc -O -swift-version 5 -target "$arch-apple-macos13" Sources/main.swift -o "build/ConnectAnytime-$arch"
done
lipo -create build/ConnectAnytime-arm64 build/ConnectAnytime-x86_64 -output "$BIN"
rm build/ConnectAnytime-arm64 build/ConnectAnytime-x86_64
codesign --force --sign - "$APP"

if [[ "${1:-}" == "--release" ]]; then
  rm -f build/ConnectAnytime.zip
  ditto -c -k --norsrc --noextattr --noqtn --keepParent "$APP" build/ConnectAnytime.zip
  echo "Built build/ConnectAnytime.zip"
  exit 0
fi

mkdir -p ~/Applications
pkill -x ConnectAnytime 2>/dev/null || true
rm -rf ~/Applications/ConnectAnytime.app
cp -R "$APP" ~/Applications/
echo "Installed ~/Applications/ConnectAnytime.app"
