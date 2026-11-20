#!/bin/zsh
# Build ConnectAnytime.app (Apple Silicon + Intel, macOS 13+).
#   ./build.sh            build and install to ~/Applications
#   ./build.sh --release  build a signed, notarized build/ConnectAnytime.dmg (to download)
#                         and build/ConnectAnytime.zip (for the in-app updater)
#
# Signing uses the "Developer ID Application" certificate in your keychain (ad-hoc if there
# is none, for local builds only). Releases also need notarization credentials, stored once:
#   xcrun notarytool store-credentials connectanytime-notary \
#     --key ~/.appstoreconnect/private_keys/AuthKey_<KEYID>.p8 --key-id <KEYID> --issuer <ISSUER-UUID>
set -euo pipefail
cd "${0:A:h}"
APP=build/ConnectAnytime.app
BIN="$APP/Contents/MacOS/ConnectAnytime"
NOTARY_PROFILE=${NOTARY_PROFILE:-connectanytime-notary}
RELEASE=0; [[ "${1:-}" == "--release" ]] && RELEASE=1

IDENTITY=$(security find-identity -v -p codesigning | awk -F'"' '/Developer ID Application/ { print $2; exit }')
if (( RELEASE )); then
  [[ -n "$IDENTITY" ]] || { echo "No Developer ID Application certificate in the keychain." >&2; exit 1; }
  xcrun notarytool history --keychain-profile "$NOTARY_PROFILE" >/dev/null 2>&1 ||
    { echo "No notarization credentials named $NOTARY_PROFILE (see the top of build.sh)." >&2; exit 1; }
fi

rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS"
cp Info.plist "$APP/Contents/"
for arch in arm64 x86_64; do
  swiftc -O -swift-version 5 -target "$arch-apple-macos13" Sources/main.swift -o "build/ConnectAnytime-$arch"
done
lipo -create build/ConnectAnytime-arm64 build/ConnectAnytime-x86_64 -output "$BIN"
rm build/ConnectAnytime-arm64 build/ConnectAnytime-x86_64

if [[ -n "$IDENTITY" ]]; then
  codesign --force --options runtime --timestamp --sign "$IDENTITY" "$APP"
else
  echo "No Developer ID certificate found: signing ad-hoc." >&2
  codesign --force --sign - "$APP"
fi
codesign --verify --strict "$APP"

if (( RELEASE )); then
  notarize() { xcrun notarytool submit "$1" --keychain-profile "$NOTARY_PROFILE" --wait --timeout 30m; }

  # Notarize and staple the app itself, so it opens cleanly however it's copied.
  rm -f build/ConnectAnytime.zip build/ConnectAnytime.dmg
  ditto -c -k --norsrc --noextattr --noqtn --keepParent "$APP" build/ConnectAnytime.zip
  notarize build/ConnectAnytime.zip
  xcrun stapler staple "$APP"
  rm build/ConnectAnytime.zip
  ditto -c -k --norsrc --noextattr --noqtn --keepParent "$APP" build/ConnectAnytime.zip

  # Drag-and-drop disk image: the app next to a link to /Applications.
  STAGE=build/dmg
  rm -rf "$STAGE"; mkdir -p "$STAGE"
  ditto "$APP" "$STAGE/ConnectAnytime.app"
  ln -s /Applications "$STAGE/Applications"
  hdiutil create -volname ConnectAnytime -srcfolder "$STAGE" -fs HFS+ -format UDZO -ov build/ConnectAnytime.dmg
  rm -rf "$STAGE"
  codesign --force --timestamp --sign "$IDENTITY" build/ConnectAnytime.dmg
  notarize build/ConnectAnytime.dmg
  xcrun stapler staple build/ConnectAnytime.dmg

  spctl --assess --type execute "$APP"
  spctl --assess --type open --context context:primary-signature build/ConnectAnytime.dmg
  echo "Built build/ConnectAnytime.dmg and build/ConnectAnytime.zip"
  exit 0
fi

mkdir -p ~/Applications
pkill -x ConnectAnytime 2>/dev/null || true
rm -rf ~/Applications/ConnectAnytime.app
cp -R "$APP" ~/Applications/
echo "Installed ~/Applications/ConnectAnytime.app"
