# ConnectAnytime

A menu-bar Connect/Disconnect button for the NYU Shanghai VPN on macOS.

Cisco Secure Client makes you type your password, type `push`, approve Duo, then click
**Accept** on NYU's notice. ConnectAnytime does all of that for you except the Duo approval:
click **Connect**, approve the push on your phone, and you're on.

It doesn't replace Cisco Secure Client. It drives Cisco's own command-line client
(`/opt/cisco/secureclient/bin/vpn`) in the background, so the VPN itself is still Cisco's.

## What it does

- **Connect / Disconnect** from the menu bar. The icon shows the state:
  `network` connected, `network.slash` disconnected, `network.badge.shield.half.filled`
  connecting, waiting for Duo or reconnecting.
- **Answers Cisco's prompts**: username, password, `push` for Duo, then accepts NYU's
  connection notice (the banner you'd otherwise click **Accept** on). You still approve
  Duo yourself.
- **Auto-connect on networks you choose.** On a network, pick
  **Auto-Connect Networks ▸ Add Current Network…**. Joining it later starts a connect if the
  VPN is off, including when the app starts while you're already on it. It tries once per
  join, so a manual disconnect or an ignored Duo push is never retried. Networks are recognised by the router's hardware address, so no Location
  permission is needed. Rename or remove them from the same menu.
- **Keyboard shortcut** via any launcher: run
  `/Applications/ConnectAnytime.app/Contents/MacOS/ConnectAnytime --toggle`
  (or `--connect` / `--disconnect`). A Raycast script command is in `scripts/raycast/`.

## Your password

- Stored in your macOS Keychain. Other apps must ask your permission to read it.
- Sent only to Cisco's client, through a private terminal session. Never written to a file,
  a log, a command line or the clipboard.
- The app's own network traffic is a ping to your router, to identify the network for
  auto-connect, and the daily update check, a plain request to GitHub for the latest
  release (no account, usage or network details).
- Your username comes from Cisco Secure Client's saved settings (`~/.vpn/.anyconnect`), so
  connect once with Cisco's app first.

It answers each prompt at most once. A wrong password fails instead of retrying, so it
can't lock your account.

## Install

Requires macOS 13+ (Apple Silicon or Intel) and Cisco Secure Client.

1. Download `ConnectAnytime.dmg` from the
   [latest release](https://github.com/muunkk/connectanytime/releases/latest) and open it.
2. Drag `ConnectAnytime` onto the Applications folder next to it.
3. Open it from Applications. It's signed and notarized by Apple, so it opens without a
   security warning.
4. Click the globe in the menu bar, then **Connect**. It asks for your NYU password once.

Optional: turn on **Launch at Login** in the menu.

## Updates

The app checks GitHub for a new release once a day and shows **Update to x.y.z…** in the
menu when there is one (or choose **Check for Updates…**). The update dialog shows that
release's notes before you install it. Installing downloads the release's
`ConnectAnytime.zip`, checks it against the SHA-256 GitHub publishes for it, checks the app
inside is intact (bundle ID, version, and a code signature from this project's Developer ID),
then swaps it in and restarts. The VPN connection isn't touched. Updating from 0.1.x to 0.2.0
or later, macOS asks once whether the app can use its Keychain item: choose **Always Allow**.
Later updates don't ask.

## Build from source

Requires Xcode command-line tools.

```sh
./build.sh             # build and install to ~/Applications
./build.sh --release   # build signed, notarized build/ConnectAnytime.dmg and .zip
```

Builds are signed with the Developer ID certificate in your keychain if there is one, ad-hoc
otherwise (macOS may then ask about the Keychain item after each rebuild: choose
**Always Allow**). `--release` needs the Developer ID certificate and notarization
credentials; the top of `build.sh` shows the one-time setup. Publish both files on the
GitHub release: the `.dmg` is the download, the `.zip` is what the in-app updater installs.

Log: `~/Library/Logs/ConnectAnytime.log`. It records which prompts were answered and
Cisco's status lines, never what was typed.

## Notes

- Cisco's command-line client can't connect while the Cisco Secure Client window app is
  running, so Connect quits that app first.
- Not affiliated with Cisco or NYU.

## License

MIT
