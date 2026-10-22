#!/bin/bash

# @raycast.schemaVersion 1
# @raycast.title Toggle NYU VPN
# @raycast.mode silent
# @raycast.icon 🔒
# @raycast.packageName ConnectAnytime

APP=/Applications/ConnectAnytime.app
[ -d "$APP" ] || APP="$HOME/Applications/ConnectAnytime.app"
"$APP/Contents/MacOS/ConnectAnytime" --toggle
