#!/usr/bin/env bash
# Build Mifare SSH (MifareClassicTool fork) debug APK.
# Maven mirrors are configured in "Mifare Classic Tool/settings.gradle",
# so a plain manual build works too:
#   cd "Mifare Classic Tool" && ./gradlew assembleDebug
set -euo pipefail

cd "$(dirname "$0")/Mifare Classic Tool"

./gradlew clean assembleDebug

APK="app/build/outputs/apk/debug/app-debug.apk"
echo
echo "Build successful: $(pwd)/$APK"
