#!/usr/bin/env bash
# Build Mifare SSH (MifareClassicTool fork) debug APK.
# Self-contained: creates a temporary Gradle init script with Maven mirrors
# (needed because dl.google.com / Google Maven may be unreachable), builds,
# and prints the APK path.
set -euo pipefail

cd "$(dirname "$0")/Mifare Classic Tool"

INIT_SCRIPT="$(mktemp /tmp/mct-mirrors-XXXXXX.init.gradle)"
trap 'rm -f "$INIT_SCRIPT"' EXIT

cat > "$INIT_SCRIPT" <<'EOF'
settingsEvaluated { settings ->
    settings.pluginManagement.repositories {
        maven { url 'https://maven.aliyun.com/repository/google' }
        maven { url 'https://maven.aliyun.com/repository/central' }
        maven { url 'https://maven.aliyun.com/repository/gradle-plugin' }
        maven { url 'https://mirrors.cloud.tencent.com/nexus/repository/maven-public/' }
        google()
        gradlePluginPortal()
        mavenCentral()
    }
    settings.dependencyResolutionManagement.repositories {
        maven { url 'https://maven.aliyun.com/repository/google' }
        maven { url 'https://maven.aliyun.com/repository/central' }
        maven { url 'https://maven.aliyun.com/repository/gradle-plugin' }
        maven { url 'https://mirrors.cloud.tencent.com/nexus/repository/maven-public/' }
        google()
        mavenCentral()
    }
}
EOF

./gradlew assembleDebug -I "$INIT_SCRIPT"

APK="app/build/outputs/apk/debug/app-debug.apk"
echo
echo "Build successful: $(pwd)/$APK"
