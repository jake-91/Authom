#!/usr/bin/env bash
# Prepare the NSIS toolchain that `tauri build` needs, without letting the CLI
# download it itself.
#
# Why this exists: the CLI extracts NSIS into %LOCALAPPDATA%\tauri and then
# renames the extracted folder into place. Under a virtualised AppData (MSIX /
# App-V containers, some redirected profiles) that rename fails with
# `os error 17` even though both paths are on the same volume, and the CLI
# deletes its half-built toolchain on every retry. Laying the files down by
# hand sidesteps the rename entirely.
#
# Safe to re-run. On an ordinary machine you never need this — plain
# `npm run app:build` works.

set -euo pipefail

NSIS_URL="https://github.com/tauri-apps/binary-releases/releases/download/nsis-3.11/nsis-3.11.zip"
NSIS_SHA1="ef7ff767e5cbd9edd22add3a32c9b8f4500bb10d"

# Version pinned to what the installed CLI verifies. If `tauri build` starts
# reporting a hash mismatch, read the new URL and SHA1 out of the CLI binary:
#   grep -aoE "nsis-tauri-utils/releases/download/[^\"]+" \
#     node_modules/@tauri-apps/cli-win32-x64-msvc/*.node
PLUGIN_URL="https://github.com/tauri-apps/nsis-tauri-utils/releases/download/nsis_tauri_utils-v0.5.3/nsis_tauri_utils.dll"
PLUGIN_SHA1="75197fee3c6a814fe035788d1c34ead39349b860"

CACHE="${LOCALAPPDATA:-$HOME/AppData/Local}"
CACHE="$(cygpath -u "$CACHE" 2>/dev/null || echo "$CACHE")/tauri"
NSIS_DIR="$CACHE/NSIS"

verify() {
  local file="$1" expected="$2" actual
  actual="$(sha1sum "$file" | cut -d' ' -f1)"
  if [ "$actual" != "$expected" ]; then
    echo "  해시 불일치: $file" >&2
    echo "    기대: $expected" >&2
    echo "    실제: $actual" >&2
    return 1
  fi
}

mkdir -p "$CACHE"

if [ ! -d "$CACHE/nsis-3.11" ]; then
  echo "NSIS 3.11 내려받는 중..."
  curl -sSL -o "$CACHE/nsis.zip" "$NSIS_URL"
  verify "$CACHE/nsis.zip" "$NSIS_SHA1"
  unzip -q -o "$CACHE/nsis.zip" -d "$CACHE"
  rm -f "$CACHE/nsis.zip"
fi

echo "툴체인 배치 중..."
rm -rf "$NSIS_DIR"
cp -r "$CACHE/nsis-3.11" "$NSIS_DIR"

echo "tauri 플러그인 내려받는 중..."
mkdir -p "$NSIS_DIR/Plugins/x86-unicode/additional"
curl -sSL -o "$NSIS_DIR/Plugins/x86-unicode/additional/nsis_tauri_utils.dll" "$PLUGIN_URL"
verify "$NSIS_DIR/Plugins/x86-unicode/additional/nsis_tauri_utils.dll" "$PLUGIN_SHA1"

# The CLI wipes and re-downloads the whole toolchain if any one of these is
# absent, so check them before handing over.
REQUIRED=(
  "makensis.exe"
  "Bin/makensis.exe"
  "Stubs/lzma-x86-unicode"
  "Stubs/lzma_solid-x86-unicode"
  "Plugins/x86-unicode/additional/nsis_tauri_utils.dll"
  "Include/MUI2.nsh"
  "Include/FileFunc.nsh"
  "Include/x64.nsh"
  "Include/nsDialogs.nsh"
  "Include/WinMessages.nsh"
  "Include/Win/COM.nsh"
  "Include/Win/Propkey.nsh"
  "Include/Win/RestartManager.nsh"
)

missing=0
for f in "${REQUIRED[@]}"; do
  [ -e "$NSIS_DIR/$f" ] || { echo "  누락: $f" >&2; missing=$((missing + 1)); }
done

if [ "$missing" -ne 0 ]; then
  echo "필수 파일 $missing 개가 없습니다. 인스톨러 빌드가 실패합니다." >&2
  exit 1
fi

echo "완료: $NSIS_DIR"
echo "이제 'npm run app:build' 를 실행하세요."
