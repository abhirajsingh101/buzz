#!/usr/bin/env bash
#
# Install this fork's Buzz desktop build, replacing any existing install.
#
#   curl -fsSL https://raw.githubusercontent.com/abhirajsingh101/buzz/personal/scripts/install-buzz-fork.sh | bash
#
# Resolves the current version from the updater manifest, so it stays correct
# for every future release without edits. Supports macOS (arm64/x64) and Linux.
#
# Data is preserved: the fork build keeps the upstream bundle identifier
# (xyz.block.buzz.app), so the app-data directory is unchanged, and the macOS
# keychain entry is keyed on the constant service name "buzz-desktop" rather
# than the code signature -- see desktop/src-tauri/src/secret_store.rs.
set -euo pipefail

REPO="${BUZZ_FORK_REPO:-abhirajsingh101/buzz}"
MANIFEST="https://github.com/$REPO/releases/download/buzz-desktop-latest/latest.json"
STAMP="$(date +%Y%m%d-%H%M%S)"

say() { printf '\033[1m%s\033[0m\n' "$*"; }
die() { printf '\033[31merror: %s\033[0m\n' "$*" >&2; exit 1; }

say "Resolving latest release from your fork…"
VER="$(curl -fsSL "$MANIFEST" \
  | sed -n 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1)"
[ -n "$VER" ] || die "could not read a version from $MANIFEST"
say "  version: $VER"

dl() { # dl <asset-name> <dest>
  curl -fL --progress-bar -o "$2" \
    "https://github.com/$REPO/releases/download/desktop-v${VER}/$1"
}

stop_app() {
  pkill -x buzz-desktop 2>/dev/null || true
  pkill -x Buzz 2>/dev/null || true
  while pgrep -x buzz-desktop >/dev/null 2>&1 || pgrep -x Buzz >/dev/null 2>&1; do
    sleep 1
  done
}

case "$(uname -s)" in
# ── macOS ──────────────────────────────────────────────────────────────────
Darwin)
  case "$(uname -m)" in
    arm64)  ASSET="Buzz_${VER}_aarch64.dmg" ;;
    x86_64) ASSET="Buzz_${VER}_x64.dmg" ;;
    *) die "unsupported arch $(uname -m)" ;;
  esac

  say "Stopping Buzz…"; stop_app

  DATA="$HOME/Library/Application Support/xyz.block.buzz.app"
  if [ -d "$DATA" ]; then
    BK="$HOME/Desktop/buzz-data-$STAMP.tgz"
    say "Backing up app data (caches excluded)…"
    tar --exclude=WebKitCache --exclude=CacheStorage -czf "$BK" \
      -C "$HOME/Library/Application Support" xyz.block.buzz.app
    say "  $BK"
  fi

  if [ -d /Applications/Buzz.app ]; then
    # Kept OUT of /Applications so LaunchServices never sees two apps
    # claiming the same bundle identifier.
    mv /Applications/Buzz.app "$HOME/Desktop/Buzz-previous-$STAMP.app"
    say "Previous app -> ~/Desktop/Buzz-previous-$STAMP.app (rollback copy)"
  fi

  say "Downloading $ASSET…"; dl "$ASSET" "/tmp/$ASSET"
  MNT="$(hdiutil attach "/tmp/$ASSET" -nobrowse | grep -o '/Volumes/.*' | head -1)"
  [ -n "$MNT" ] || die "could not mount $ASSET"
  ditto "$MNT/Buzz.app" /Applications/Buzz.app
  hdiutil detach "$MNT" -quiet
  rm -f "/tmp/$ASSET"

  # Required: this build is ad-hoc signed, not notarized. Without this macOS
  # refuses to launch it ("damaged and can't be opened").
  xattr -dr com.apple.quarantine /Applications/Buzz.app
  APP=/Applications/Buzz.app
  EXE="$APP/Contents/MacOS/$(/usr/libexec/PlistBuddy -c 'Print :CFBundleExecutable' "$APP/Contents/Info.plist")"
  ;;

# ── Linux ──────────────────────────────────────────────────────────────────
Linux)
  ASSET="Buzz_${VER}_amd64.AppImage"
  say "Stopping Buzz…"; stop_app
  mkdir -p "$HOME/Applications"
  say "Downloading $ASSET…"; dl "$ASSET" "$HOME/Applications/Buzz.AppImage.new"
  chmod +x "$HOME/Applications/Buzz.AppImage.new"
  mv "$HOME/Applications/Buzz.AppImage.new" "$HOME/Applications/Buzz.AppImage"
  EXE="$HOME/Applications/Buzz.AppImage"
  ;;

*) die "unsupported OS $(uname -s)" ;;
esac

# ── Verify we installed the fork build, not upstream's ─────────────────────
# grep -a, not `strings`: strings needs Xcode command line tools on macOS.
# The trailing `|| true` is required: grep exits 1 when it matches nothing, and
# under `set -euo pipefail` that would abort the script mid-install.
say "Verifying updater endpoint…"
FOUND="$(grep -ao 'https://github\.com/[^/]*/buzz/releases/download/buzz-desktop-latest/latest\.json' "$EXE" 2>/dev/null | sort -u | head -1 || true)"
case "$FOUND" in
  *"/${REPO%%/*}/"*)
    say "  OK -> $FOUND" ;;
  "")
    # Expected on Linux: an AppImage is a compressed squashfs, so the string
    # lives inside the image and is not greppable from the outer file. macOS
    # .app binaries are uncompressed, so verification is real there.
    if [ "$(uname -s)" = Linux ]; then
      say "  (AppImage is compressed — endpoint not greppable; this is normal)"
    else
      printf '\033[33m  could not read endpoint from binary — verify manually\033[0m\n'
    fi ;;
  *)
    die "installed build points at $FOUND — that is NOT your fork" ;;
esac

say ""
say "Installed Buzz $VER from $REPO."
# `if`, not `[ … ] && cat`: on Linux the test fails, and as the script's last
# command that would make a successful install exit non-zero.
if [ "$(uname -s)" = Darwin ]; then
  cat <<'EOF'
  Launch it from the Mac itself the first time: macOS will show a keychain
  prompt ("Buzz wants to access buzz-desktop") that cannot be answered over
  SSH. Click "Always Allow" — that is the ad-hoc signature not yet being on
  the keychain item's ACL, and approving preserves your existing identity.
EOF
fi
