#!/bin/bash
# ADV7 Hyprland Project Final Script — Full Automated Flow v7.0
# Includes: Build, Validate, Launcher, Icon, Bundle, GitHub Upload

set -e
LOG_FILE="$HOME/adv7-hyprland-final.log"
REPO="adv7team/hyprland-tools"
TAG="release-$(date +%Y%m%d%H%M)"
SCRIPT_BASE="$HOME"
BUNDLE_NAME="adv7-hyprland-bundle.tar.gz"

log() {
  echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

header() {
  echo -e "\n==========================="
  echo -e " ADV7 FINAL SETUP SCRIPT  "
  echo -e "==========================="
}

# Step 1: Build Hyprland if needed
build_hyprland() {
  log "Checking Hyprland installation..."
  if ! command -v Hyprland &>/dev/null; then
    log "Building Hyprland from source..."
    apt update && apt install -y git build-essential
    # Advanced: Backup or clean /opt/Hyprland if it exists and is not empty
    if [ -d /opt/Hyprland ] && [ "$(ls -A /opt/Hyprland)" ]; then
      log "/opt/Hyprland exists and is not empty. Backing up to /opt/Hyprland.bak.$(date +%s)"
      mv /opt/Hyprland "/opt/Hyprland.bak.$(date +%s)"
    fi
    git clone --depth=1 https://github.com/hyprwm/Hyprland.git /opt/Hyprland
    cd /opt/Hyprland && make all && make install
    log "Hyprland installed."
  else
    log "Hyprland already present."
  fi
}

# Step 2: Validate system
validate_env() {
  log "Validating system environment..."
  bash "$SCRIPT_BASE/adv7-final-hyprland-repair.sh" --repair
}

# Step 3: Generate launcher
generate_launcher() {
  log "Creating multi-terminal launcher..."
  bash "$SCRIPT_BASE/adv7-gui-launcher-complete.sh"
}

# Step 4: Package everything
package_bundle() {
  log "Packing scripts, icon, and launcher..."
  tar -czf "$SCRIPT_BASE/$BUNDLE_NAME" \
    "$SCRIPT_BASE/adv7-hyprland-menu.sh" \
    "$SCRIPT_BASE/.icons/adv7.png" \
    "$SCRIPT_BASE/.local/share/applications/adv7-hyprland-menu.desktop" 2>/dev/null
  log "Bundle created at: $SCRIPT_BASE/$BUNDLE_NAME"
}

# Step 5: Push to GitHub
push_to_github() {
  if ! command -v gh &>/dev/null; then
    log "[ERROR] GitHub CLI not installed. Skipping upload."
    return
  fi
  log "Pushing bundle to GitHub..."
  gh release create "$TAG" "$SCRIPT_BASE/$BUNDLE_NAME" \
    --title "ADV7 Hyprland Toolkit $TAG" \
    --notes "Automated full release with launcher, config, icon, and script." \
    --repo "$REPO" \
    --generate-notes
  log "Uploaded to: https://github.com/$REPO/releases/tag/$TAG"
}

# Run all
header
build_hyprland
validate_env
generate_launcher
package_bundle
push_to_github

log "✅ ADV7 Full Project Build Complete."
