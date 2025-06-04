#!/bin/bash
# ADV7Unified Setup Script - Full GUI Swap to Hyprland + System Preparation + Fan/Sensor Enhancements
# Version: ADV7-FULL-MERGE-v4.0
# Scope: BlackArch (VM or Bare Metal)

LOG_FILE="/var/log/adv7-unified-install.log"
USER_HOME="$(getent passwd $SUDO_USER | cut -d: -f6)"

log() {
  echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# --------- ROOT CHECK ---------
if [[ $EUID -ne 0 ]]; then
  echo "[ERROR] Run as root." >&2
  exit 1
fi

log "==[ ADV7 UNIFIED SETUP STARTED ]=="

# --------- PRE-SETUP CLEANUP ---------
log "Purging legacy GUI stack: XFCE + LightDM."
systemctl stop lightdm 2>> "$LOG_FILE"
apt purge --autoremove -y lightdm xfce4 xfce4-* >> "$LOG_FILE" 2>&1

# --------- BASE SYSTEM UPDATE & PREP ---------
log "Updating system and installing core build tools."
apt update && apt upgrade -y >> "$LOG_FILE" 2>&1
apt install -y git sudo curl wget build-essential \
  libwayland-dev libxkbcommon-dev wayland-protocols \
  wlroots libxcb1-dev libinput-dev libseat-dev \
  seatd xwayland xdg-desktop-portal-wlr >> "$LOG_FILE" 2>&1

# --------- HYPRLAND INSTALLATION ---------
if ! command -v Hyprland &>/dev/null; then
  log "Cloning and building Hyprland."
  git clone --depth=1 https://github.com/hyprwm/Hyprland.git /opt/Hyprland >> "$LOG_FILE" 2>&1
  cd /opt/Hyprland || exit 1
  make all >> "$LOG_FILE" 2>&1 && make install >> "$LOG_FILE" 2>&1
else
  log "Hyprland already installed."
fi

# --------- CONFIGURATION DEPLOYMENT ---------
log "Setting up Hyprland config for user: $SUDO_USER."
mkdir -p "$USER_HOME/.config/hypr"
cp -n /opt/Hyprland/example/hyprland.conf "$USER_HOME/.config/hypr/hyprland.conf" 2>/dev/null || true
chown -R $SUDO_USER:$SUDO_USER "$USER_HOME/.config/hypr"

# --------- AUTOSTART & AUTLOGIN SETUP ---------
log "Configuring system autologin + Hyprland autostart."
mkdir -p /etc/systemd/system/getty@tty1.service.d
cat <<EOC > /etc/systemd/system/getty@tty1.service.d/override.conf
[Service]
ExecStart=
ExecStart=-/sbin/agetty --autologin $SUDO_USER --noclear %I \$TERM
EOC

cat <<'EOC' > "$USER_HOME/.bash_profile"
if [[ -z $DISPLAY ]] && [[ $(tty) = /dev/tty1 ]]; then
  exec Hyprland
fi
EOC
chown $SUDO_USER:$SUDO_USER "$USER_HOME/.bash_profile"

systemctl enable seatd >> "$LOG_FILE" 2>&1
systemctl enable getty@tty1 >> "$LOG_FILE" 2>&1

# --------- OPTIONAL POST-INSTALL UTILITIES ---------
log "Installing optional utilities for Pentest GUI Ops."
apt install -y neofetch htop pavucontrol pipewire wireplumber rofi >> "$LOG_FILE" 2>&1

# --------- FAN & TEMPERATURE SENSOR CONFIGURATION ---------
log "Installing fan control and sensor packages."
apt install -y lm-sensors fancontrol psensor >> "$LOG_FILE" 2>&1
log "Running sensors-detect (automated mode)."
echo -e "\n\n\nYES\nYES\nYES\nYES\n" | sensors-detect --auto >> "$LOG_FILE" 2>&1

log "Setting up fancontrol service."
systemctl enable fancontrol >> "$LOG_FILE" 2>&1 || log "[WARN] fancontrol may require manual config in /etc/fancontrol"

# --------- FINALIZATION ---------
log "Setup complete. You may reboot into Hyprland on TTY1."
echo -e "\n[✔] ADV7 GUI + System + Fan/Sensor Config Complete — Reboot Recommended."
