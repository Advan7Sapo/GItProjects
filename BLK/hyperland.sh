#!/bin/bash

set -e

# Verificacoes iniciais
if [ "$(id -u)" -ne 0 ]; then
  echo "Este script precisa ser executado como root."
  exit 1
fi

if ! grep -qi 'blackarch\|arch' /etc/os-release; then
  echo "Este script foi feito para BlackArch (base Arch Linux)."
  exit 1
fi

# Atualiza sistema
pacman -Syu --noconfirm

# Instala dependencias basicas
pacman -S --noconfirm git base-devel wget vim tmux htop curl

# Define o usuario alvo
TARGET_USER=${SUDO_USER:-root}
USER_HOME=$(eval echo ~$TARGET_USER)

# Instala AUR helper (yay)
if ! command -v yay &>/dev/null; then
  sudo -u "$TARGET_USER" bash -c '
    cd /tmp && \
    git clone https://aur.archlinux.org/yay.git && \
    cd yay && \
    makepkg -si --noconfirm
  '
fi

# Instala Hyprland e dependencias
sudo -u "$TARGET_USER" yay -S --noconfirm hyprland-git waybar dunst alacritty rofi \
  swaylock swayidle xdg-desktop-portal-hyprland grim slurp wl-clipboard \
  pipewire wireplumber network-manager-applet ttf-fira-code papirus-icon-theme \
  swww

# Instala ferramentas essenciais de pentest (interface grafica)
pacman -S --noconfirm wireshark-qt burpsuite nmap metasploit armitage \
  sqlmap zaproxy john aircrack-ng tcpdump openvpn firefox

# Configura Hyprland
HYPR_DIR="$USER_HOME/.config/hypr"
mkdir -p "$HYPR_DIR"

cat <<'CFG' > "$HYPR_DIR/hyprland.conf"
# Configuracao Hyprland focada em pentest
exec-once = swww-daemon && swww img ~/.config/hypr/wallpapers/hack.jpg
exec-once = waybar &
exec-once = dunst &
exec-once = nm-applet &
exec-once = swayidle -w &
exec-once = alacritty -e ~/.config/hypr/pentest-start.sh &

monitor=,preferred,auto,1

# Workspaces por aplicacao
workspace = 1
workspace = 2
workspace = 3
workspace = 4
workspace = 5

$mod = SUPER
bind = $mod, RETURN, exec, alacritty
bind = $mod, Q, killactive
bind = $mod, E, exec, rofi -show drun
bind = $mod, W, exec, firefox
bind = $mod, S, exec, bash -c 'burpsuite; hyprctl dispatch workspace 3'
bind = $mod, N, exec, bash -c 'alacritty -e nmap; hyprctl dispatch workspace 4'
bind = $mod, M, exec, bash -c 'alacritty -e msfconsole; hyprctl dispatch workspace 4'
bind = $mod, A, exec, bash -c 'alacritty -e aircrack-ng; hyprctl dispatch workspace 5'
bind = $mod, Z, exec, bash -c 'zaproxy; hyprctl dispatch workspace 3'

# Layout de tiling automatico
windowrulev2 = float,class:^(burpsuite|zaproxy)$
windowrulev2 = size 80% 80%,class:^(burpsuite|zaproxy)$
windowrulev2 = move 10% 10%,class:^(burpsuite|zaproxy)$
windowrulev2 = tile,class:^(alacritty|firefox)$
CFG

mkdir -p "$HYPR_DIR/wallpapers"
wget -qO "$HYPR_DIR/wallpapers/hack.jpg" https://wallpapercave.com/wp/wp2563137.jpg || echo "Aviso: falha ao baixar wallpaper."

chown -R "$TARGET_USER:$TARGET_USER" "$HYPR_DIR"

# Painel inicial com dicas
cat <<'EOT' > "$HYPR_DIR/pentest-start.sh"
#!/bin/bash
clear
echo "============================================"
echo "  Ambiente de Pentest Iniciado com Hyprland"
echo "============================================"
echo -e "\nAtalhos Disponíveis:"
echo "SUPER + RETURN  => Terminal (Alacritty)"
echo "SUPER + E       => Rofi Launcher"
echo "SUPER + W       => Firefox (WS 2)"
echo "SUPER + S       => BurpSuite (WS 3)"
echo "SUPER + Z       => OWASP ZAP (WS 3)"
echo "SUPER + N       => Nmap Terminal (WS 4)"
echo "SUPER + M       => Metasploit Console (WS 4)"
echo "SUPER + A       => Aircrack-ng (WS 5)"
echo -e "\nUse os workspaces para organizar ferramentas de forma produtiva."
echo "============================================"
echo
bash
EOT

chmod +x "$HYPR_DIR/pentest-start.sh"
chown "$TARGET_USER:$TARGET_USER" "$HYPR_DIR/pentest-start.sh"

# Configura autostart do Hyprland
PROFILE_FILE="$USER_HOME/.bash_profile"
if ! grep -q Hyprland "$PROFILE_FILE"; then
  echo '[[ -z $DISPLAY && $XDG_VTNR -eq 1 ]] && exec Hyprland' >> "$PROFILE_FILE"
fi

chown "$TARGET_USER:$TARGET_USER" "$PROFILE_FILE"

# Mensagem final
echo -e "\nHyprland com ambiente de pentest completo e visual configurado com sucesso! Reinicie para iniciar automaticamente."
