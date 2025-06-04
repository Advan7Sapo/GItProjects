#!/bin/bash

echo "[+] Removendo LightDM, XFCE e greeters antigos..."
systemctl disable lightdm 2>/dev/null
pacman -Rns --noconfirm lightdm lightdm-gtk-greeter xfce4 xfce4-goodies

echo "[+] Atualizando o sistema..."
pacman -Syu --noconfirm

echo "[+] Instalando Hyprland e pacotes essenciais para pentest e VM..."
pacman -S --noconfirm \
  hyprland xorg-xwayland xorg-xinit \
  xdg-desktop-portal-hyprland waybar rofi \
  alacritty kitty neofetch \
  network-manager-applet polkit-gnome pipewire wireplumber \
  pavucontrol brightnessctl wl-clipboard grim slurp \
  ttf-font-awesome ttf-jetbrains-mono noto-fonts \
  virtualbox-guest-utils xf86-video-vmware nautilus flameshot lxappearance

echo "[+] Ativando suporte à integração VirtualBox..."
systemctl enable vboxservice
systemctl start vboxservice

echo "[+] Configurando .xinitrc para fallback de inicialização..."
echo "exec Hyprland" > ~/.xinitrc

echo "[+] Criando configuração personalizada do Hyprland..."
mkdir -p ~/.config/hypr

cat > ~/.config/hypr/hyprland.conf <<EOF
# Hyprland Config - Pentest VM Optimized

monitor=,preferred,auto,1

exec-once = nm-applet &
exec-once = polkit-gnome-authentication-agent-1 &
exec-once = waybar &
exec-once = lxappearance &
exec-once = neofetch --logo never --config none --color_blocks on

env = XCURSOR_SIZE,24
env = GDK_SCALE,1

input {
  kb_layout = us
  follow_mouse = 1
  touchpad {
    natural_scroll = yes
  }
}

general {
  gaps_in = 5
  gaps_out = 10
  border_size = 2
  col.active_border = rgba(33cc33ee)
  col.inactive_border = rgba(222222aa)
  layout = dwindle
}

decoration {
  rounding = 8
  drop_shadow = false
}

animations {
  enabled = no
}

dwindle {
  pseudotile = yes
  preserve_split = yes
}

gestures {
  workspace_swipe = false
}

misc {
  disable_hyprland_logo = true
  mouse_move_enables_dpms = true
}

# BINDINGS PENTEST
bind = SUPER, RETURN, exec, alacritty
bind = SUPER, D, exec, rofi -show drun
bind = SUPER, Q, killactive
bind = SUPER, E, exec, nautilus
bind = SUPER SHIFT, S, exec, grim -g "\$(slurp)" - | wl-copy
bind = SUPER, F, togglefloating
bind = SUPER, M, exit
bind = SUPER, SPACE, togglefloating

# Workspaces
bind = SUPER, 1, workspace, 1
bind = SUPER, 2, workspace, 2
bind = SUPER, 3, workspace, 3
bind = SUPER, 4, workspace, 4
bind = SUPER, 5, workspace, 5
EOF

echo "[✓] Instalação e configuração finalizada com sucesso!"
echo "[ℹ] Reinicie com: sudo reboot"
echo "[➡] Depois, inicie com: startx"
