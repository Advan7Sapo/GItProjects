#!/bin/bash

echo "[+] Atualizando pacman.conf para garantir acesso aos repositórios essenciais..."
sed -i '/^\[extra\]/,/^$/s/^#//' /etc/pacman.conf
sed -i '/^\[community\]/,/^$/s/^#//' /etc/pacman.conf

echo "[+] Sincronizando pacotes..."
pacman -Sy --noconfirm

echo "[+] Removendo drivers quebrados (vmware)..."
pacman -Rns --noconfirm xf86-video-vmware

echo "[+] Instalando drivers de vídeo e integração para VirtualBox..."
pacman -S --noconfirm virtualbox-guest-utils xf86-video-vesa xf86-video-fbdev
systemctl enable vboxservice
systemctl start vboxservice

echo "[+] Instalando base para compilação (yay)..."
pacman -S --noconfirm git base-devel

if [ ! -d /opt/yay ]; then
  cd /opt
  git clone https://aur.archlinux.org/yay.git
  chown -R $USER:$USER yay
  cd yay
  sudo -u $USER makepkg -si --noconfirm
else
  echo "[i] yay já instalado."
fi

echo "[+] Instalando Hyprland via AUR..."
sudo -u $USER yay -S hyprland-git --noconfirm

echo "[+] Instalando dependências gráficas essenciais..."
pacman -S --noconfirm xorg-xwayland xorg-xinit xdg-desktop-portal-hyprland \
  waybar rofi alacritty kitty neofetch network-manager-applet \
  polkit-gnome pipewire wireplumber pavucontrol brightnessctl \
  wl-clipboard grim slurp nautilus flameshot lxappearance \
  ttf-font-awesome ttf-jetbrains-mono noto-fonts

echo "[+] Removendo LightDM e XFCE caso ainda existam..."
systemctl disable lightdm 2>/dev/null
pacman -Rns --noconfirm lightdm lightdm-gtk-greeter xfce4 xfce4-goodies

echo "[+] Criando .xinitrc para fallback..."
echo "exec Hyprland" > /root/.xinitrc
cp /root/.xinitrc /home/$USER/.xinitrc 2>/dev/null

echo "[+] Aplicando configuração personalizada do Hyprland..."
mkdir -p /home/$USER/.config/hypr
cat > /home/$USER/.config/hypr/hyprland.conf <<EOF
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

bind = SUPER, RETURN, exec, alacritty
bind = SUPER, D, exec, rofi -show drun
bind = SUPER, Q, killactive
bind = SUPER, E, exec, nautilus
bind = SUPER SHIFT, S, exec, grim -g "\$(slurp)" - | wl-copy
bind = SUPER, F, togglefloating
bind = SUPER, M, exit
bind = SUPER, SPACE, togglefloating

bind = SUPER, 1, workspace, 1
bind = SUPER, 2, workspace, 2
bind = SUPER, 3, workspace, 3
bind = SUPER, 4, workspace, 4
bind = SUPER, 5, workspace, 5
EOF

chown -R $USER:$USER /home/$USER/.config /home/$USER/.xinitrc 2>/dev/null

echo "[✓] Setup finalizado com sucesso!"
echo "[➡] Reinicie e digite: startx"
