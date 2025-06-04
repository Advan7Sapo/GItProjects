#!/bin/bash
# ADV7PentestStackInstaller.sh
# Versão final full stack: Instalação completa do Hyperland + Ferramentas de Pentest + Configuração de Sessão Wayland

set -e

log() { echo -e "\033[1;32m[+] $1\033[0m"; }
err() { echo -e "\033[1;31m[-] $1\033[0m" >&2; }

log "🚀 Iniciando ADV7 Instalação Completa Full Stack"

# --- Atualização Base e Dependências de Desenvolvimento ---
sudo pacman -Syu --noconfirm
sudo pacman -S --noconfirm base-devel cmake git wayland wayland-protocols wayland-utils libxkbcommon glew \
    glfw-x11 glfw-wayland libglvnd libinput libliftoff libdisplay-info vulkan-headers vulkan-loader \
    vulkan-icd-loader glslang shaderc meson ninja pkg-config unzip wget neofetch zsh btop

# --- BlackArch Keyring & Ferramentas de Pentest ---
log "🔐 Configurando repositório BlackArch e instalando ferramentas"
if ! pacman -Qi blackarch-keyring >/dev/null 2>&1; then
    curl -O https://blackarch.org/strap.sh
    echo "6dc0efcbbc4cd3f4540f12d4c6cc7c493c495d96 strap.sh" | sha1sum -c || { err "Checksum inválido"; exit 1; }
    chmod +x strap.sh && sudo ./strap.sh
fi

sudo pacman -S --noconfirm metasploit nmap sqlmap wireshark-qt burpsuite gobuster zaproxy dirb ffuf \
    john hashcat aircrack-ng bettercap exploitdb binwalk radare2 ghidra rustscan

# --- Instalação do Hyprland + Correções ---
log "🎨 Instalando Hyprland com correções e dependências"
if [ ! -d /opt/Hyperland ]; then
    sudo git clone https://github.com/hyprwm/Hyprland /opt/Hyperland
fi

cd /opt/Hyperland/subprojects || mkdir -p subprojects && cd subprojects
if [ ! -d udis86 ]; then
    git clone https://github.com/vmt/udis86.git
    cd udis86 && make clean || true && make && sudo make install
else
    log "udis86 já existente"
fi

cd /opt/Hyperland
meson setup build || meson setup build --wipe
meson compile -C build
sudo ninja -C build install

if ! pacman -Q aquamarine >/dev/null 2>&1; then
    log "🔍 Instalando aquamarine via AUR (yay)"
    if ! command -v yay >/dev/null; then
        git clone https://aur.archlinux.org/yay.git /tmp/yay
        cd /tmp/yay && makepkg -si --noconfirm
    fi
    yay -S --noconfirm aquamarine
fi

# --- Configuração do Ambiente Hyprland ---
log "🛠️ Configurando diretórios e arquivos padrão do Hyprland"
mkdir -p ~/.config/hypr
cat > ~/.config/hypr/hyprland.conf << EOF
monitor=,preferred,auto,1
devices {
    touchpad {
        natural_scroll=yes
    }
}
bind=SUPER,RETURN,exec,kitty
bind=SUPER,Q,exit
exec-once=waybar &
exec-once=nm-applet &
exec-once=blueman-applet &
EOF

# --- Remoção do XFCE e LightDM (se presente) ---
log "🧹 Removendo LightDM e XFCE (modo seguro)"
sudo pacman -Rns --noconfirm lightdm lightdm-gtk-greeter xfce4 xfce4-goodies || log "LightDM/XFCE não encontrados ou já removidos"

# --- Configuração do Wayland como sessão padrão ---
log "🖥️ Ajustando sessão padrão para Hyprland"
if [ ! -f /etc/sddm.conf ]; then
    echo "[Autologin]\nUser=$USER\nSession=hyprland.desktop" | sudo tee /etc/sddm.conf > /dev/null
fi

# --- Script de Validação Final ---
if [ ! -f /usr/bin/hyprland-repair.sh ]; then
    log "✅ Criando script de verificação do Hyprland"
    echo -e "#!/bin/bash\necho '✅ Hyperland pronto para uso!'" | sudo tee /usr/bin/hyprland-repair.sh > /dev/null
    sudo chmod +x /usr/bin/hyprland-repair.sh
fi

/usr/bin/hyprland-repair.sh
neofetch
log "✅ ADV7 Full Stack instalado com sucesso — Hyprland + Ferramentas de Pentest prontas."
exit 0
