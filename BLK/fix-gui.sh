#!/bin/bash

echo "[+] Atualizando sistema..."
pacman -Syu --noconfirm

echo "[+] Instalando XFCE + LightDM + Greeter..."
pacman -S --noconfirm xfce4 xfce4-goodies lightdm lightdm-gtk-greeter

echo "[+] Instalando drivers para VirtualBox e Xorg..."
pacman -S --noconfirm virtualbox-guest-utils xf86-video-vmware xorg-server xorg-xinit

echo "[+] Habilitando serviços necessários..."
systemctl enable lightdm.service
systemctl enable vboxservice.service

echo "[+] Corrigindo configuração do greeter..."
sed -i 's/^#greeter-session=.*/greeter-session=lightdm-gtk-greeter/' /etc/lightdm/lightdm.conf
sed -i 's/^greeter-session=.*/greeter-session=lightdm-gtk-greeter/' /etc/lightdm/lightdm.conf

echo "[+] Criando .xinitrc padrão para fallback..."
echo "exec startxfce4" > /root/.xinitrc

echo "[+] Reiniciando sistema para aplicar mudanças..."
reboot
