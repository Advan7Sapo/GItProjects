#!/bin/bash
# BLACKARCH_NETINSTALL_FULL.SH
# Full autonomous setup script for ADV7Prompt deployment (BlackArch + Hyprland)

set -e

loadkeys br-abnt2
ping -c 2 archlinux.org

cfdisk /dev/sda
mkfs.fat -F32 /dev/sda1
mkfs.ext4 /dev/sda2
mount /dev/sda2 /mnt
mkdir /mnt/boot
mount /dev/sda1 /mnt/boot

pacstrap /mnt base linux linux-firmware nano networkmanager grub efibootmgr sudo git vim

genfstab -U /mnt >> /mnt/etc/fstab
arch-chroot /mnt <<EOF
ln -sf /usr/share/zoneinfo/America/Sao_Paulo /etc/localtime
hwclock --systohc
echo "en_US.UTF-8 UTF-8" >> /etc/locale.gen
locale-gen
echo "LANG=en_US.UTF-8" > /etc/locale.conf
echo "blackarch" > /etc/hostname
passwd
systemctl enable NetworkManager
grub-install --target=x86_64-efi --efi-directory=/boot --bootloader-id=GRUB
grub-mkconfig -o /boot/grub/grub.cfg
EOF

umount -R /mnt
reboot

# Post-reboot Phase (run manually after boot):
curl -O https://blackarch.org/strap.sh
chmod +x strap.sh
./strap.sh
pacman -Syyu --noconfirm
pacman -S --noconfirm blackarch

pacman -Rns --noconfirm lightdm xfce4 xfce4-goodies
pacman -S --noconfirm hyprland kitty foot waybar rofi wofi thunar thunar-archive-plugin
pacman -S --noconfirm xdg-desktop-portal-hyprland xdg-desktop-portal

mkdir -p ~/.config/hypr
cp /usr/share/hyprland/hyprland.conf ~/.config/hypr/hyprland.conf

echo 'if [[ -z $DISPLAY ]] && [[ $(tty) = /dev/tty1 ]]; then exec Hyprland; fi' >> ~/.bash_profile

# ZSH Aesthetic Layer
pacman -S --noconfirm zsh zsh-autosuggestions zsh-syntax-highlighting starship
echo "source /usr/share/zsh/plugins/zsh-autosuggestions/zsh-autosuggestions.zsh" >> ~/.zshrc
echo "source /usr/share/zsh/plugins/zsh-syntax-highlighting/zsh-syntax-highlighting.zsh" >> ~/.zshrc
echo 'eval "$(starship init zsh)"' >> ~/.zshrc
mkdir -p ~/.config && echo -e '[prompt]\nadd_newline = false\n' > ~/.config/starship.toml
chsh -s /bin/zsh $USER

# Diagnostic Loop
cat <<'EOFLOOP' > /usr/local/bin/adv7loop.sh
#!/bin/bash
while true; do
  echo "Enter option [1=Check status, 0=Exit]: "
  read user_input
  if [[ "$user_input" == "1" ]]; then
    echo "System Check Output:" && uptime && df -h && free -m
  elif [[ "$user_input" == "0" || "$user_input" == "exit" ]]; then
    echo "Goodbye." && break
  else
    echo "Invalid option. Try again."
  fi
done
EOFLOOP
chmod +x /usr/local/bin/adv7loop.sh

# Guest additions
pacman -S --noconfirm virtualbox-guest-utils
systemctl enable vboxservice
usermod -aG vboxsf $USER

echo "Setup complete. Run 'adv7loop.sh' or reboot into Hyprland."
