FROM ubuntu:26.04
RUN apt-get update -q && DEBIAN_FRONTEND=noninteractive apt-get install -y -q systemd systemd-sysv dbus kmod iproute2 sudo cron libpam-sss pamtester gsettings-desktop-schemas dconf-cli openssh-server ufw nano cowsay && rm -f /etc/systemd/system/*.wants/* 2>/dev/null; true
RUN systemctl enable ssh && mkdir -p /usr/share/dconf/profile && printf 'user-db:user\nfile-db:/var/lib/gdm3/greeter-dconf-defaults\n' > /usr/share/dconf/profile/gdm
RUN useradd -m -s /bin/bash kit && echo 'kit:Correct-Horse-9x' | chpasswd
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
