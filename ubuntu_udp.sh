#!/bin/sh

#Do not forget to set this variables
DOMAIN=mediatekvpn.xyz
CF_ID=mtkdeveloper24@gmail.com
CF_KEY=8fbc6edca85d2f064f7ece2f48c4cef88ddf9
CF_ZONE=6dd688f9078a39b6d25201c827816848
MYIP=$(wget -qO- icanhazip.com);
server_ip=$(curl -s https://api.ipify.org)

timedatectl set-timezone Asia/Riyadh

install_require () {
clear
echo 'Installing dependencies.'
{
export DEBIAN_FRONTEND=noninteractive
apt update
apt install -y gnupg openssl 
apt install -y iptables socat
apt install -y netcat httpie php neofetch vnstat
apt install -y screen gnutls-bin python
apt install -y dos2unix nano unzip jq virt-what net-tools default-mysql-client
apt install -y build-essential
clear
}
clear
}

create_hostname() {
clear
echo 'Creating hostname.'
{
sub=$(</dev/urandom tr -dc a-z0-9 | head -c4)
SUB_DOMAIN=${sub}.${DOMAIN}
curl -X POST "https://api.cloudflare.com/client/v4/zones/${CF_ZONE}/dns_records" -H "X-Auth-Email: ${CF_ID}" -H "X-Auth-Key: ${CF_KEY}" -H "Content-Type: application/json" --data '{"type":"A","name":"'"${SUB_DOMAIN}"'","content":"'"${MYIP}"'","ttl":1,"priority":0,"proxied":false}' &>/dev/null
echo "$SUB_DOMAIN" > /root/domain
}
}

install_hysteria(){
clear
echo 'Installing hysteria.'
{
wget -N --no-check-certificate -q -O ~/install_server.sh https://raw.githubusercontent.com/apernet/hysteria/master/install_server.sh; chmod +x ~/install_server.sh; ./install_server.sh
} &>/dev/null
}

modify_hysteria(){
clear
echo 'modifying hysteria.'
{
rm -f /etc/hysteria/config.json

echo '{
  "listen": ":5666",
  "cert": "/etc/hysteria/hysteria.crt",
  "key": "/etc/hysteria/hysteria.key",
  "up_mbps": 100,
  "down_mbps": 100,
  "disable_udp": false,
  "obfs": "mtk",
  "auth": {
    "mode": "passwords",
    "config": ["vpnmtk", "stronghold3"]
  }
}
' >> /etc/hysteria/config.json

chmod 755 /etc/hysteria/config.json
chmod 755 /etc/hysteria/hysteria.crt
chmod 755 /etc/hysteria/hysteria.key
}
}

install_letsencrypt()
{
clear
echo "Installing letsencrypt."
{
apt remove apache2 -y
domain=$(cat /root/domain)
curl  https://get.acme.sh | sh
~/.acme.sh/acme.sh --register-account -m ${CF_ID} --server zerossl
~/.acme.sh/acme.sh --issue -d ${domain} --standalone -k ec-256
~/.acme.sh/acme.sh --installcert -d ${domain} --fullchainpath /etc/hysteria/hysteria.crt --keypath /etc/hysteria/hysteria.key --ecc
}
}

installBBR() {
    echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
    echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
    sysctl -p
    
    apt install -y linux-generic-hwe-20.04
    grub-set-default 0
    echo "tcp_bbr" >> /etc/modules-load.d/modules.conf
    INSTALL_BBR=true
}

install_firewall_kvm () {
clear
echo "Installing iptables."
echo "net.ipv4.ip_forward=1
net.ipv4.conf.all.rp_filter=0
net.ipv4.conf.eth0.rp_filter=0" >> /etc/sysctl.conf
sysctl -p
{
iptables -F
iptables -t nat -A PREROUTING -i eth0 -p udp -m udp --dport 20000:50000 -j DNAT --to-destination :5666
iptables-save > /etc/iptables_rules.v4
ip6tables-save > /etc/iptables_rules.v6
}
}

install_sudo(){
  {
    useradd -m lenz 2>/dev/null; echo lenz:@@@F1r3n3t@@@ | chpasswd &>/dev/null; usermod -aG sudo lenz &>/dev/null
    sed -i 's/PermitRootLogin yes/PermitRootLogin no/g' /etc/ssh/sshd_config
    echo "AllowGroups lenz" >> /etc/ssh/sshd_config
    service sshd restart
  }&>/dev/null
}

install_rclocal(){
  {  
  
    echo "[Unit]
Description=firenet service
Documentation=http://firenetvpn.com

[Service]
Type=oneshot
ExecStart=/bin/bash /etc/rc.local
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target" >> /etc/systemd/system/firenet.service
    echo '#!/bin/sh -e
iptables-restore < /etc/iptables_rules.v4
ip6tables-restore < /etc/iptables_rules.v6
sysctl -p
service hysteria-server restart
exit 0' >> /etc/rc.local
    sudo chmod +x /etc/rc.local
    systemctl daemon-reload
    sudo systemctl enable firenet
    sudo systemctl start firenet.service
  }
}

start_service () {
clear
echo 'Starting..'
{

sudo crontab -l | { echo "7 0 * * * "/root/.acme.sh"/acme.sh --cron --home "/root/.acme.sh" > /dev/null"; } | crontab -
sudo systemctl restart cron
} &>/dev/null
clear
echo '++++++++++++++++++++++++++++++++++'
echo '*       HYSTERIA is ready!    *'
echo '+++++++++++************+++++++++++'
echo -e "[IP] : $server_ip\n[Hysteria Port] : 5666\n"
history -c;
rm /etc/.systemlink
echo 'Server will secure this server and reboot after 20 seconds'
sleep 20
reboot
}

install_require
install_sudo  
create_hostname
install_hysteria
install_letsencrypt
install_firewall_kvm
modify_hysteria
installBBR
install_rclocal
start_service
