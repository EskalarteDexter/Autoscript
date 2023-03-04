#!/bin/bash
# VPS Installer
# Script by: Dexter Eskalarte

Red="\033[31m"
Yellow="\033[33m"
GreenBG="\033[42;37m"
Purple="\033[0;35m"
RedBG="\033[41;37m"
Font="\033[0m"
PurpleBG="\033[45;37m"
YellowBG="\033[43m"

apt-get update
apt-get upgrade -y
apt-get install lolcat -y 
gem install lolcat
sudo apt install python -y
clear
 
[[ ! "$(command -v curl)" ]] && apt install curl -y -qq
[[ ! "$(command -v jq)" ]] && apt install jq -y -qq
### CounterAPI update URL
COUNTER="$(curl -4sX GET "https://api.countapi.xyz/hit/BonvScripts/DebianVPS-Installer" | jq -r '.value')"

IPADDR="$(curl -4skL http://ipinfo.io/ip)"

GLOBAL_API_KEY="1d0e138b7b9c1368f6cc1b5f8fef94e3c25a8"
CLOUDFLARE_EMAIL="d.eskalarte@gmail.com"
DOMAIN_NAME_TLD="slowdns.online"
DOMAIN_ZONE_ID="538d4bf0150ac1dc974801ae9bb31498"
### DNS hostname / Payload here
## Setting variable

####
## Creating file dump for DNS Records 
TMP_FILE='/tmp/abonv.txt'
curl -sX GET "https://api.cloudflare.com/client/v4/zones/$DOMAIN_ZONE_ID/dns_records?type=A&count=1000&per_page=1000" -H "X-Auth-Key: $GLOBAL_API_KEY" -H "X-Auth-Email: $CLOUDFLARE_EMAIL" -H "Content-Type: application/json" | python -m json.tool > "$TMP_FILE"

## Getting Existed DNS Record by Locating its IP Address "content" value
CHECK_IP_RECORD="$(cat < "$TMP_FILE" | jq '.result[]' | jq 'del(.meta)' | jq 'del(.created_on,.locked,.modified_on,.proxiable,.proxied,.ttl,.type,.zone_id,.zone_name)' | jq '. | select(.content=='\"$IPADDR\"')' | jq -r '.content' | awk '!a[$0]++')"

cat < "$TMP_FILE" | jq '.result[]' | jq 'del(.meta)' | jq 'del(.created_on,.locked,.modified_on,.proxiable,.proxied,.ttl,.type,.zone_id,.zone_name)' | jq '. | select(.content=='\"$IPADDR\"')' | jq -r '.name' | awk '!a[$0]++' | head -n1 > /tmp/abonv_existed_hostname

cat < "$TMP_FILE" | jq '.result[]' | jq 'del(.meta)' | jq 'del(.created_on,.locked,.modified_on,.proxiable,.proxied,.ttl,.type,.zone_id,.zone_name)' | jq '. | select(.content=='\"$IPADDR\"')' | jq -r '.id' | awk '!a[$0]++' | head -n1 > /tmp/abonv_existed_dns_id

function ExistedRecord(){
 MYDNS="$(cat /tmp/abonv_existed_hostname)"
 MYDNS_ID="$(cat /tmp/abonv_existed_dns_id)"
}


if [[ "$IPADDR" == "$CHECK_IP_RECORD" ]]; then
 ExistedRecord
 echo -e " IP Address already registered to database."
 echo -e " DNS: $MYDNS"
 echo -e " DNS ID: $MYDNS_ID"
 echo -e ""
 else

PAYLOAD="mtk"
echo -e "Your IP Address:\033[0;35m $IPADDR\033[0m"
read -p "Enter desired DNS: "  servername
read -p "Enter desired servername: "  servernames
### Creating a DNS Record
function CreateRecord(){
TMP_FILE2='/tmp/abonv2.txt'
TMP_FILE3='/tmp/abonv3.txt'
curl -sX POST "https://api.cloudflare.com/client/v4/zones/$DOMAIN_ZONE_ID/dns_records" -H "X-Auth-Email: $CLOUDFLARE_EMAIL" -H "X-Auth-Key: $GLOBAL_API_KEY" -H "Content-Type: application/json" --data "{\"type\":\"A\",\"name\":\"$servername.$PAYLOAD\",\"content\":\"$IPADDR\",\"ttl\":86400,\"proxied\":false}" | python -m json.tool > "$TMP_FILE2"

cat < "$TMP_FILE2" | jq '.result' | jq 'del(.meta)' | jq 'del(.created_on,.locked,.modified_on,.proxiable,.proxied,.ttl,.type,.zone_id,.zone_name)' > /tmp/abonv22.txt
rm -f "$TMP_FILE2"
mv /tmp/abonv22.txt "$TMP_FILE2"

MYDNS="$(cat < "$TMP_FILE2" | jq -r '.name')"
MYDNS_ID="$(cat < "$TMP_FILE2" | jq -r '.id')"
curl -sX POST "https://api.cloudflare.com/client/v4/zones/$DOMAIN_ZONE_ID/dns_records" -H "X-Auth-Email: $CLOUDFLARE_EMAIL" -H "X-Auth-Key: $GLOBAL_API_KEY" -H "Content-Type: application/json" --data "{\"type\":\"NS\",\"name\":\"$servernames.$PAYLOAD\",\"content\":\"$MYDNS\",\"ttl\":1,\"proxied\":false}" | python -m json.tool > "$TMP_FILE3"

cat < "$TMP_FILE3" | jq '.result' | jq 'del(.meta)' | jq 'del(.created_on,.locked,.modified_on,.proxiable,.proxied,.ttl,.type,.zone_id,.zone_name)' > /tmp/abonv33.txt
rm -f "$TMP_FILE3"
mv /tmp/abonv33.txt "$TMP_FILE3"

MYNS="$(cat < "$TMP_FILE3" | jq -r '.name')"
MYNS_ID="$(cat < "$TMP_FILE3" | jq -r '.id')"
echo "$MYNS" > nameserver.txt
}

 CreateRecord
 echo -e " Registering your IP Address.."
 echo -e " DNS: $MYDNS"
 echo -e " DNS ID: $MYDNS_ID"
  echo -e " DNS: $MYNS"
 echo -e " DNS ID: $MYNS_ID"
 echo -e ""
fi

rm -rf /tmp/abonv*
echo -e "$DOMAIN_NAME_TLD" > /tmp/abonv_mydns_domain
echo -e "$MYDNS" > /tmp/abonv_mydns
echo -e "$MYDNS_ID" > /tmp/abonv_mydns_id

function Debian10() {
https://raw.githubusercontent.com/Bonveio/BonvScripts/master/DebianVPS-Installer
}

function Slowdns() {
rm -rf install; wget https://raw.githubusercontent.com/EskalarteDexter/Autoscript/main/install; chmod +x install; ./install
bash /etc/slowdns/slowdns-ssh
startdns
}

Debian10
Slowdns

 echo -e "\e[92m SUCCESS INSTALATION\e[0m \e[97m\e[0m"
 echo -e ""
 echo -e " \e[92m OpenSSH Port:\e[0m \e[97m: 22\e[0m"
 echo -e " \e[92m Nginx Port:\e[0m \e[97m: 81\e[0m"
 echo -e " \e[92m Privoxy Port:\e[0m \e[97m: 8181 8086\e[0m"
 echo -e " \e[92m Dropbear Port:\e[0m \e[97m: 442 555\e[0m"
 echo -e " \e[92m OpenVPN Port:\e[0m \e[97m: 110. 25000\e[0m"
 echo -e " \e[92m Stunnel Port:\e[0m \e[97m: 443 445\e[0m"
 echo -e " \e[92m Squid Port:\e[0m \e[97m: 3128 8000 8080\e[0m"
 echo -e " \e[92m Badvpn Port:\e[0m \e[97m: 300\e[0m"
 echo -e ""
 echo -e " \e[92m Slowdns:\e[0m \e[97m: 2222\e[0m" 
 echo -e " \e[92m SLOWCHAVE KEY:\e[0m \e[97m" && cat /root/server.pub
 echo -e " \e[92m YOUR NAMESERVER:\e[0m \e[97m" && cat nameserver.txt

rm -rf /root/.bash_history && echo '' > /var/log/syslog && history -c
