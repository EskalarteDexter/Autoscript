#!/bin/bash
# BonChan Autoscript
# Modded by: Dexter Eskalarte

# Please respect author's Property
# Wag n Wag ibebebenta mga Kupal...
#############################
#############################

MyScriptName='DexterEskalarte'
WS_Port1='80'
WS_Port2='444'
SSH_Port1='22'
SSH_Port2='225'
SSH_Banner='http://script.psytech-vpn.com/setup/debian_wssh/server_message.txt'
Dropbear_Port1='550'
Dropbear_Port2='500'
Stunnel_Port1='443' 
Stunnel_Port2='445'
Stunnel_Port3='587'
OpenVPN_Port1='110'
OpenVPN_Port2='1194'
Proxy_Port1='8080'
 Proxy_Port2='8000'
Privoxy_Port1='9191'
Privoxy_Port2='9090'
OvpnDownload_Port='86'
MyVPS_Time='Asia/Manila'
function InstUpdates(){
 export DEBIAN_FRONTEND=noninteractive
 apt-get update
 apt-get upgrade -y
 apt-get -o Acquire::ForceIPv4=true install python dos2unix stunnel4 dropbear screen curl -y
 apt-get install nano wget curl zip unzip tar gzip p7zip-full bc rc openssl cron net-tools dnsutils dos2unix screen bzip2 ccrypt -y
 apt-get install dropbear stunnel4 privoxy ca-certificates nginx ruby apt-transport-https lsb-release squid screenfetch -y
 apt-get install perl libnet-ssleay-perl openssl libauthen-pam-perl libpam-runtime libio-pty-perl apt-show-versions python dbus libxml-parser-perl -y
 apt-get install shared-mime-info jq -y
 gem install lolcat
 apt-get autoremove -y
 echo "deb http://build.openvpn.net/debian/openvpn/stable $(lsb_release -sc) main" >/etc/apt/sources.list.d/openvpn.list && apt-key del E158C569 && wget -O - https://swupdate.openvpn.net/repos/repo-public.gpg | apt-key add -
 wget -qO security-openvpn-net.asc "https://keys.openpgp.org/vks/v1/by-fingerprint/F554A3687412CFFEBDEFE0A312F5F7B42F2B01E7" && gpg --import security-openvpn-net.asc
 apt-get update -y
 apt-get install openvpn -y
rm -rf {/usr/bin/ffsend,/usr/local/bin/ffsend}
printf "%b\n" "\e[32m[\e[0mInfo\e[32m]\e[0m\e[97m running FFSend installation on background\e[0m"
screen -S ffsendinstall -dm bash -c "curl -4skL "http://script.psytech-vpn.com/setup/debian_wssh/ffsend-v0.2.65-linux-x64-static" -o /usr/bin/ffsend && chmod a+x /usr/bin/ffsend"
hostnamectl set-hostname localhost &> /dev/null
printf "%b\n" "\e[32m[\e[0mInfo\e[32m]\e[0m\e[97m running DDoS-deflate installation on background\e[0m"
cat <<'ddosEOF'> /tmp/install-ddos.bash
#!/bin/bash
if [[ -e /etc/ddos ]]; then
 printf "%s\n" "DDoS-deflate already installed" && exit 1
else
 curl -4skL "https://github.com/jgmdev/ddos-deflate/archive/master.zip" -o ddos.zip
 unzip -qq ddos.zip
 rm -rf ddos.zip
 cd ddos-deflate-master
 echo -e "/r/n/r/n"
 ./install.sh &> /dev/null
 cd .. && rm -rf ddos-deflate-master
 systemctl start ddos &> /dev/null
 systemctl enable ddos &> /dev/null
fi
ddosEOF
screen -S ddosinstall -dm bash -c "bash /tmp/install-ddos.bash && rm -f /tmp/install-ddos.bash"
}
function InstWebmin(){
 cat <<'webminEOF'> /tmp/install-webmin.bash
#!/bin/bash
if [[ -e /etc/webmin ]]; then
 echo 'Webmin already installed' && exit 1
fi
rm -rf /etc/apt/sources.list.d/webmin*
echo 'deb https://download.webmin.com/download/repository sarge contrib' > /etc/apt/sources.list.d/webmin.list
apt-key del 1719003ACE3E5A41E2DE70DFD97A3AE911F63C51 &> /dev/null
wget -qO - https://download.webmin.com/jcameron-key.asc | apt-key add - &> /dev/null
apt update &> /dev/null
apt install webmin -y &> /dev/null
sed -i "s|\(ssl=\).\+|\10|" /etc/webmin/miniserv.conf
lsof -t -i tcp:10000 -s tcp:listen | xargs kill 2>/dev/null
systemctl restart webmin &> /dev/null
systemctl enable webmin &> /dev/null
webminEOF
screen -S webmininstall -dm bash -c "bash /tmp/install-webmin.bash && rm -f /tmp/install-webmin.bash"
}
function InstSSH(){
 rm -f /etc/ssh/sshd_config*
 cat <<'MySSHConfig' > /etc/ssh/sshd_config
# My OpenSSH Server config
Port myPORT1
Port myPORT2
AddressFamily inet
ListenAddress 0.0.0.0
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key
PermitRootLogin yes
MaxSessions 1024
PubkeyAuthentication yes
PasswordAuthentication yes
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding yes
PrintMotd no
ClientAliveInterval 240
ClientAliveCountMax 2
UseDNS no
Banner /etc/banner
AcceptEnv LANG LC_*
Subsystem   sftp  /usr/lib/openssh/sftp-server
MySSHConfig
 sed -i "s|myPORT1|$SSH_Port1|g" /etc/ssh/sshd_config
 sed -i "s|myPORT2|$SSH_Port2|g" /etc/ssh/sshd_config
 rm -f /etc/banner
 wget -qO /etc/banner "$SSH_Banner"
 dos2unix -q /etc/banner
 sed -i '/password\s*requisite\s*pam_cracklib.s.*/d' /etc/pam.d/common-password
 sed -i 's/use_authtok //g' /etc/pam.d/common-password
 sed -i '/\/bin\/false/d' /etc/shells
 sed -i '/\/usr\/sbin\/nologin/d' /etc/shells
 echo '/bin/false' >> /etc/shells
 echo '/usr/sbin/nologin' >> /etc/shells
 echo -e "[\e[33mNotice\e[0m] Restarting SSH Service.."
 systemctl restart ssh
 rm -rf /etc/default/dropbear*
 cat <<'MyDropbear' > /etc/default/dropbear
# My Dropbear Config
NO_START=0
DROPBEAR_PORT=PORT01
DROPBEAR_EXTRA_ARGS="-p PORT02"
DROPBEAR_BANNER="/etc/banner"
DROPBEAR_RSAKEY="/etc/dropbear/dropbear_rsa_host_key"
DROPBEAR_DSSKEY="/etc/dropbear/dropbear_dss_host_key"
DROPBEAR_ECDSAKEY="/etc/dropbear/dropbear_ecdsa_host_key"
DROPBEAR_RECEIVE_WINDOW=65536
MyDropbear
 sed -i "s|PORT01|$Dropbear_Port1|g" /etc/default/dropbear
 sed -i "s|PORT02|$Dropbear_Port2|g" /etc/default/dropbear
 echo -e "[\e[33mNotice\e[0m] Restarting Dropbear Service.."
 systemctl enable dropbear &>/dev/null
 systemctl restart dropbear &>/dev/null
}
function InsStunnel(){
StunnelDir=$(ls /etc/default | grep stunnel | head -n1)
cat <<'MyStunnelD' > /etc/default/$StunnelDir
# My Stunnel Config
ENABLED=1
FILES="/etc/stunnel/*.conf"
OPTIONS=""
BANNER="/etc/banner"
PPP_RESTART=0
# RLIMITS="-n 4096 -d unlimited"
RLIMITS=""
MyStunnelD
 rm -rf /etc/stunnel/*
 openssl req -new -x509 -days 9999 -nodes -subj "/C=PH/ST=NCR/L=Manila/O=$MyScriptName/OU=$MyScriptName/CN=$MyScriptName" -out /etc/stunnel/stunnel.pem -keyout /etc/stunnel/stunnel.pem &> /dev/null
 cat <<'MyStunnelC' > /etc/stunnel/stunnel.conf
# My Stunnel Config
pid = /var/run/stunnel.pid
cert = /etc/stunnel/stunnel.pem
client = no
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1
TIMEOUTclose = 0
[stunnel]
connect = 127.0.0.1:WS_Port1
accept = WS_Port2
[dropbear]
accept = 333
connect = 127.0.0.1:550
[openssh]
accept = Stunnel_Port2
connect = 127.0.0.1:openssh_port_c
[openvpn]
accept = 587
connect = 127.0.0.1:110
MyStunnelC
 sed -i "s|Stunnel_Port1|$Stunnel_Port1|g" /etc/stunnel/stunnel.conf
 sed -i "s|WS_Port1|$WS_Port1|g" /etc/stunnel/stunnel.conf
 sed -i "s|WS_Port2|$WS_Port2|g" /etc/stunnel/stunnel.conf
 sed -i "s|dropbear_port_c|$(netstat -tlnp | grep -i dropbear | awk '{print $4}' | cut -d: -f2 | xargs | awk '{print $2}' | head -n1)|g" /etc/stunnel/stunnel.conf
 sed -i "s|Stunnel_Port2|$Stunnel_Port2|g" /etc/stunnel/stunnel.conf
 sed -i "s|openssh_port_c|$(netstat -tlnp | grep -i ssh | awk '{print $4}' | cut -d: -f2 | xargs | awk '{print $2}' | head -n1)|g" /etc/stunnel/stunnel.conf
 echo -e "[\e[33mNotice\e[0m] Restarting Stunnel Service.."
systemctl restart $StunnelDir

}
function InsOpenVPN(){
 if [[ ! -e /etc/openvpn ]]; then
  mkdir -p /etc/openvpn
 fi
 rm -rf /etc/openvpn/*
 cat <<'myOpenVPNconf1' > /etc/openvpn/server_tcp.conf
# OpenVPN Server build vOPENVPN_SERVER_VERSION
# Server Location: OPENVPN_SERVER_LOCATION
# Server ISP: OPENVPN_SERVER_ISP
#
port MyOvpnPort1
dev tun
proto tcp
ca /etc/openvpn/ca.crt
cert /etc/openvpn/dextereskalarte.crt
key /etc/openvpn/dextereskalarte.key
duplicate-cn
dh none
persist-tun
persist-key
persist-remote-ip
cipher none
ncp-disable
auth none
comp-lzo
tun-mtu 1500
reneg-sec 0
plugin /etc/openvpn/openvpn-auth-pam.so /etc/pam.d/login
verify-client-cert none
username-as-common-name
max-clients 4000
topology subnet
server 172.16.0.0 255.255.0.0
push "redirect-gateway def1"
keepalive 5 60
status /etc/openvpn/tcp_stats.log
log /etc/openvpn/tcp.log
verb 2
script-security 2
socket-flags TCP_NODELAY
push "socket-flags TCP_NODELAY"
push "dhcp-option DNS 1.0.0.1"
push "dhcp-option DNS 1.1.1.1"
push "dhcp-option DNS 8.8.4.4"
push "dhcp-option DNS 8.8.8.8"
myOpenVPNconf1
cat <<'myOpenVPNconf2' > /etc/openvpn/server_udp.conf
# OpenVPN Server build vOPENVPN_SERVER_VERSION
# Server Location: OPENVPN_SERVER_LOCATION
# Server ISP: OPENVPN_SERVER_ISP
#
port 53
dev tun
proto udp
ca /etc/openvpn/ca.crt
cert /etc/openvpn/dextereskalarte.crt
key /etc/openvpn/dextereskalarte.key
duplicate-cn
dh none
persist-tun
persist-key
persist-remote-ip
cipher none
ncp-disable
auth none
comp-lzo
tun-mtu 1500
reneg-sec 0
plugin /etc/openvpn/openvpn-auth-pam.so /etc/pam.d/login
verify-client-cert none
username-as-common-name
max-clients 4000
topology subnet
server 172.17.0.0 255.255.0.0
push "redirect-gateway def1"
keepalive 5 60
status /etc/openvpn/udp_stats.log
log /etc/openvpn/tcp.log
verb 2
script-security 2
socket-flags TCP_NODELAY
push "socket-flags TCP_NODELAY"
push "dhcp-option DNS 1.0.0.1"
push "dhcp-option DNS 1.1.1.1"
push "dhcp-option DNS 8.8.4.4"
push "dhcp-option DNS 8.8.8.8"
myOpenVPNconf2
 cat <<'EOF7'> /etc/openvpn/ca.crt
-----BEGIN CERTIFICATE-----
MIIEAjCCA2ugAwIBAgIJAIMieFdClco7MA0GCSqGSIb3DQEBCwUAMIGuMQswCQYD
VQQGEwJQSDELMAkGA1UECAwCTU4xDzANBgNVBAcMBk1hbmlsYTEWMBQGA1UECgwN
VHlsZXIgQWx2YXJlejEpMCcGA1UECwwgaHR0cHM6Ly9naXRodWIuY29tL1R5bGVy
QWx2YXJlenoxFDASBgNVBAMMC0Vhc3ktUlNBIENBMSgwJgYJKoZIhvcNAQkBFhlU
eWxlckFsdmFyZXoxMjFAZ21haWwuY29tMB4XDTIxMDgwMzA5NTQxMloXDTQ4MTIx
ODA5NTQxMlowga4xCzAJBgNVBAYTAlBIMQswCQYDVQQIDAJNTjEPMA0GA1UEBwwG
TWFuaWxhMRYwFAYDVQQKDA1UeWxlciBBbHZhcmV6MSkwJwYDVQQLDCBodHRwczov
L2dpdGh1Yi5jb20vVHlsZXJBbHZhcmV6ejEUMBIGA1UEAwwLRWFzeS1SU0EgQ0Ex
KDAmBgkqhkiG9w0BCQEWGVR5bGVyQWx2YXJlejEyMUBnbWFpbC5jb20wgZ8wDQYJ
KoZIhvcNAQEBBQADgY0AMIGJAoGBAL0nS2VC+tw/DEg9NxQZNlxOsuFqpVW3SLAS
KzHUafBVsPoqa4mMtNWQ/geKwZQgMCWSuENpdKW9az8/LGohjuQnEUA95JLt83mJ
3gBTSEd67UbsPPRrdb9XnFqlVWpwhIe8kSsmZWtO4DR4/8xaQiAI5X02P5kxCsrn
0QPopZyFAgMBAAGjggEkMIIBIDAdBgNVHQ4EFgQUsM5I2r1mVqmiRzL/6bmhx+LU
D5AwgeMGA1UdIwSB2zCB2IAUsM5I2r1mVqmiRzL/6bmhx+LUD5ChgbSkgbEwga4x
CzAJBgNVBAYTAlBIMQswCQYDVQQIDAJNTjEPMA0GA1UEBwwGTWFuaWxhMRYwFAYD
VQQKDA1UeWxlciBBbHZhcmV6MSkwJwYDVQQLDCBodHRwczovL2dpdGh1Yi5jb20v
VHlsZXJBbHZhcmV6ejEUMBIGA1UEAwwLRWFzeS1SU0EgQ0ExKDAmBgkqhkiG9w0B
CQEWGVR5bGVyQWx2YXJlejEyMUBnbWFpbC5jb22CCQCDInhXQpXKOzAMBgNVHRME
BTADAQH/MAsGA1UdDwQEAwIBBjANBgkqhkiG9w0BAQsFAAOBgQCMPCZcCjxOOF5A
t5Y0iS5MjTCeZUHZ7fTxUkLlidlhbnmeIzDsbqocTIxPpkSJ7g8hf1BXSaLphwT0
L2q/siUuSyvigG5WNs+5N4r5hvtVsh3aYCYPtEFYNuOiNeEqws+gS9MiaWsL6d1Z
QCo/VufP1Wj5xuhzN0UTTMrVMoNRGQ==
-----END CERTIFICATE-----
EOF7
 cat <<'EOF9'> /etc/openvpn/dextereskalarte.crt
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            c1:5a:01:7a:a3:8f:cf:05:d4:01:9f:d7:73:4d:de:17
    Signature Algorithm: sha256WithRSAEncryption
        Issuer: C=PH, ST=MN, L=Manila, O=Dexter Eskalarte, OU=http://script.psytech-vpn.com/setup/debian_wssh, CN=Easy-RSA CA/emailAddress=deskalarte@gmail.com
        Validity
            Not Before: Aug  3 10:05:54 2021 GMT
            Not After : Dec 18 10:05:54 2048 GMT
        Subject: C=PH, ST=MN, L=Manila, O=Dexter Eskalarte, OU=http://script.psytech-vpn.com/setup/debian_wssh, CN=server/emailAddress=deskalarte@gmail.com
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (1024 bit)
                Modulus:
                    00:da:60:cb:d7:90:28:db:87:68:f0:ef:85:9f:cd:
                    78:f6:8c:b2:cf:e4:f6:51:61:0f:86:84:bd:59:44:
                    67:4e:47:14:ea:66:2f:eb:2e:0f:42:71:51:d5:d8:
                    30:7d:73:98:ff:ff:0a:4e:6d:b8:c6:9a:e7:4d:ab:
                    2e:35:2c:78:32:5a:32:57:38:42:a9:aa:04:11:72:
                    56:01:6b:a4:ed:ac:3c:cc:c6:a6:2a:e3:3a:45:cd:
                    c1:01:2f:0e:f1:a5:00:c3:d0:44:46:71:3a:59:fe:
                    fc:e3:f3:a8:93:72:c3:f2:84:31:c8:f7:69:12:84:
                    d0:37:91:ba:9d:58:4e:8b:65
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Basic Constraints: 
                CA:FALSE
            X509v3 Subject Key Identifier: 
                B6:CC:CF:0A:36:63:C6:55:7B:28:5B:35:1D:27:94:07:9A:01:17:6E
            X509v3 Authority Key Identifier: 
                keyid:B0:CE:48:DA:BD:66:56:A9:A2:47:32:FF:E9:B9:A1:C7:E2:D4:0F:90
                DirName:/C=PH/ST=MN/L=Manila/O=Dexter Eskalarte/OU=http://script.psytech-vpn.com/setup/debian_wssh/CN=Easy-RSA CA/emailAddress=deskalarte@gmail.com
                serial:83:22:78:57:42:95:CA:3B

            X509v3 Extended Key Usage: 
                TLS Web Server Authentication
            X509v3 Key Usage: 
                Digital Signature, Key Encipherment
            X509v3 Subject Alternative Name: 
                DNS:server
    Signature Algorithm: sha256WithRSAEncryption
         ae:f9:c0:19:ba:de:3c:ea:0e:31:a0:b8:41:71:c1:5e:78:df:
         d0:70:0d:2f:b8:54:39:44:18:fa:74:33:5f:95:dd:1d:be:bc:
         b0:f8:49:e6:d1:b5:0f:34:ad:19:b7:23:61:68:e7:d6:85:8b:
         d5:82:61:b9:78:03:0a:96:40:00:56:27:48:1a:fe:50:93:89:
         bc:a3:8f:e7:74:65:5a:8e:ef:e8:55:1e:5d:94:9a:12:68:fc:
         cc:fd:cd:6f:5d:aa:78:88:6f:02:ed:e5:18:2d:3c:bd:54:63:
         c1:2a:47:87:e0:80:20:55:8a:3b:44:57:44:c8:08:34:61:18:
         64:d4
-----BEGIN CERTIFICATE-----
MIIEKjCCA5OgAwIBAgIRAMFaAXqjj88F1AGf13NN3hcwDQYJKoZIhvcNAQELBQAw
ga4xCzAJBgNVBAYTAlBIMQswCQYDVQQIDAJNTjEPMA0GA1UEBwwGTWFuaWxhMRYw
FAYDVQQKDA1UeWxlciBBbHZhcmV6MSkwJwYDVQQLDCBodHRwczovL2dpdGh1Yi5j
b20vVHlsZXJBbHZhcmV6ejEUMBIGA1UEAwwLRWFzeS1SU0EgQ0ExKDAmBgkqhkiG
9w0BCQEWGVR5bGVyQWx2YXJlejEyMUBnbWFpbC5jb20wHhcNMjEwODAzMTAwNTU0
WhcNNDgxMjE4MTAwNTU0WjCBqTELMAkGA1UEBhMCUEgxCzAJBgNVBAgMAk1OMQ8w
DQYDVQQHDAZNYW5pbGExFjAUBgNVBAoMDVR5bGVyIEFsdmFyZXoxKTAnBgNVBAsM
IGh0dHBzOi8vZ2l0aHViLmNvbS9UeWxlckFsdmFyZXp6MQ8wDQYDVQQDDAZzZXJ2
ZXIxKDAmBgkqhkiG9w0BCQEWGVR5bGVyQWx2YXJlejEyMUBnbWFpbC5jb20wgZ8w
DQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBANpgy9eQKNuHaPDvhZ/NePaMss/k9lFh
D4aEvVlEZ05HFOpmL+suD0JxUdXYMH1zmP//Ck5tuMaa502rLjUseDJaMlc4Qqmq
BBFyVgFrpO2sPMzGpirjOkXNwQEvDvGlAMPQREZxOln+/OPzqJNyw/KEMcj3aRKE
0DeRup1YTotlAgMBAAGjggFJMIIBRTAJBgNVHRMEAjAAMB0GA1UdDgQWBBS2zM8K
NmPGVXsoWzUdJ5QHmgEXbjCB4wYDVR0jBIHbMIHYgBSwzkjavWZWqaJHMv/puaHH
4tQPkKGBtKSBsTCBrjELMAkGA1UEBhMCUEgxCzAJBgNVBAgMAk1OMQ8wDQYDVQQH
DAZNYW5pbGExFjAUBgNVBAoMDVR5bGVyIEFsdmFyZXoxKTAnBgNVBAsMIGh0dHBz
Oi8vZ2l0aHViLmNvbS9UeWxlckFsdmFyZXp6MRQwEgYDVQQDDAtFYXN5LVJTQSBD
QTEoMCYGCSqGSIb3DQEJARYZVHlsZXJBbHZhcmV6MTIxQGdtYWlsLmNvbYIJAIMi
eFdClco7MBMGA1UdJQQMMAoGCCsGAQUFBwMBMAsGA1UdDwQEAwIFoDARBgNVHREE
CjAIggZzZXJ2ZXIwDQYJKoZIhvcNAQELBQADgYEArvnAGbrePOoOMaC4QXHBXnjf
0HANL7hUOUQY+nQzX5XdHb68sPhJ5tG1DzStGbcjYWjn1oWL1YJhuXgDCpZAAFYn
SBr+UJOJvKOP53RlWo7v6FUeXZSaEmj8zP3Nb12qeIhvAu3lGC08vVRjwSpHh+CA
IFWKO0RXRMgINGEYZNQ=
-----END CERTIFICATE-----
EOF9
 cat <<'EOF10'> /etc/openvpn/dextereskalarte.key
-----BEGIN PRIVATE KEY-----
MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBANpgy9eQKNuHaPDv
hZ/NePaMss/k9lFhD4aEvVlEZ05HFOpmL+suD0JxUdXYMH1zmP//Ck5tuMaa502r
LjUseDJaMlc4QqmqBBFyVgFrpO2sPMzGpirjOkXNwQEvDvGlAMPQREZxOln+/OPz
qJNyw/KEMcj3aRKE0DeRup1YTotlAgMBAAECgYBge2G0RKn4i/QOdxTHjMWD0Jf0
CAnX3JU6bo0l0nX9/KO+CBXlxzzQszZfz5tk4dzYRbss+YcooCnPg/DvZ01WyHpP
yIVw3MdYRD45lz46yBxFnwDl9UfnIz5T7PgFmNr79ZBe/9zqPkVz3B7XzaSQ7040
UpSSV+MsYJCNvBFsRQJBAPsbphg5teLw57d83Azq7mHkcUUhRuRdcp+UPPN15VVH
cY2W9cp9lOULi80DUMzKFYgEa2m5Z0Bm4mfJ9dqz7s8CQQDeoenjRomS7VAfWhJE
x2aCeCKuMIt+FNS1aEjil8deNa0JwzpH3vVUOjIOu4F4adwaIVy7rfsiserd/Cm5
9k+LAkBgQooacU0TcSwyv6+PWCQH7M2rJYWKl3QQToBLCB/g4CFcmMkiVZ/Vaeau
sZ2w06sLWD5g6gz1uDsEdHxF2YIrAkAazX9s/0b8y1lEDQH6Cc+LkY8LTYjdqwBY
vq9XqFI2Q1wLutc/Y9ZBR6hTIbvalVQMSUvyxGVhre3Kv9r+Kms1AkEA3A65PcNS
o2bOVyc4U5O2QtWLJtNanNImqE1o8x/ebCDqYmBFCvq0ACuhc9wgrWQM2p/bcyXE
YSoAC0l6Pw/kXg==
-----END PRIVATE KEY-----
EOF10
 sed -i "s|MyOvpnPort1|$OpenVPN_Port1|g" /etc/openvpn/server_tcp.conf
 sed -i "s|MyOvpnPort2|$OpenVPN_Port2|g" /etc/openvpn/server_udp.conf
 wget -qO /etc/openvpn/b.zip 'http://script.psytech-vpn.com/setup/debian_wssh/openvpn_plugin64'
 unzip -qq /etc/openvpn/b.zip -d /etc/openvpn
 rm -f /etc/openvpn/b.zip
 if [[ "$(hostnamectl | grep -i Virtualization | awk '{print $2}' | head -n1)" == 'openvz' ]]; then
 sed -i 's|LimitNPROC|#LimitNPROC|g' /lib/systemd/system/openvpn*
 systemctl daemon-reload
fi
 echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/20-openvpn.conf && sysctl --system &> /dev/null && echo 1 > /proc/sys/net/ipv4/ip_forward
 apt install firewalld -y
 systemctl start firewalld
 systemctl enable firewalld
 firewall-cmd --quiet --set-default-zone=public
 firewall-cmd --quiet --zone=public --permanent --add-port=1-65534/tcp
 firewall-cmd --quiet --zone=public --permanent --add-port=1-65534/udp
 firewall-cmd --quiet --reload
 firewall-cmd --quiet --add-masquerade
 firewall-cmd --quiet --permanent --add-masquerade
 firewall-cmd --quiet --permanent --add-service=ssh
 firewall-cmd --quiet --permanent --add-service=openvpn
 firewall-cmd --quiet --permanent --add-service=http
 firewall-cmd --quiet --permanent --add-service=https
 firewall-cmd --quiet --permanent --add-service=privoxy
 firewall-cmd --quiet --permanent --add-service=squid
 firewall-cmd --quiet --reload
 echo 1 > /proc/sys/net/ipv4/ip_forward
 systemctl start openvpn@server_tcp
 systemctl start openvpn@server_udp
 systemctl enable openvpn@server_tcp
 systemctl enable openvpn@server_udp
 systemctl restart openvpn@server_tcp
 systemctl restart openvpn@server_udp
}

function InsProxy(){
 rm -rf /etc/privoxy/config*
 cat <<'myPrivoxy' > /etc/privoxy/config
# My Privoxy Server Config
user-manual /usr/share/doc/privoxy/user-manual
confdir /etc/privoxy
logdir /var/log/privoxy
filterfile default.filter
logfile logfile
listen-address 0.0.0.0:Privoxy_Port1
listen-address 0.0.0.0:Privoxy_Port2
toggle 1
enable-remote-toggle 0
enable-remote-http-toggle 0
enable-edit-actions 0
enforce-blocks 0
buffer-limit 4096
enable-proxy-authentication-forwarding 1
forwarded-connect-retries 1
accept-intercepted-requests 1
allow-cgi-request-crunching 1
split-large-forms 0
keep-alive-timeout 5
tolerate-pipelining 1
socket-timeout 300
permit-access 0.0.0.0/0 IP-ADDRESS
myPrivoxy
 sed -i "s|IP-ADDRESS|$IPADDR|g" /etc/privoxy/config
 sed -i "s|Privoxy_Port1|$Privoxy_Port1|g" /etc/privoxy/config
 sed -i "s|Privoxy_Port2|$Privoxy_Port2|g" /etc/privoxy/config
 apt remove --purge squid -y
 rm -rf /etc/squid/sq*
 apt install squid -y
 cat <<mySquid > /etc/squid/squid.conf
acl VPN dst $(wget -4qO- http://ipinfo.io/ip)/32
http_access allow VPN
http_access deny all 
http_port 0.0.0.0:$Proxy_Port1
http_port 0.0.0.0:$Proxy_Port2
coredump_dir /var/spool/squid
dns_nameservers 1.1.1.1 1.0.0.1
refresh_pattern ^ftp: 1440 20% 10080
refresh_pattern ^gopher: 1440 0% 1440
refresh_pattern -i (/cgi-bin/|\?) 0 0% 0
refresh_pattern . 0 20% 4320
visible_hostname localhost
mySquid
 sed -i "s|SquidCacheHelper|$Privoxy_Port1|g" /etc/squid/squid.conf
echo -e "[\e[33mNotice\e[0m] Restarting Proxy Service.."
 systemctl restart privoxy
 systemctl restart squid
}
function OvpnConfigs(){
 cat <<'myNginxC' > /etc/nginx/conf.d/dextereskalarte-ovpn-config.conf
# My OpenVPN Config Download Directory
server {
 listen 0.0.0.0:myNginx;
 server_name localhost;
 root /var/www/openvpn;
 index index.html;
}
myNginxC
 sed -i "s|myNginx|$OvpnDownload_Port|g" /etc/nginx/conf.d/dextereskalarte-ovpn-config.conf
 rm -rf /etc/nginx/sites-*
 rm -rf /var/www/openvpn
 mkdir -p /var/www/openvpn
cat <<EOFtcp> /var/www/openvpn/TCPConfig.ovpn
# OpenVPN Server build vOPENVPN_SERVER_VERSION
# Server Location: OPENVPN_SERVER_LOCATION
# Server ISP: OPENVPN_SERVER_ISP
#
client
dev tun
proto tcp
remote $IPADDR $OpenVPN_Port1
remote-cert-tls server
resolv-retry infinite
nobind
tun-mtu 1500
tun-mtu-extra 32
mssfix 1450
persist-key
persist-tun
auth-user-pass
auth none
auth-nocache
cipher none
keysize 0
comp-lzo
setenv CLIENT_CERT 0
reneg-sec 0
verb 1
<ca>
$(cat /etc/openvpn/ca.crt)
</ca>
EOFtcp
cat <<EOFudp> /var/www/openvpn/UDPConfig.ovpn
# OpenVPN Server build vOPENVPN_SERVER_VERSION
# Server Location: OPENVPN_SERVER_LOCATION
# Server ISP: OPENVPN_SERVER_ISP
#
client
dev tun
proto udp
remote $IPADDR 53
remote-cert-tls server
resolv-retry infinite
nobind
tun-mtu 1500
tun-mtu-extra 32
mssfix 1450
persist-key
persist-tun
auth-user-pass
auth none
auth-nocache
cipher none
keysize 0
comp-lzo
setenv CLIENT_CERT 0
reneg-sec 0
verb 1
<ca>
$(cat /etc/openvpn/ca.crt)
</ca>
EOFudp
cat <<EOF152> /var/www/openvpn/GTMConfig.ovpn
# OpenVPN Server build vOPENVPN_SERVER_VERSION
# Server Location: OPENVPN_SERVER_LOCATION
# Server ISP: OPENVPN_SERVER_ISP
#
client
dev tun
proto tcp
remote $IPADDR $OpenVPN_Port1
remote-cert-tls server
resolv-retry infinite
nobind
tun-mtu 1500
tun-mtu-extra 32
mssfix 1450
persist-key
persist-tun
auth-user-pass
auth none
auth-nocache
cipher none
keysize 0
comp-lzo
setenv CLIENT_CERT 0
reneg-sec 0
verb 1
http-proxy $(curl -s http://ipinfo.io/ip || wget -q http://ipinfo.io/ip) $Proxy_Port2
http-proxy-option CUSTOM-HEADER Host redirect.googlevideo.com
http-proxy-option CUSTOM-HEADER X-Forwarded-For redirect.googlevideo.com
<ca>
$(cat /etc/openvpn/ca.crt)
</ca>
EOF152
cat <<EOF16> /var/www/openvpn/SunConfig.ovpn
# OpenVPN Server build vOPENVPN_SERVER_VERSION
# Server Location: OPENVPN_SERVER_LOCATION
# Server ISP: OPENVPN_SERVER_ISP
#
client
dev tun
proto udp
remote $IPADDR 53
remote-cert-tls server
resolv-retry infinite
nobind
tun-mtu 1500
tun-mtu-extra 32
mssfix 1450
persist-key
persist-tun
auth-user-pass
auth none
auth-nocache
cipher none
keysize 0
comp-lzo
setenv CLIENT_CERT 0
reneg-sec 0
verb 1
<ca>
$(cat /etc/openvpn/ca.crt)
</ca>
EOF16
cat <<EOF160> /var/www/openvpn/GStories.ovpn
# OpenVPN Server build vOPENVPN_SERVER_VERSION
# Server Location: OPENVPN_SERVER_LOCATION
# Server ISP: OPENVPN_SERVER_ISP
#
client
dev tun
proto tcp
remote $IPADDR $OpenVPN_Port1
remote-cert-tls server
resolv-retry infinite
nobind
tun-mtu 1500
tun-mtu-extra 32
mssfix 1450
persist-key
persist-tun
auth-user-pass
auth none
auth-nocache
cipher none
keysize 0
comp-lzo
setenv CLIENT_CERT 0
reneg-sec 0
verb 1
http-proxy $(curl -s http://ipinfo.io/ip || wget -q http://ipinfo.io/ip) $Proxy_Port2
http-proxy-option CUSTOM-HEADER Host tweetdeck.twitter.com
http-proxy-option CUSTOM-HEADER X-Forwarded-For tweetdeck.twitter.com
<ca>
$(cat /etc/openvpn/ca.crt)
</ca>
EOF160
cat <<EOF17> /var/www/openvpn/SunNoLoad.ovpn
# OpenVPN Server build vOPENVPN_SERVER_VERSION
# Server Location: OPENVPN_SERVER_LOCATION
# Server ISP: OPENVPN_SERVER_ISP
#
client
dev tun
proto tcp-client
remote $IPADDR $OpenVPN_Port1
remote-cert-tls server
bind
float
tun-mtu 1500
tun-mtu-extra 32
mssfix 1450
mute-replay-warnings
connect-retry-max 9999
redirect-gateway def1
connect-retry 0 1
resolv-retry infinite
setenv CLIENT_CERT 0
persist-tun
persist-key
auth-user-pass
auth none
auth-nocache
auth-retry interact
cipher none
keysize 0
comp-lzo
reneg-sec 0
verb 0
nice -20
log /dev/null
<ca>
$(cat /etc/openvpn/ca.crt)
</ca>
EOF17
cat <<EOFsmart1> /var/www/openvpn/SmartGStories.ovpn
# OpenVPN Server build vOPENVPN_SERVER_VERSION
# Server Location: OPENVPN_SERVER_LOCATION
# Server ISP: OPENVPN_SERVER_ISP
#
client
dev tun
proto tcp
remote $IPADDR $OpenVPN_Port1
remote-cert-tls server
resolv-retry infinite
nobind
tun-mtu 1500
tun-mtu-extra 32
mssfix 1450
persist-key
persist-tun
auth-user-pass
auth none
auth-nocache
cipher none
keysize 0
comp-lzo
setenv CLIENT_CERT 0
reneg-sec 0
verb 1
http-proxy-option VERSION 1.1
http-proxy-option AGENT Chrome/80.0.3987.87
http-proxy-option CUSTOM-HEADER Host api.twitter.com
http-proxy-option CUSTOM-HEADER X-Forward-Host api.twitter.com
http-proxy-option CUSTOM-HEADER X-Forwarded-For api.twitter.com
http-proxy-option CUSTOM-HEADER Referrer api.twitter.com
<ca>
$(cat /etc/openvpn/ca.crt)
</ca>
EOFsmart1
cat <<EOFsmart2> /var/www/openvpn/SmartGGames.ovpn
# OpenVPN Server build vOPENVPN_SERVER_VERSION
# Server Location: OPENVPN_SERVER_LOCATION
# Server ISP: OPENVPN_SERVER_ISP
# Convert your IP address into hostname (class A record) combined with Mobilelegends's URL to make this config work
# example: wscdn.ml.youngjoygame.com.mydns.domain.com
#
client
dev tun
proto tcp
remote $IPADDR $OpenVPN_Port1
remote-cert-tls server
resolv-retry infinite
nobind
tun-mtu 1500
tun-mtu-extra 32
mssfix 1450
persist-key
persist-tun
auth-user-pass
auth none
auth-nocache
cipher none
keysize 0
comp-lzo
setenv CLIENT_CERT 0
reneg-sec 0
verb 1
http-proxy-option VERSION 1.1
http-proxy-option AGENT Chrome/80.0.3987.87
http-proxy-option CUSTOM-HEADER Host wscdn.ml.youngjoygame.com
http-proxy-option CUSTOM-HEADER X-Forward-Host wscdn.ml.youngjoygame.com
http-proxy-option CUSTOM-HEADER X-Forwarded-For wscdn.ml.youngjoygame.com
http-proxy-option CUSTOM-HEADER Referrer wscdn.ml.youngjoygame.com
<ca>
$(cat /etc/openvpn/ca.crt)
</ca>
EOFsmart2

sed -i "s|OPENVPN_SERVER_VERSION|$(openvpn --version | cut -d" " -f2 | head -n1)|g" /var/www/openvpn/*.ovpn
sed -i "s|OPENVPN_SERVER_LOCATION|$(curl -4s http://ipinfo.io/country), $(curl -4s http://ipinfo.io/region)|g" /var/www/openvpn/*.ovpn
sed -i "s|OPENVPN_SERVER_ISP|$(curl -4s http://ipinfo.io/org | sed -e 's/[^ ]* //')|g" /var/www/openvpn/*.ovpn
cat <<'mySiteOvpn' > /var/www/openvpn/index.html
<!DOCTYPE html>
<html lang="en">
<!-- OVPN Download site by: Dexter Eskalarte -->
<head><meta charset="utf-8" /><title>MyScriptName OVPN Config Download</title><meta name="description" content="MyScriptName Server" /><meta content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no" name="viewport" /><meta name="theme-color" content="#000000" /><link rel="stylesheet" href="https://use.fontawesome.com/releases/v5.8.2/css/all.css"><link href="https://cdnjs.cloudflare.com/ajax/libs/twitter-bootstrap/4.3.1/css/bootstrap.min.css" rel="stylesheet"><link href="https://cdnjs.cloudflare.com/ajax/libs/mdbootstrap/4.8.3/css/mdb.min.css" rel="stylesheet"></head><body><div class="container justify-content-center" style="margin-top:9em;margin-bottom:5em;"><div class="col-md"><div class="view"><img src="https://openvpn.net/wp-content/uploads/openvpn.jpg" class="card-img-top"><div class="mask rgba-white-slight"></div></div><div class="card"><div class="card-body"><h5 class="card-title">Config List</h5><br /><ul class="list-group"><li class="list-group-item justify-content-between align-items-center" style="margin-bottom:1em;"><p>TCP Config <span class="badge light-blue darken-4">Android/iOS/PC/Modem</span><br /></p><a class="btn btn-outline-success waves-effect btn-sm" href="http://IP-ADDRESS:NGINXPORT/TCPConfig.ovpn" style="float:right;"><i class="fa fa-download"></i> Download</a></li><li class="list-group-item justify-content-between align-items-center" style="margin-bottom:1em;"><p>UDP Config <span class="badge light-blue darken-4">Android/iOS/PC/Modem</span><br /></p><a class="btn btn-outline-success waves-effect btn-sm" href="http://IP-ADDRESS:NGINXPORT/UDPConfig.ovpn" style="float:right;"><i class="fa fa-download"></i> Download</a></li><li class="list-group-item justify-content-between align-items-center" style="margin-bottom:1em;"><p>For Globe/TM <span class="badge light-blue darken-4">Android/iOS/PC/Modem</span><br /><small> For EZ/GS Promo with WNP,SNS,FB and IG freebies</small></p><a class="btn btn-outline-success waves-effect btn-sm" href="http://IP-ADDRESS:NGINXPORT/GTMConfig.ovpn" style="float:right;"><i class="fa fa-download"></i> Download</a></li><li class="list-group-item justify-content-between align-items-center" style="margin-bottom:1em;"><p>For Smart <span class="badge light-blue darken-4">Android/iOS/PC/Modem</span><br /><small> For GIGASTORIES Promos</small></p><a class="btn btn-outline-success waves-effect btn-sm" href="http://IP-ADDRESS:NGINXPORT/SmartGStories.ovpn" style="float:right;"><i class="fa fa-download"></i> Download</a></li><li class="list-group-item justify-content-between align-items-center" style="margin-bottom:1em;"><p>For Smart <span class="badge light-blue darken-4">Android/iOS/PC/Modem</span><br /><small> For GIGAGAMES/ML Promos</small></p><a class="btn btn-outline-success waves-effect btn-sm" href="http://IP-ADDRESS:NGINXPORT/SmartGGames.ovpn" style="float:right;"><i class="fa fa-download"></i> Download</a></li></ul></div></div></div></div></body></html>
mySiteOvpn
 sed -i "s|MyScriptName|$MyScriptName|g" /var/www/openvpn/index.html
 sed -i "s|NGINXPORT|$OvpnDownload_Port|g" /var/www/openvpn/index.html
 sed -i "s|IP-ADDRESS|$IPADDR|g" /var/www/openvpn/index.html
 echo -e "[\e[33mNotice\e[0m] Restarting Nginx Service.."
 systemctl restart nginx
 cd /var/www/openvpn
 zip -qq -r Configs.zip *.ovpn
 cd
}
function ip_address(){
  local IP="$( ip addr | egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | egrep -v "^192\.168|^172\.1[6-9]\.|^172\.2[0-9]\.|^172\.3[0-2]\.|^10\.|^127\.|^255\.|^0\." | head -n 1 )"
  [ -z "${IP}" ] && IP="$( wget -qO- -t1 -T2 ipv4.icanhazip.com )"
  [ -z "${IP}" ] && IP="$( wget -qO- -t1 -T2 ipinfo.io/ip )"
  [ ! -z "${IP}" ] && echo "${IP}" || echo
} 
IPADDR="$(ip_address)"
function ConfStartup(){
 echo -e "0 4\t* * *\troot\treboot" > /etc/cron.d/b_reboot_job
 rm -rf /etc/dextereskalarte
 mkdir -p /etc/dextereskalarte
 chmod -R 755 /etc/dextereskalarte
 cat <<'EOFSH' > /etc/dextereskalarte/startup.sh
#!/bin/bash
# Setting server local time
ln -fs /usr/share/zoneinfo/MyVPS_Time /etc/localtime
# Prevent DOS-like UI when installing using APT (Disabling APT interactive dialog)
export DEBIAN_FRONTEND=noninteractive
# Allowing ALL TCP ports for our machine (Simple workaround for policy-based VPS)
iptables -A INPUT -s $(wget -4qO- http://ipinfo.io/ip) -p tcp -m multiport --dport 1:65535 -j ACCEPT
# Allowing OpenVPN to Forward traffic
/bin/bash /etc/openvpn/openvpn.bash
# Deleting Expired SSH Accounts
/usr/local/sbin/delete_expired &> /dev/null
EOFSH
 chmod +x /etc/dextereskalarte/startup.sh
 sed -i "s|MyVPS_Time|$MyVPS_Time|g" /etc/dextereskalarte/startup.sh
 rm -rf /etc/sysctl.d/99*
 echo "[Unit]
Description=Dexter Startup Script
Before=network-online.target
Wants=network-online.target
[Service]
Type=oneshot
ExecStart=/bin/bash /etc/dextereskalarte/startup.sh
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target" > /etc/systemd/system/dextereskalarte.service
 chmod +x /etc/systemd/system/dextereskalarte.service
 systemctl daemon-reload
 systemctl start dextereskalarte
 systemctl enable dextereskalarte &> /dev/null
 systemctl restart cron
 systemctl enable cron
 
}
function ConfMenu(){
echo -e " Creating Menu scripts.."
cd /usr/local/sbin/
rm -rf {accounts,base-ports,base-ports-wc,base-script,bench-network,clearcache,connections,create,create_random,create_trial,delete_expired,diagnose,edit_dropbear,edit_openssh,edit_openvpn,edit_ports,edit_squid3,edit_stunnel4,locked_list,menu,options,ram,reboot_sys,reboot_sys_auto,restart_services,server,set_multilogin_autokill,set_multilogin_autokill_lib,show_ports,speedtest,user_delete,user_details,user_details_lib,user_extend,user_list,user_lock,user_unlock}
wget -q 'https://raw.githubusercontent.com/EskalarteDexter/Autoscript/main/dextermenu.zip'
unzip -qq dextermenu.zip
rm -f dextermenu.zip
chmod +x ./*
dos2unix ./* &> /dev/null
sed -i 's|/etc/squid/squid.conf|/etc/privoxy/config|g' ./*
sed -i 's|http_port|listen-address|g' ./*
cd ~
echo 'clear' > /etc/profile.d/dextereskalarte.sh
echo 'echo '' > /var/log/syslog' >> /etc/profile.d/dextereskalarte.sh
echo 'screenfetch -p -A Debian' >> /etc/profile.d/dextereskalarte.sh
chmod +x /etc/profile.d/dextereskalarte.sh
}
function ScriptMessage(){
 echo -e "\033[1;31m═════════════════════════════════════════════════════\033[0m"
echo '                                                              
   ██████╗ ███████╗██╗  ██╗████████╗███████╗██████╗        
   ██╔══██╗██╔════╝╚██╗██╔╝╚══██╔══╝██╔════╝██╔══██╗       
   ██║  ██║█████╗   ╚███╔╝    ██║   █████╗  ██████╔╝       
   ██║  ██║██╔══╝   ██╔██╗    ██║   ██╔══╝  ██╔══██╗       
   ██████╔╝███████╗██╔╝ ██╗   ██║   ███████╗██║  ██║       
   ╚═════╝ ╚══════╝╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝       
'
echo -e "\033[1;31m══════════════════════════════════════════════════════\033[0m"
}
function Installssl () {

apt-get install stunnel4 -y
echo -e "client = no\n[SSL]\ncert = /etc/stunnel/stunnel.pem\naccept = 443 \nconnect = 127.0.0.1:80" > /etc/stunnel/stunnel.conf
openssl genrsa -out stunnel.key 2048 > /dev/null 2>&1
(echo "" ; echo "" ; echo "" ; echo "" ; echo "" ; echo "" ; echo "@cloudflare" )|openssl req -new -key stunnel.key -x509 -days 1000 -out stunnel.crt 
cat stunnel.crt stunnel.key > stunnel.pem 
mv stunnel.pem /etc/stunnel/
sed -i 's/ENABLED=0/ENABLED=1/g' /etc/default/stunnel4
service stunnel4 restart 
rm -rf /etc/ger-frm/stunnel.crt 
rm -rf /etc/ger-frm/stunnel.key
rm -rf /root/stunnel.crt
rm -rf /root/stunnel.key

}
install_socks()
{
clear
echo "Installing socks."
{
wget --no-check-certificate http://script.psytech-vpn.com/proxy.py -O ~/.ubuntu.py
dos2unix ~/.ubuntu.py
chmod +x ~/.ubuntu.py

cat > /etc/condom.sh << END
#!/bin/sh -e
service stunnel4 restart
screen -dmS socks python ~/.ubuntu.py
exit 0
END

chmod +x /etc/condom.sh
sudo crontab -l | { echo '@reboot bash /etc/condom.sh'; } | crontab -
} &>/dev/null
}

install_dropbear()
{
clear
echo "Installing dropbear."
{
rm -rf /etc/default/dropbear

cat > /etc/default/dropbear << MyDropbear
#FirenetDev
NO_START=0
DROPBEAR_PORT=550
DROPBEAR_EXTRA_ARGS="-p 500"
DROPBEAR_BANNER="/etc/banner"
DROPBEAR_RSAKEY="/etc/dropbear/dropbear_rsa_host_key"
DROPBEAR_DSSKEY="/etc/dropbear/dropbear_dss_host_key"
DROPBEAR_ECDSAKEY="/etc/dropbear/dropbear_ecdsa_host_key"
DROPBEAR_RECEIVE_WINDOW=65536
MyDropbear

service dropbear restart
} &>/dev/null
}

install_stunnel()
{
clear
echo "Installing stunnel."
{
cd /etc/stunnel/ || exit
openssl req -new -newkey rsa:2048 -days 3650 -nodes -x509 -sha256 -subj '/CN=KobzVPN/O=KobeKobz/C=PH' -keyout /etc/stunnel/stunnel.pem -out /etc/stunnel/stunnel.pem
echo "cert = /etc/stunnel/stunnel.pem
client = no
socket = a:SO_REUSEADDR=1
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1

[stunnel]
connect = 127.0.0.1:80
accept = 444

[dropbear]
accept = 443
connect = 127.0.0.1:550

[openssh]
accept = 445
connect = 127.0.0.1:225

[openvpn]
accept = 587
connect = 127.0.0.1:110" >> stunnel.conf


cd /etc/default && rm stunnel4

echo 'ENABLED=1
FILES="/etc/stunnel/*.conf"
OPTIONS=""
PPP_RESTART=0
RLIMITS=""' >> stunnel4

chmod 755 stunnel4
sudo service stunnel4 restart
} &>/dev/null
}

install_done()
{
  clear
  echo "WEBSOCKET SSH SERVER"
  echo "IP : $(curl -s https://api.ipify.org)"
  echo "SSL port : 443"
  echo "SSH SSL port : 80"
  echo "SOCKS port : 80"
  echo
  echo
  history -c;
  rm ~/.installer
}


 source /etc/os-release
if [[ "$ID" != 'debian' ]]; then
 ScriptMessage
 echo -e "[\e[1;31mError\e[0m] This script is for Debian only, exting..." 
 exit 1
fi
 if [[ $EUID -ne 0 ]];then
 ScriptMessage
 echo -e "[\e[1;31mError\e[0m] This script must be run as root, exiting..."
 exit 1
fi
 if [[ ! -e /dev/net/tun ]]; then
 echo -e "[\e[1;31m×\e[0m] You cant use this script without TUN Module installed/embedded in your machine, file a support ticket to your machine admin about this matter"
 echo -e "[\e[1;31m-\e[0m] Script is now exiting..."
 exit 1
fi
 ScriptMessage
 sleep 2
 InstUpdates
 echo -e "Configuring ssh..."
 InstSSH
 echo -e "Configuring stunnel..."
 InsStunnel
 echo -e "Configuring webmin..."
 InstWebmin
 echo -e "Configuring proxy..."
 InsProxy
 echo -e "Configuring OpenVPN..."
 InsOpenVPN
 OvpnConfigs
 ConfStartup
 ConfMenu
 Installssl
 install_dropbear
 install_socks
 install_stunnel
 install_done
 ln -fs /usr/share/zoneinfo/$MyVPS_Time /etc/localtime
 clear
 cd ~
 bash /etc/profile.d/dextereskalarte.sh
 ScriptMessage
 echo -e ""
 echo -e " \e[94mSuccess Installation\e[0m"
 echo -e " \e[92m Service Ports\e[0m "
 echo -e " \e[92m OpenSSH:\e[0m \e[97m$SSH_Port1, $SSH_Port2\e[0m"
 echo -e " \e[92m Stunnel:\e[0m \e[97m$Stunnel_Port1, $Stunnel_Port2\e[0m"
 echo -e " \e[92m DropbearSSH:\e[0m \e[97m$Dropbear_Port1, $Dropbear_Port2\e[0m"
 echo -e " \e[92m Privoxy:\e[0m \e[97m$Privoxy_Port1, $Privoxy_Port2\e[0m"
 echo -e " \e[92m Squid:\e[0m \e[97m$Proxy_Port1, $Proxy_Port2\e[0m"
 echo -e " \e[92m OpenVPN:\e[0m \e[97m$OpenVPN_Port1 (tcp), $OpenVPN_Port2 (udp)\e[0m"
 echo -e " \e[92m OpenVPN SSL:\e[0m \e[97m$Stunnel_Port3\e[0m"
 echo -e " \e[92m Websocket ssh:\e[0m \e[97m80\e[0m"
 echo -e " \e[92m Websocket ssl:\e[0m \e[97m443\e[0m"
 echo -e " \e[92m NGiNX:\e[0m \e[97m$OvpnDownload_Port\e[0m"
 echo -e " \e[92m Webmin:\e[0m \e[97m10000\e[0m"
 echo -e ""
 echo -e " \e[92m OpenVPN Configs Download site\e[0m"
 echo -e " \e[97m http://$IPADDR:$OvpnDownload_Port\e[0m"
 echo -e ""
 echo -e " \e[92m All OpenVPN Configs Archive\e[0m"
 echo -e " \e[97m http://$IPADDR:$OvpnDownload_Port/Configs.zip\e[0m"
  echo -e " \e[91m [Important] Take a Screenshot!\e[0m"
 echo -e ""
 echo -e " \e[92m [Note] DO NOT SELL THIS SCRIPT\e[0m"
  echo -e ""
 rm -rf /root/.bash_history && history -c && echo '' > /var/log/syslog
rm -f DebianVPS-Script.sh*
exit 1