#!/usr/bin/env bash

#====================================================
#	System Request:Debian 9+/Ubuntu 18.04+/Centos 7+
#	Author:	Dexter Eskalarte
#	Dscription: Xray onekey Management
#	email: admin@dextereskalarte.com
#====================================================

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
stty erase ^?

cd "$(
  cd "$(dirname "$0")" || exit
  pwd
)" || exit

# font color configuration
Green="\033[32m"
Red="\033[31m"
Yellow="\033[33m"
Blue="\033[36m"
Font="\033[0m"
GreenBG="\033[42;37m"
RedBG="\033[41;37m"
OK="${Green}[OK]${Font}"
ERROR="${Red}[ERROR]${Font}"

# variable
shell_version="1.3.11"
github_branch="main"
xray_conf_dir="/usr/local/etc/xray"
website_dir="/www/xray_web/"
xray_access_log="/var/log/xray/access.log"
xray_error_log="/var/log/xray/error.log"
cert_dir="/usr/local/etc/xray"
domain_tmp_dir="/usr/local/etc/xray"
cert_group="nobody"
random_num=$((RANDOM % 12 + 4))

VERSION=$(echo "${VERSION}" | awk -F "[()]" '{print $2}')
WS_PATH="/$(head -n 10 /dev/urandom | md5sum | head -c ${random_num})/"

function shell_mode_check() {
  if [ -f ${xray_conf_dir}/config.json ]; then
    if [ "$(grep -c "wsSettings" ${xray_conf_dir}/config.json)" -ge 1 ]; then
      shell_mode="ws"
    else
      shell_mode="tcp"
    fi
  else
    shell_mode="None"
  fi
}
function print_ok() {
  echo -e "${OK} ${Blue} $1 ${Font}"
}

function print_error() {
  echo -e "${ERROR} ${RedBG} $1 ${Font}"
}

function is_root() {
  if [[ 0 == "$UID" ]]; then
    print_ok "The current user is the root user, start the installation process"
  else
    print_error "The current user is not the root user, please switch to the root user and execute the script again"
    exit 1
  fi
}

judge() {
  if [[ 0 -eq $? ]]; then
    print_ok "$1 completed"
    sleep 1
  else
    print_error "$1 failed"
    exit 1
  fi
}

function system_check() {
  source '/etc/os-release'

  if [[ "${ID}" == "centos" && ${VERSION_ID} -ge 7 ]]; then
    print_ok "The current system is Centos ${VERSION_ID} ${VERSION}"
    INS="yum install -y"
    ${INS} wget
    wget -N -P /etc/yum.repos.d/ https://raw.githubusercontent.com/EskalarteDexter/V2rayFiles/${github_branch}/nginx.repo


  elif [[ "${ID}" == "ol" ]]; then
    print_ok "The current system is Oracle Linux ${VERSION_ID} ${VERSION}"
    INS="yum install -y"
    wget -N -P /etc/yum.repos.d/ https://raw.githubusercontent.com/EskalarteDexter/V2rayFiles/${github_branch}/nginx.repo
  elif [[ "${ID}" == "debian" && ${VERSION_ID} -ge 9 ]]; then
    print_ok "The current system is Debian ${VERSION_ID} ${VERSION}"
    INS="apt install -y"
    # Clear up possible legacy issues
    rm -f /etc/apt/sources.list.d/nginx.list
    # nginx Install preprocessing
    $INS curl gnupg2 ca-certificates lsb-release debian-archive-keyring
    curl https://nginx.org/keys/nginx_signing.key | gpg --dearmor \
    | tee /usr/share/keyrings/nginx-archive-keyring.gpg >/dev/null
    echo "deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] \
    http://nginx.org/packages/debian `lsb_release -cs` nginx" \
    | tee /etc/apt/sources.list.d/nginx.list
    echo -e "Package: *\nPin: origin nginx.org\nPin: release o=nginx\nPin-Priority: 900\n" \
    | tee /etc/apt/preferences.d/99nginx

    apt update

  elif [[ "${ID}" == "ubuntu" && $(echo "${VERSION_ID}" | cut -d '.' -f1) -ge 18 ]]; then
    print_ok "The current system is Ubuntu ${VERSION_ID} ${UBUNTU_CODENAME}"
    INS="apt install -y"
    # Clear up possible legacy issues
    rm -f /etc/apt/sources.list.d/nginx.list
    # nginx Install preprocessing
    $INS curl gnupg2 ca-certificates lsb-release ubuntu-keyring
    curl https://nginx.org/keys/nginx_signing.key | gpg --dearmor \
    | tee /usr/share/keyrings/nginx-archive-keyring.gpg >/dev/null
    echo "deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] \
    http://nginx.org/packages/ubuntu `lsb_release -cs` nginx" \
    | tee /etc/apt/sources.list.d/nginx.list
    echo -e "Package: *\nPin: origin nginx.org\nPin: release o=nginx\nPin-Priority: 900\n" \
    | tee /etc/apt/preferences.d/99nginx

    apt update
  else
    print_error "The current system is ${ID} ${VERSION_ID} Not in the list of supported systems"
    exit 1
  fi

  if [[ $(grep "nogroup" /etc/group) ]]; then
    cert_group="nogroup"
  fi

  $INS dbus

  # 关闭各类防火墙
  systemctl stop firewalld
  systemctl disable firewalld
  systemctl stop nftables
  systemctl disable nftables
  systemctl stop ufw
  systemctl disable ufw
}

function nginx_install() {
  if ! command -v nginx >/dev/null 2>&1; then
    ${INS} nginx
    judge "Nginx Install"
  else
    print_ok "Nginx 已存在"
  fi
  # Dealing with Legacy Issues
  mkdir -p /etc/nginx/conf.d >/dev/null 2>&1
}
function dependency_install() {
  ${INS} lsof tar
  judge "Install lsof tar"

  if [[ "${ID}" == "centos" || "${ID}" == "ol" ]]; then
    ${INS} crontabs
  else
    ${INS} cron
  fi
  judge "Install crontab"

  if [[ "${ID}" == "centos" || "${ID}" == "ol" ]]; then
    touch /var/spool/cron/root && chmod 600 /var/spool/cron/root
    systemctl start crond && systemctl enable crond
  else
    touch /var/spool/cron/crontabs/root && chmod 600 /var/spool/cron/crontabs/root
    systemctl start cron && systemctl enable cron

  fi
  judge "crontab autostart configuration "

  ${INS} unzip
  judge "Install unzip"

  ${INS} curl
  judge "Install curl"

  # upgrade systemd
  ${INS} systemd
  judge "Install/upgrade systemd"

  # Nginx postfix no compilation no longer needed
  #  if [[ "${ID}" == "centos" ||  "${ID}" == "ol" ]]; then
  #    yum -y groupinstall "Development tools"
  #  else
  #    ${INS} build-essential
  #  fi
  #  judge "build toolkit Install"

  if [[ "${ID}" == "centos" ]]; then
    ${INS} pcre pcre-devel zlib-devel epel-release openssl openssl-devel
  elif [[ "${ID}" == "ol" ]]; then
    ${INS} pcre pcre-devel zlib-devel openssl openssl-devel
    # Oracle Linux The VERSION_ID of different date versions is messy. Direct violence. If there is a problem or there is a better solution, please submit Issue。
    yum-config-manager --enable ol7_developer_EPEL >/dev/null 2>&1
    yum-config-manager --enable ol8_developer_EPEL >/dev/null 2>&1
  else
    ${INS} libpcre3 libpcre3-dev zlib1g-dev openssl libssl-dev
  fi

  ${INS} jq

  if ! command -v jq; then
    wget -P /usr/bin https://raw.githubusercontent.com/EskalarteDexter/V2rayFiles/${github_branch}/jq && chmod +x /usr/bin/jq
    judge "Install jq"
  fi

  # Prevent the default bin directory of xray in some systems from missing
  mkdir /usr/local/bin >/dev/null 2>&1
}

function basic_optimization() {
  # Maximum number of open files
  sed -i '/^\*\ *soft\ *nofile\ *[[:digit:]]*/d' /etc/security/limits.conf
  sed -i '/^\*\ *hard\ *nofile\ *[[:digit:]]*/d' /etc/security/limits.conf
  echo '* soft nofile 65536' >>/etc/security/limits.conf
  echo '* hard nofile 65536' >>/etc/security/limits.conf

  # RedHat system distro close SELinux
  if [[ "${ID}" == "centos" || "${ID}" == "ol" ]]; then
    sed -i 's/^SELINUX=.*/SELINUX=disabled/' /etc/selinux/config
    setenforce 0
  fi
}

function domain_check() {
  read -rp "Please enter your domain name information(eg: www.dextereskalarte.com):" domain
  domain_ip=$(curl -sm8 ipget.net/?ip="${domain}")
  print_ok "Obtaining IP address information, please be patient"
  wgcfv4_status=$(curl -s4m8 https://www.cloudflare.com/cdn-cgi/trace -k | grep warp | cut -d= -f2)
  wgcfv6_status=$(curl -s6m8 https://www.cloudflare.com/cdn-cgi/trace -k | grep warp | cut -d= -f2)
  if [[ ${wgcfv4_status} =~ "on"|"plus" ]] || [[ ${wgcfv6_status} =~ "on"|"plus" ]]; then
    # Close wgcf-warp to prevent misjudgment of VPS IP
    wg-quick down wgcf >/dev/null 2>&1
    print_ok "Closed wgcf-warp"
  fi
  local_ipv4=$(curl -4 ip.sb)
  local_ipv6=$(curl -6 ip.sb)
  if [[ -z ${local_ipv4} && -n ${local_ipv6} ]]; then
    # Pure IPv6 VPS, automatically add DNS64 server for acme.sh application certificate
    echo -e nameserver 2a01:4f8:c2c:123f::1 > /etc/resolv.conf
    print_ok "VPS recognized as IPv6 Only, automatically add DNS64 server"
  fi
  echo -e "The IP address of the domain name resolved through DNS：${domain_ip}"
  echo -e "Local public network IPv4 address： ${local_ipv4}"
  echo -e "Local public network IPv6 address： ${local_ipv6}"
  sleep 2
  if [[ ${domain_ip} == "${local_ipv4}" ]]; then
    print_ok "The IP address resolved by the domain name through DNS matches the local IPv4 address"
    sleep 2
  elif [[ ${domain_ip} == "${local_ipv6}" ]]; then
    print_ok "The IP address resolved by the domain name through DNS matches the native IPv6 address"
    sleep 2
  else
    print_error "Please make sure that the correct A/AAAA records are added to the domain name, otherwise it will not work properly xray"
    print_error "The IP address resolved by the domain name through DNS does not match the local IPv4/IPv6 address. Do you want to continue the installation? (y/n)" && read -r install
    case $install in
    [yY][eE][sS] | [yY])
      print_ok "continue to install"
      sleep 2
      ;;
    *)
      print_error "installation terminated"
      exit 2
      ;;
    esac
  fi
}

function port_exist_check() {
  if [[ 0 -eq $(lsof -i:"$1" | grep -i -c "listen") ]]; then
    print_ok "$1 port is not used"
    sleep 1
  else
    print_error "It is detected that the $1 port is occupied, and the following is the $1 port occupancy information"
    lsof -i:"$1"
    print_error "5s will try to automatically kill the occupying process"
    sleep 5
    lsof -i:"$1" | awk '{print $2}' | grep -v "PID" | xargs kill -9
    print_ok "kill completed"
    sleep 1
  fi
}
function update_sh() {
  ol_version=$(curl -L -s https://raw.githubusercontent.com/EskalarteDexter/Autoscript/main/dragonz/install.sh | grep "shell_version=" | head -1 | awk -F '=|"' '{print $3}')
  if [[ "$shell_version" != "$(echo -e "$shell_version\n$ol_version" | sort -rV | head -1)" ]]; then
    print_ok "New version exists, update [Y/N]?"
    read -r update_confirm
    case $update_confirm in
    [yY][eE][sS] | [yY])
      wget -N --no-check-certificate https://raw.githubusercontent.com/EskalarteDexter/Autoscript/main/dragonz/install.sh
      print_ok "update completed"
      print_ok "You can execute this program through bash $0"
      exit 0
      ;;
    *) ;;
    esac
  else
    print_ok "The current version is the latest version"
    print_ok "You can execute this program through bash $0"
  fi
}

function xray_tmp_config_file_check_and_use() {
  if [[ -s ${xray_conf_dir}/config_tmp.json ]]; then
    mv -f ${xray_conf_dir}/config_tmp.json ${xray_conf_dir}/config.json
  else
    print_error "xray Configuration file modification exception"
  fi
}

function modify_UUID() {
  [ -z "$UUID" ] && UUID=$(cat /proc/sys/kernel/random/uuid)
  cat ${xray_conf_dir}/config.json | jq 'setpath(["inbounds",0,"settings","clients",0,"id"];"'${UUID}'")' >${xray_conf_dir}/config_tmp.json
  xray_tmp_config_file_check_and_use
  judge "Xray TCP UUID Revise"
}

function modify_UUID_ws() {
  cat ${xray_conf_dir}/config.json | jq 'setpath(["inbounds",1,"settings","clients",0,"id"];"'${UUID}'")' >${xray_conf_dir}/config_tmp.json
  xray_tmp_config_file_check_and_use
  judge "Xray ws UUID Revise"
}

function modify_fallback_ws() {
  cat ${xray_conf_dir}/config.json | jq 'setpath(["inbounds",0,"settings","fallbacks",2,"path"];"'${WS_PATH}'")' >${xray_conf_dir}/config_tmp.json
  xray_tmp_config_file_check_and_use
  judge "Xray fallback_ws Revise"
}

function modify_ws() {
  cat ${xray_conf_dir}/config.json | jq 'setpath(["inbounds",1,"streamSettings","wsSettings","path"];"'${WS_PATH}'")' >${xray_conf_dir}/config_tmp.json
  xray_tmp_config_file_check_and_use
  judge "Xray ws Revise"
}

function configure_nginx() {
  nginx_conf="/etc/nginx/conf.d/${domain}.conf"
  cd /etc/nginx/conf.d/ && rm -f ${domain}.conf && wget -O ${domain}.conf https://raw.githubusercontent.com/EskalarteDexter/V2rayFiles/${github_branch}/web.conf
  sed -i "s/xxx/${domain}/g" ${nginx_conf}
  judge "Nginx configuration modify"
  
  systemctl enable nginx
  systemctl restart nginx
}

function modify_port() {
  read -rp "Please enter the port number (default：443)：" PORT
  [ -z "$PORT" ] && PORT="443"
  if [[ $PORT -le 0 ]] || [[ $PORT -gt 65535 ]]; then
    print_error "Please enter a value between 0-65535"
    exit 1
  fi
  port_exist_check $PORT
  cat ${xray_conf_dir}/config.json | jq 'setpath(["inbounds",0,"port"];'${PORT}')' >${xray_conf_dir}/config_tmp.json
  xray_tmp_config_file_check_and_use
  judge "Xray port modification"
}

function configure_xray() {
  cd /usr/local/etc/xray && rm -f config.json && wget -O config.json https://raw.githubusercontent.com/EskalarteDexter/V2rayFiles/${github_branch}/xray_xtls-rprx-direct.json
  modify_UUID
  modify_port
}

function configure_xray_ws() {
  cd /usr/local/etc/xray && rm -f config.json && wget -O config.json https://raw.githubusercontent.com/EskalarteDexter/V2rayFiles/${github_branch}/xray_tls_ws_mix-rprx-direct.json
  modify_UUID
  modify_UUID_ws
  modify_port
  modify_fallback_ws
  modify_ws
}

function xray_install() {
  print_ok "Install Xray"
  curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh | bash -s -- install
  judge "Xray installation"

  # Import link for generating Xray
  echo $domain >$domain_tmp_dir/domain
  judge "domain name record"
}

function ssl_install() {
  #  Use Nginx to cooperate and issue, no need to install related dependencies
  #  if [[ "${ID}" == "centos" ||  "${ID}" == "ol" ]]; then
  #    ${INS} socat nc
  #  else
  #    ${INS} socat netcat
  #  fi
  #  judge "安装 SSL 证书生成脚本依赖"

  curl -L https://get.acme.sh | bash
  judge "Install the SSL certificate generation script"
}

function acme() {
  "$HOME"/.acme.sh/acme.sh --set-default-ca --server letsencrypt

  sed -i "6s/^/#/" "$nginx_conf"
  sed -i "6a\\\troot $website_dir;" "$nginx_conf"
  systemctl restart nginx

  if "$HOME"/.acme.sh/acme.sh --issue --insecure -d "${domain}" --webroot "$website_dir" -k ec-256 --force; then
    print_ok "SSL Certificate generated successfully"
    sleep 2
    if "$HOME"/.acme.sh/acme.sh --installcert -d "${domain}" --fullchainpath /ssl/xray.crt --keypath /ssl/xray.key --reloadcmd "systemctl restart xray" --ecc --force; then
      print_ok "SSL The certificate configuration is successful"
      sleep 2
      if [[ -n $(type -P wgcf) && -n $(type -P wg-quick) ]]; then
        wg-quick up wgcf >/dev/null 2>&1
        print_ok "wgcf-warp started"
      fi
    fi
  elif "$HOME"/.acme.sh/acme.sh --issue --insecure -d "${domain}" --webroot "$website_dir" -k ec-256 --force --listen-v6; then
    print_ok "SSL Certificate generated successfully"
    sleep 2
    if "$HOME"/.acme.sh/acme.sh --installcert -d "${domain}" --fullchainpath /ssl/xray.crt --keypath /ssl/xray.key --reloadcmd "systemctl restart xray" --ecc --force; then
      print_ok "SSL The certificate configuration is successful"
      sleep 2
      if [[ -n $(type -P wgcf) && -n $(type -P wg-quick) ]]; then
        wg-quick up wgcf >/dev/null 2>&1
        print_ok "wgcf-warp started"
      fi
    fi
  else
    print_error "SSL certificate generation failed"
    rm -rf "$HOME/.acme.sh/${domain}_ecc"
    if [[ -n $(type -P wgcf) && -n $(type -P wg-quick) ]]; then
      wg-quick up wgcf >/dev/null 2>&1
      print_ok "wgcf-warp started"
    fi
    exit 1
  fi

  sed -i "7d" "$nginx_conf"
  sed -i "6s/#//" "$nginx_conf"
}

function ssl_judge_and_install() {

  mkdir -p /ssl >/dev/null 2>&1
  if [[ -f "/ssl/xray.key" || -f "/ssl/xray.crt" ]]; then
    print_ok "/ssl The certificate file already exists in the directory"
    print_ok "Whether to delete the certificate file under the /ssl directory [Y/N]?"
    read -r ssl_delete
    case $ssl_delete in
    [yY][eE][sS] | [yY])
      rm -rf /ssl/*
      print_ok "deleted"
      ;;
    *) ;;

    esac
  fi

  if [[ -f "/ssl/xray.key" || -f "/ssl/xray.crt" ]]; then
    echo "Certificate file already exists"
  elif [[ -f "$HOME/.acme.sh/${domain}_ecc/${domain}.key" && -f "$HOME/.acme.sh/${domain}_ecc/${domain}.cer" ]]; then
    echo "Certificate file already exists"
    "$HOME"/.acme.sh/acme.sh --installcert -d "${domain}" --fullchainpath /ssl/xray.crt --keypath /ssl/xray.key --ecc
    judge "certificate enable"
  else
    mkdir /ssl
    cp -a $cert_dir/self_signed_cert.pem /ssl/xray.crt
    cp -a $cert_dir/self_signed_key.pem /ssl/xray.key
    ssl_install
    acme
  fi

  # Xray runs as the nobody user by default, and the certificate permissions are adapted
  chown -R nobody.$cert_group /ssl/*
}

function generate_certificate() {
  if [[ -z ${local_ipv4} && -n ${local_ipv6} ]]; then
    signedcert=$(xray tls cert -domain="$local_ipv6" -name="$local_ipv6" -org="$local_ipv6" -expire=87600h)
  else
    signedcert=$(xray tls cert -domain="$local_ipv4" -name="$local_ipv4" -org="$local_ipv4" -expire=87600h)
  fi
  echo $signedcert | jq '.certificate[]' | sed 's/\"//g' | tee $cert_dir/self_signed_cert.pem
  echo $signedcert | jq '.key[]' | sed 's/\"//g' >$cert_dir/self_signed_key.pem
  openssl x509 -in $cert_dir/self_signed_cert.pem -noout || (print_error "Failed to generate self-signed certificate" && exit 1)
  print_ok "Successfully generated self-signed certificate"
  chown nobody.$cert_group $cert_dir/self_signed_cert.pem
  chown nobody.$cert_group $cert_dir/self_signed_key.pem
}

function configure_web() {
  rm -rf /www/xray_web
  mkdir -p /www/xray_web
  print_ok "Do you want to configure camouflaged web pages? [Y/N]"
  read -r webpage
  case $webpage in
  [yY][eE][sS] | [yY])
    wget -O web.tar.gz https://raw.githubusercontent.com/EskalarteDexter/V2rayFiles/main/web.tar.gz
    tar xzf web.tar.gz -C /www/xray_web
    judge "site masquerading"
    rm -f web.tar.gz
    ;;
  *) ;;
  esac
}

function xray_uninstall() {
  curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh | bash -s -- remove --purge
  rm -rf $website_dir
  print_ok "Whether to uninstall nginx [Y/N] installed?"
  read -r uninstall_nginx
  case $uninstall_nginx in
  [yY][eE][sS] | [yY])
    if [[ "${ID}" == "centos" || "${ID}" == "ol" ]]; then
      yum remove nginx -y
    else
      apt purge nginx -y
    fi
    ;;
  *) ;;
  esac
  print_ok "Whether to uninstall acme.sh [Y/N]?"
  read -r uninstall_acme
  case $uninstall_acme in
  [yY][eE][sS] | [yY])
    "$HOME"/.acme.sh/acme.sh --uninstall
    rm -rf /root/.acme.sh
    rm -rf /ssl/
    ;;
  *) ;;
  esac
  print_ok "uninstall complete"
  exit 0
}

function restart_all() {
  systemctl restart nginx
  judge "Nginx start up"
  systemctl restart xray
  judge "Xray start up"
}

function vless_xtls-rprx-direct_link() {
  UUID=$(cat ${xray_conf_dir}/config.json | jq .inbounds[0].settings.clients[0].id | tr -d '"')
  PORT=$(cat ${xray_conf_dir}/config.json | jq .inbounds[0].port)
  FLOW=$(cat ${xray_conf_dir}/config.json | jq .inbounds[0].settings.clients[0].flow | tr -d '"')
  DOMAIN=$(cat ${domain_tmp_dir}/domain)

  print_ok "URL Link (VLESS + TCP + TLS)"
  print_ok "vless://$UUID@$DOMAIN:$PORT?security=tls&flow=$FLOW#TLS_wulabing-$DOMAIN"

  print_ok "URL Link (VLESS + TCP + XTLS)"
  print_ok "vless://$UUID@$DOMAIN:$PORT?security=xtls&flow=$FLOW#XTLS_wulabing-$DOMAIN"
  print_ok "-------------------------------------------------"
  print_ok "URL 二QR code (VLESS + TCP + TLS) (Please visit in browser)"
  print_ok "https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=vless://$UUID@$DOMAIN:$PORT?security=tls%26flow=$FLOW%23TLS_wulabing-$DOMAIN"

  print_ok "URL 二QR code(VLESS + TCP + XTLS) (Please visit in browser)"
  print_ok "https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=vless://$UUID@$DOMAIN:$PORT?security=xtls%26flow=$FLOW%23XTLS_wulabing-$DOMAIN"
}

function vless_xtls-rprx-direct_information() {
  UUID=$(cat ${xray_conf_dir}/config.json | jq .inbounds[0].settings.clients[0].id | tr -d '"')
  PORT=$(cat ${xray_conf_dir}/config.json | jq .inbounds[0].port)
  FLOW=$(cat ${xray_conf_dir}/config.json | jq .inbounds[0].settings.clients[0].flow | tr -d '"')
  DOMAIN=$(cat ${domain_tmp_dir}/domain)

  echo -e "${Red} Xray Configuration Information ${Font}"
  echo -e "${Red} address :${Font}  $DOMAIN"
  echo -e "${Red} port ：${Font}  $PORT"
  echo -e "${Red} UUID ：${Font} $UUID"
  echo -e "${Red} flow ：${Font} $FLOW"
  echo -e "${Red} security ：${Font} none "
  echo -e "${Red} network ：${Font} tcp "
  echo -e "${Red} type ：${Font} none "
  echo -e "${Red} underlying transport security：${Font} xtls or tls"
}

function ws_information() {
  UUID=$(cat ${xray_conf_dir}/config.json | jq .inbounds[0].settings.clients[0].id | tr -d '"')
  PORT=$(cat ${xray_conf_dir}/config.json | jq .inbounds[0].port)
  FLOW=$(cat ${xray_conf_dir}/config.json | jq .inbounds[0].settings.clients[0].flow | tr -d '"')
  WS_PATH=$(cat ${xray_conf_dir}/config.json | jq .inbounds[0].settings.fallbacks[2].path | tr -d '"')
  DOMAIN=$(cat ${domain_tmp_dir}/domain)

  echo -e "${Red} Xray Configuration Information ${Font}"
  echo -e "${Red} address :${Font}  $DOMAIN"
  echo -e "${Red} port ：${Font}  $PORT"
  echo -e "${Red} UUID ：${Font} $UUID"
  echo -e "${Red} security ：${Font} none "
  echo -e "${Red} network ：${Font} ws "
  echo -e "${Red} type ：${Font} none "
  echo -e "${Red} path ：${Font} $WS_PATH "
  echo -e "${Red} underlying transport security：${Font} tls "
}

function ws_link() {
  UUID=$(cat ${xray_conf_dir}/config.json | jq .inbounds[0].settings.clients[0].id | tr -d '"')
  PORT=$(cat ${xray_conf_dir}/config.json | jq .inbounds[0].port)
  FLOW=$(cat ${xray_conf_dir}/config.json | jq .inbounds[0].settings.clients[0].flow | tr -d '"')
  WS_PATH=$(cat ${xray_conf_dir}/config.json | jq .inbounds[0].settings.fallbacks[2].path | tr -d '"')
  WS_PATH_WITHOUT_SLASH=$(echo $WS_PATH | tr -d '/')
  DOMAIN=$(cat ${domain_tmp_dir}/domain)
  echo -e ""
  echo -e ""
  print_ok "Dexter Eskalarte link config (VLESS + TCP + TLS)"
  print_ok "vless://$UUID@$DOMAIN:$PORT?security=tls#TLS_wulabing-$DOMAIN"
  echo -e ""
  echo -e ""
  print_ok "Dexter Eskalarte link config (VLESS + TCP + XTLS)"
  print_ok "vless://$UUID@$DOMAIN:$PORT?security=xtls&flow=$FLOW#XTLS_wulabing-$DOMAIN"
  echo -e ""
  echo -e ""
  print_ok "Dexter Eskalarte link config (VLESS + WebSocket + TLS)"
  print_ok "vless://$UUID@$DOMAIN:$PORT?type=ws&security=tls&path=%2f${WS_PATH_WITHOUT_SLASH}%2f#WS_TLS_wulabing-$DOMAIN"
}

function basic_information() {
  print_ok "VLESS+TCP+XTLS+Nginx installed successfully"
  vless_xtls-rprx-direct_information
  vless_xtls-rprx-direct_link
}

function basic_ws_information() {
  print_ok "VLESS+TCP+TLS+Nginx with WebSocket mixed mode installed successfully"
  ws_information
  echo -e ""
  print_ok "————————————————————————"
  echo -e ""
  vless_xtls-rprx-direct_information
  ws_link
}

function show_access_log() {
  [ -f ${xray_access_log} ] && tail -f ${xray_access_log} || echo -e "${RedBG}log file does not exist${Font}"
}

function show_error_log() {
  [ -f ${xray_error_log} ] && tail -f ${xray_error_log} || echo -e "${RedBG}log file does not exist${Font}"
}

function bbr_boost_sh() {
  [ -f "tcp.sh" ] && rm -rf ./tcp.sh
  wget -N --no-check-certificate "https://raw.githubusercontent.com/EskalarteDexter/V2rayFiles/main/tcp.sh" && chmod +x tcp.sh && ./tcp.sh
}

function mtproxy_sh() {
  wget -N --no-check-certificate "https://raw.githubusercontent.com/EskalarteDexter/V2rayFiles/main/mtproxy.sh" && chmod +x mtproxy.sh && bash mtproxy.sh
}

function install_xray() {
  is_root
  system_check
  dependency_install
  basic_optimization
  domain_check
  port_exist_check 80
  xray_install
  configure_xray
  nginx_install
  configure_nginx
  configure_web
  generate_certificate
  ssl_judge_and_install
  restart_all
  basic_information
}
function install_xray_ws() {
  is_root
  system_check
  dependency_install
  basic_optimization
  domain_check
  port_exist_check 80
  xray_install
  configure_xray_ws
  nginx_install
  configure_nginx
  configure_web
  generate_certificate
  ssl_judge_and_install
  restart_all
  basic_ws_information
}
menu() {
  update_sh
  shell_mode_check
  
  echo -e "$GREEN
  
   ██████╗ ███████╗██╗  ██╗████████╗███████╗██████╗ 
   ██╔══██╗██╔════╝╚██╗██╔╝╚══██╔══╝██╔════╝██╔══██╗
   ██║  ██║█████╗   ╚███╔╝    ██║   █████╗  ██████╔╝
   ██║  ██║██╔══╝   ██╔██╗    ██║   ██╔══╝  ██╔══██╗
   ██████╔╝███████╗██╔╝ ██╗   ██║   ███████╗██║  ██║
   ╚═════╝ ╚══════╝╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝		
$RESET"
  echo -e ""
  echo -e ""
  echo -e "Currently installed version：${shell_mode}"
  echo -e ""
  echo -e "—————————————— Installation Guide ——————————————"
  echo -e ""
  echo -e "${Green}0.${Font}  upgrade script"
  echo -e "${Green}1.${Font}  Install Xray (VLESS + TCP + XTLS / TLS + Nginx)"
  echo -e "${Green}2.${Font}  Install Xray (VLESS + TCP + XTLS / TLS + Nginx and VLESS + TCP + TLS + Nginx + WebSocket)"
  echo -e ""
  echo -e ""
  read -rp "Select Number (Default 2): " menu_num
  case $menu_num in
  0)
    update_sh
    ;;
  1)
    install_xray
    ;;
  2)
    install_xray_ws
    ;;
  11)
    read -rp "please enter UUID:" UUID
    if [[ ${shell_mode} == "tcp" ]]; then
      modify_UUID
    elif [[ ${shell_mode} == "ws" ]]; then
      modify_UUID
      modify_UUID_ws
    fi
    restart_all
    ;;
  13)
    modify_port
    restart_all
    ;;
  14)
    if [[ ${shell_mode} == "ws" ]]; then
      read -rp "Please enter the path (example：/dexterpogi/ Requires both sides to contain /):" WS_PATH
      modify_fallback_ws
      modify_ws
      restart_all
    else
      print_error "The current mode is not Websocket mode"
    fi
    ;;
  21)
    tail -f $xray_access_log
    ;;
  22)
    tail -f $xray_error_log
    ;;
  23)
    if [[ -f $xray_conf_dir/config.json ]]; then
      if [[ ${shell_mode} == "tcp" ]]; then
        basic_information
      elif [[ ${shell_mode} == "ws" ]]; then
        basic_ws_information
      fi
    else
      print_error "xray configuration file does not exist"
    fi
    ;;
  31)
    bbr_boost_sh
    ;;
  32)
    mtproxy_sh
    ;;
  33)
    source '/etc/os-release'
    xray_uninstall
    ;;
  34)
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" - install
    restart_all
    ;;
  35)
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" - install --beta
    restart_all
    ;;
  36)
    "/root/.acme.sh"/acme.sh --cron --home "/root/.acme.sh"
    restart_all
    ;;
  40)
    exit 0
    ;;
  *)
    print_error "Please enter the correct number"
    ;;
  esac
}
menu "$@"
