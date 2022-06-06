#!/bin/bash

# Color
N="\033[0m"
R="\033[31m"
G="\033[32m"
B="\033[34m"
Y="\033[33m"
C="\033[36m"
M="\033[35m"
LR="\033[1;31m"
LG="\033[1;32m"
LB="\033[1;34m"
RB="\033[41;37m"
GB="\033[42;37m"
BB="\033[44;37m"

# Notification
OK="${LG}[✔]${N}"
ERROR="${LR}[✘]${N}"
INFO="${LB}[+]${N}"

ok() {
  echo -e "${OK} ${LG}$1${N}"
}

error() {
  echo -e "${ERROR} ${LR}$1${N}"
}

info() {
  echo -e "${INFO} ${LB}$1${N}"
}

newline() {
  echo -e ""
}

check_package() {
  if hash $1 > /dev/null 2>&1; then
    ok "$1 is installed"
  else
    error "$1 is not installed"
  fi
}

check_service() {
  if systemctl is-active $1 > /dev/null 2>&1; then
    ok "$1 is running"
  else
    error "$1 is not running"
  fi
}

check_screen() {
	if screen -ls | grep -qw $1; then
		ok "$1 is running"
	else
		error "$1 is not running"
	fi
}

check_system() {
  if grep -qs "ubuntu" /etc/os-release; then
    os="ubuntu"
    os_version=$(grep 'VERSION_ID' /etc/os-release | cut -d '"' -f 2 | tr -d '.')
    group_name="nogroup"
  elif [[ -e /etc/debian_version ]]; then
    os="debian"
    os_version=$(grep -oE '[0-9]+' /etc/debian_version | head -1)
    group_name="nogroup" 
  fi
  if [[ "$os" == "ubuntu" && "$os_version" -lt 2004 ]]; then
    info "Ubuntu 20.04 or higher is required to use this autoscript"
    exit 1
  elif [[ "$os" == "debian" && "$os_version" -lt 10 ]]; then
    info "Debian 10 or higher is required to use this autoscript"
    exit 1
  fi
}

check_root() {
  if [[ "$EUID" -ne 0 ]]; then
  	error "This autoscript needs to be run with root privileges"
  	exit 1
  fi
}

start_install() {
repo="https://raw.githubusercontent.com/mrjohntora/autoscript-metavpn/main/"
net=$(ip link | awk -F: '$0 !~ "lo|vir|wl|^[^0-9]"{print $2;getline}' | head -n 1)
domain=$(hostname -f)
localhost=$(hostname -s)
host=$(hostname -d)
ip=$(wget -qO- ipv4.icanhazip.com)
domain_ip=$(ping "${domain}" -c 1 | sed '1{s/[^(]*(//;s/).*//;q}')

clear
newline 
info "Checking system requirements"
sleep 2
check_system
check_root
sleep 2
ok "System meets operational requirements"
sleep 3

clear
newline 
info "Checking available package update"
sleep 2
apt update && apt list --upgradable 
sleep 2
newline
info "Installing package update"
sleep 2
apt upgrade -y
sleep 2
ok "Successful updated system"
sleep 3

clear
newline
info "Installing autoscript dependencies"
sleep 2
apt install systemd curl wget screen cmake zip unzip vnstat tar openssl git socat uuid-runtime -y
sleep 2
check_package "curl"
check_package "wget"
check_package "screen"
check_package "cmake"
check_package "vnstat"
check_package "openssl"
check_package "git"
check_package "socat"
check_package "uuid-runtime"
sleep 2
ok "Successful installed dependencies"
sleep 3

clear
newline
info "Enter a valid domain: \c"
read domain
info "Checking domain"
sleep 2
if [[ ${domain_ip} == "${ip}" ]]; then
	ok "DNS-resolved domain IP matches the public IP"
	echo -e ""
else
	error "Domain IP resolved through DNS does not match the IP of the server"
	exit 1
fi
sleep 2
newline
info "Optimizing system"
sleep 2
sed -i '/^\*\ *soft\ *nofile\ *[[:digit:]]*/d' /etc/security/limits.conf
sed -i '/^\*\ *hard\ *nofile\ *[[:digit:]]*/d' /etc/security/limits.conf
echo -e "* soft nofile 65536
* hard nofile 65536" >> /etc/security/limits.conf
locale-gen en_US
sleep 2
newline
info "Disabling IPv6 setting"
sleep 2
sysctl -w net.ipv6.conf.all.disable_ipv6=1
sysctl -w net.ipv6.conf.default.disable_ipv6=1
sysctl -w net.ipv6.conf.lo.disable_ipv6=1
echo -e "net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1" >> /etc/sysctl.conf
sysctl -p
sleep 2
newline
info "Reset iptables setting"
sleep 2
ufw disable
apt install iptables-persistent -y
sleep 2
check_package "iptables-persistent"
sleep 2
newline
iptables-save | awk '/^[*]/ { print $1 } 
                     /^:[A-Z]+ [^-]/ { print $1 " ACCEPT" ; }
                     /COMMIT/ { print $0; }' | iptables-restore
sleep 2
ok "Successful optimized system"
ok "Successful disabled IPv6"
ok "Successful reset iptables"
sleep 3

clear
newline
info "Installing cron"
sleep 2
apt install cron -y
sleep 2
check_package "cron"
sleep 2
newline
info "Configuring cron"
sleep 2
mkdir /metavpn
wget -O /metavpn/cron.daily "${repo}files/cron.daily"
chmod +x /metavpn/cron.daily
(crontab -l;echo "0 6 * * * /metavpn/cron.daily") | crontab -
ok "Successful configured cron"
sleep 3

clear
newline
info "Configuring ssh"
sleep 2
echo -e "WELCOME TO META VPN" > /etc/issue.net
sed -i "s/#Banner none/Banner \/etc\/issue.net/g" /etc/ssh/sshd_config
mkdir /metavpn/ssh
touch /metavpn/ssh/ssh-clients.tx
sleep 2
systemctl restart ssh
check_service "ssh"
sleep 2
ok "Successful configured ssh"
sleep 3

clear
newline
info "Installing dropbear"
sleep 2
apt install dropbear -y
sleep 2
check_package "dropbear"
sleep 2
newline
info "Configuring dropbear"
sleep 2
sed -i "s/NO_START=1/NO_START=0/g" /etc/default/dropbear
sed -i "s/DROPBEAR_PORT=22/DROPBEAR_PORT=110/g" /etc/default/dropbear
sed -i "s/DROPBEAR_EXTRA_ARGS=/DROPBEAR_EXTRA_ARGS=465/g" /etc/default/dropbear
echo -e "/bin/false" >> /etc/shells
wget -O /etc/dropbear_issue.net "${repo}files/dropbear_issue.net"
sed -i 's|DROPBEAR_BANNER=""|DROPBEAR_BANNER="/etc/dropbear_issue.net"|g' /etc/default/dropbear
systemctl restart dropbear
check_service "dropbear"
sleep 2
ok "Successful configured dropbear"
sleep 3

clear
newline
info "Installing stunnel"
sleep 2
apt install stunnel4 -y
sleep 2
check_package "stunnel4"
sleep 2
newline
info "Configuring stunnel"
sleep 2
sed -i "s/ENABLED=0/ENABLED=1/g" /etc/default/stunnel4
openssl req -new -newkey rsa:2048 -days 3650 -nodes -x509 -sha256 -subj "/CN=Meta VPN/emailAddress=admin@metavpn.tk/O=DigitalOcean, LLC/OU=Meta VPN/C=MY" -keyout /etc/stunnel/stunnel.pem -out /etc/stunnel/stunnel.pem
wget -O /etc/stunnel/stunnel.conf "${repo}files/stunnel.conf"
systemctl restart stunnel4
check_service "stunnel4"
sleep 2
ok "Successful configured stunnel"
sleep 3

clear
newline
info "Installing openvpn"
sleep 2
apt install openvpn -y
sleep 2
check_package "openvpn"
sleep 2
newline
info "Configuring openvpn"
sleep 2
wget "${repo}files/openvpn/EasyRSA-3.0.8.tgz"
tar xvf EasyRSA-3.0.8.tgz
mv EasyRSA-3.0.8 /etc/openvpn/easy-rsa
cp /etc/openvpn/easy-rsa/vars.example /etc/openvpn/easy-rsa/vars
sed -i 's/#set_var EASYRSA_REQ_COUNTRY\t"US"/set_var EASYRSA_REQ_COUNTRY\t"MY"/g' /etc/openvpn/easy-rsa/vars
sed -i 's/#set_var EASYRSA_REQ_PROVINCE\t"California"/set_var EASYRSA_REQ_PROVINCE\t"Wilayah Persekutuan"/g' /etc/openvpn/easy-rsa/vars
sed -i 's/#set_var EASYRSA_REQ_CITY\t"San Francisco"/set_var EASYRSA_REQ_CITY\t"Kuala Lumpur"/g' /etc/openvpn/easy-rsa/vars
sed -i 's/#set_var EASYRSA_REQ_ORG\t"Copyleft Certificate Co"/set_var EASYRSA_REQ_ORG\t\t"DigitalOcean, LLC"/g' /etc/openvpn/easy-rsa/vars
sed -i 's/#set_var EASYRSA_REQ_EMAIL\t"me@example.net"/set_var EASYRSA_REQ_EMAIL\t"admin@metavpn.tk"/g' /etc/openvpn/easy-rsa/vars
sed -i 's/#set_var EASYRSA_REQ_OU\t\t"My Organizational Unit"/set_var EASYRSA_REQ_OU\t\t"Meta VPN"/g' /etc/openvpn/easy-rsa/vars
sed -i 's/#set_var EASYRSA_CA_EXPIRE\t3650/set_var EASYRSA_CA_EXPIRE\t3650/g' /etc/openvpn/easy-rsa/vars
sed -i 's/#set_var EASYRSA_CERT_EXPIRE\t825/set_var EASYRSA_CERT_EXPIRE\t3650/g' /etc/openvpn/easy-rsa/vars
sed -i 's/#set_var EASYRSA_REQ_CN\t\t"ChangeMe"/set_var EASYRSA_REQ_CN\t\t"Meta VPN"/g' /etc/openvpn/easy-rsa/vars
cd /etc/openvpn/easy-rsa
./easyrsa --batch init-pki
./easyrsa --batch build-ca nopass
./easyrsa gen-dh
./easyrsa build-server-full server nopass
cd
mkdir /etc/openvpn/key
cp /etc/openvpn/easy-rsa/pki/issued/server.crt /etc/openvpn/key/
cp /etc/openvpn/easy-rsa/pki/ca.crt /etc/openvpn/key/
cp /etc/openvpn/easy-rsa/pki/dh.pem /etc/openvpn/key/
cp /etc/openvpn/easy-rsa/pki/private/server.key /etc/openvpn/key/
wget -O /etc/openvpn/server-udp.conf "${repo}files/openvpn/server-udp.conf"
wget -O /etc/openvpn/server-tcp.conf "${repo}files/openvpn/server-tcp.conf"
sed -i "s/#AUTOSTART="all"/AUTOSTART="all"/g" /etc/default/openvpn
echo -e "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf
sysctl -p
rm EasyRSA-3.0.8.tgz
iptables -t nat -I POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE
iptables -t nat -I POSTROUTING -s 10.9.0.0/24 -o eth0 -j MASQUERADE
systemctl start openvpn@server-udp
systemctl start openvpn@server-tcp
systemctl enable openvpn@server-udp
systemctl enable openvpn@server-tcp
check_service "openvpn@server-udp"
check_service "openvpn@server-tcp"
sleep 2
ok "Successful configured openvpn"
sleep 2
newline
info "Configuring openvpn client"
sleep 2
mkdir /metavpn/openvpn
wget -O /metavpn/openvpn/client-udp.ovpn "${repo}files/openvpn/client-udp.ovpn"
wget -O /metavpn/openvpn/client-tcp.ovpn "${repo}files/openvpn/client-tcp.ovpn"
sleep 2
sed -i "s/remote xx 1194/remote $ip 1194/g" /metavpn/openvpn/client-udp.ovpn
echo -e "\n<ca>" >> /metavpn/openvpn/client-tcp.ovpn
cat "/etc/openvpn/key/ca.crt" >> /metavpn/openvpn/client-tcp.ovpn
echo -e "</ca>" >> /metavpn/openvpn/client-tcp.ovpn
echo -e "\n<ca>" >> /metavpn/openvpn/client-udp.ovpn
cat "/etc/openvpn/key/ca.crt" >> /metavpn/openvpn/client-udp.ovpn
echo -e "</ca>" >> /metavpn/openvpn/client-udp.ovpn
sleep 2
ok "Successful configured openvpn client"
sleep 3

clear
newline
info "Installing squid"
sleep 2
apt install squid -y
sleep 2
wget -O /etc/squid/squid.conf "${repo}files/squid.conf"
sed -i "s/xx/$domain/g" /etc/squid/squid.conf
sed -i "s/ip/$ip/g" /etc/squid/squid.conf
sleep 2
check_package "squid"
systemctl restart squid
check_service "squid"
sleep 3

clear
newline
info "Installing ohpserver"
sleep 2
apt install python -y
sleep 2
wget -O /usr/bin/ohpserver "${repo}files/ohpserver"
chmod +x /usr/bin/ohpserver
screen -AmdS ohp-dropbear ohpserver -port 3128 -proxy 127.0.0.1:8080 -tunnel 127.0.0.1:110
screen -AmdS ohp-openvpn ohpserver -port 8000 -proxy 127.0.0.1:8080 -tunnel 127.0.0.1:992
sleep 2
check_screen "ohp-dropbear"
check_screen "ohp-openvpn"
check_package "python"
ok "ohpserver is installed"
sleep 3

clear
newline
info "Installing badvpn udpgw"
sleep 2
wget -O badvpn.zip "${repo}files/badvpn.zip"
unzip badvpn.zip
mkdir badvpn-master/build-badvpn
cd badvpn-master/build-badvpn
cmake .. -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1
make install
cd
rm -rf badvpn-master
rm -r badvpn.zip
screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7300
sleep 2
check_screen "badvpn"
ok "badvpn udpgw is installed"
sleep 3

clear
newline
info "Installing xray"
sleep 2
rm -f /etc/apt/sources.list.d/nginx.list
apt install lsb-release gnupg2 -y
sleep 2
check_package "lsb-release"
check_package "gnupg2"
sleep 2
echo "deb http://nginx.org/packages/ubuntu $(lsb_release -cs) nginx" > /etc/apt/sources.list.d/nginx.list
curl -fsSL https://nginx.org/keys/nginx_signing.key | apt-key add -
apt update
sleep 2
apt install lsof libpcre3 libpcre3-dev zlib1g-dev libssl-dev jq -y
sleep 2
check_package "lsof"
check_package "libpcre3"
check_package "libpcre3-dev"
check_package "zlib1g-dev"
check_package "libssl-dev"
check_package "jq"
sleep 2
mkdir -p /usr/local/bin
curl -sL https://github.com/XTLS/Xray-install/raw/main/install-release.sh | bash -s -- install
echo $domain > /usr/local/etc/xray/domain
wget -O /usr/local/etc/xray/xtls.json "${repo}files/xray/xray_xtls.json"
wget -O /usr/local/etc/xray/ws.json "${repo}files/xray/xray_ws.json"
sed -i "s/xx/${domain}/g" /usr/local/etc/xray/ws.json
sleep 2
check_package "xray"
sleep 2
newline
info "Installing nginx"
sleep 2
apt install nginx -y
sleep 2
check_package "nginx"
sleep 2
newline
info "Configuring nginx"
sleep 2
rm -rf /etc/nginx/conf.d
mkdir -p /etc/nginx/conf.d
wget -O /etc/nginx/conf.d/${domain}.conf "${repo}files/xray/web.conf"
sed -i "s/xx/${domain}/g" /etc/nginx/conf.d/${domain}.conf
nginxConfig=$(systemctl status nginx | grep loaded | awk '{print $3}' | tr -d "(;")
sed -i "/^ExecStart=.*/i ExecStartPost=/bin/sleep 0.1" $nginxConfig
systemctl daemon-reload
systemctl restart nginx
systemctl enable nginx
rm -rf /var/www/html
mkdir -p /var/www/html/css
wget -O /var/www/html/index.html "${repo}files/web/index.html"
wget -O /var/www/html/css/style.css "${repo}files/web/style.css"
nginxUser=$(ps -eo pid,comm,euser,supgrp | grep nginx | tail -n 1 | awk '{print $2}')
nginxGroup=$(ps -eo pid,comm,euser,supgrp | grep nginx | tail -n 1 | awk '{print $3}')
chown -R ${nginxUser}:${nginxGroup} /var/www/html
find /var/www/html/ -type d -exec chmod 750 {} \;
find /var/www/html/ -type f -exec chmod 640 {} \;
sleep 2
newline
info "Configuring xray"
sleep 2
signedcert=$(xray tls cert -domain="$domain" -name="Meta VPN" -org="Meta VPN" -expire=87600h)
echo $signedcert | jq '.certificate[]' | sed 's/\"//g' | tee /usr/local/etc/xray/self_signed_cert.pem
echo $signedcert | jq '.key[]' | sed 's/\"//g' > /usr/local/etc/xray/self_signed_key.pem
openssl x509 -in /usr/local/etc/xray/self_signed_cert.pem -noout
chown -R nobody.nogroup /usr/local/etc/xray/self_signed_cert.pem
chown -R nobody.nogroup /usr/local/etc/xray/self_signed_key.pem
mkdir /metavpn/xray
touch /metavpn/xray/xray-clients.txt
curl -sL https://get.acme.sh | bash
"$HOME"/.acme.sh/acme.sh --set-default-ca --server letsencrypt
systemctl restart nginx
if "$HOME"/.acme.sh/acme.sh --issue -d "${domain}" --webroot "/var/www/html" -k ec-256 --force; then
	ok "SSL certificate generated"
	if "$HOME"/.acme.sh/acme.sh --installcert -d "${domain}" --fullchainpath /metavpn/xray/xray.crt --keypath /metavpn/xray/xray.key --reloadcmd "systemctl restart xray@xtls" --ecc --force; then
		ok "SSL certificate installed"
	fi
else
	error "SSL certificate install failed"
	exit 1
fi
chown -R nobody.nogroup /metavpn/xray/xray.crt
chown -R nobody.nogroup /metavpn/xray/xray.key
systemctl daemon-reload
systemctl restart nginx
systemctl restart xray@xtls
systemctl restart xray@ws
systemctl enable xray@xtls
systemctl enable xray@ws
check_service "nginx"
check_service "xray@xtls"
check_service "xray@ws"
(crontab -l;echo "0 * * * * echo '# Xray-XTLS access log (Script by Meta VPN)' > /var/log/xray/access-xtls.log") | crontab -
(crontab -l;echo "0 * * * * echo '# Xray-WS access log (Script by Meta VPN)' > /var/log/xray/access-ws.log") | crontab -
sleep 2
ok "Successful configured nginx"
ok "Successful configured xray"
sleep 3

clear
newline
info "Installing wireguard"
sleep 2
apt install wireguard resolvconf qrencode -y
sleep 2
check_package "wireguard"
check_package "resolvconf"
check_package "qrencode"
sleep 2
newline
info "Configuring wireguard"
sleep 2
server_priv_key=$(wg genkey)
server_pub_key=$(echo "${server_priv_key}" | wg pubkey)
echo -e "ip=${ip}
server_priv_key=${server_priv_key}
server_pub_key=${server_pub_key}" > /etc/wireguard/params
source /etc/wireguard/params
echo -e "[Interface]
Address = 10.66.66.1/24
ListenPort = 51820
PrivateKey = ${server_priv_key}
PostUp = sleep 1; iptables -A FORWARD -i eth0 -o wg0 -j ACCEPT; iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i eth0 -o wg0 -j ACCEPT; iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE" >> /etc/wireguard/wg0.conf
systemctl start wg-quick@wg0
systemctl enable wg-quick@wg0
mkdir /metavpn/wireguard
touch /metavpn/wireguard/wireguard-clients.txt
sleep 2
check_service "wg-quick@wg0"
ok "Successful configured wireguard"
sleep 3

clear
newline
info "Installing speedtest"
sleep 2
curl -s https://install.speedtest.net/app/cli/install.deb.sh | bash
apt install speedtest -y
sleep 2
check_package "speedtest"
sleep 2
newline
info "Installing fail2ban"
sleep 2
apt install fail2ban -y
sleep 2
check_service "fail2ban"
systemctl restart fail2ban
check_package "fail2ban"
sleep 2
newline
info "Installing ddos-deflate"
sleep 2
apt install dnsutils tcpdump dsniff grepcidr net-tools -y
sleep 2
check_package "dnsutils"
check_package "tcpdump"
check_package "dsniff"
check_package "grepcidr"
check_package "net-tools"
sleep 2
wget -O ddos.zip "${repo}files/ddos-deflate.zip"
unzip ddos.zip
cd ddos-deflate
chmod +x install.sh
./install.sh
cd
rm -rf ddos.zip ddos-deflate
sleep 2
check_service "ddos"
ok "ddos-deflate is installed"
sleep 3

clear
newline
info "Checking rc.local service"
sleep 2
systemctl status rc-local
if [[ 0 -ne $? ]]; then
	info "Installing rc.local" 
	sleep 2
	wget -O /etc/systemd/system/rc-local.service "${repo}files/rc-local.service"
	sleep 2
	newline
	info "Configuring rc.local"
	sleep 2
	wget -O /etc/rc.local "${repo}files/rc.local"
	chmod +x /etc/rc.local
	systemctl start rc-local
	systemctl enable rc-local 
	sleep 2
	check_service "rc-local"
else
	info "Configuring rc.local" 
	sleep 2
	wget -O /etc/rc.local "${repo}files/rc.local"
	systemctl start rc-local
	systemctl enable rc-local 
	sleep 2
	check_service "rc-local"
fi
sleep 2
ok "Successful configured rc.local"
sleep 2
newline
info "Saving rules setting"
sleep 2
systemctl stop wg-quick@wg0
iptables-save > /metavpn/iptables.rules
systemctl start wg-quick@wg0
sleep 2
ok "Rules setting saved"
sleep 3

clear
newline
info "Configuring menu"
sleep 2
wget -O /usr/bin/menu "${repo}files/menu/menu.sh"
wget -O /usr/bin/ovpn "${repo}files/menu/ovpn.sh"
wget -O /usr/bin/xray "${repo}files/menu/xray.sh"
wget -O /usr/bin/wireguard "${repo}files/menu/wireguard.sh"
wget -O /usr/bin/check "${repo}files/menu/check.sh"
wget -O /usr/bin/backup "${repo}files/menu/backup.sh"
wget -O /usr/bin/nench "${repo}files/nench.sh"
chmod +x /usr/bin/{menu,ovpn,xray,wireguard,check,backup,nench}
sleep 2
ok "Successful configured menu"
sleep 3

clear
newline
ok "Autoscript installation is finished"
sleep 2
newline
info "System reboot is required to complete installation"
info "Press enter to reboot system: \c"
read reboot
case $reboot in
*) 
  cat /dev/null > ~/.bash_history
  echo -e "clear
  cat /dev/null > ~/.bash_history
  history -c" >> ~/.bash_logout
  rm -f /root/install.sh
  reboot
esac
}

clear
newline
info "Autoscript Meta VPN"
info "Confirm to start installation (y/n)? \c"
read confirm
case $confirm in
y) 
  clear
  start_install
  ;;
n) 
  clear
  info "Installation cancelled"
  newline
  exit 1
  ;;
esac