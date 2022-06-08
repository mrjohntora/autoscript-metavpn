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
OK="${G}[OK]${N}"
ERROR="${R}[ERROR]${N}"
INFO="${C}[+]${N}"

ok() {
  echo -e "${OK} ${G}$1${N}"
}

error() {
  echo -e "${ERROR} ${R}$1${N}"
}

info() {
  echo -e "${INFO} ${B}$1${N}"
}

newline() {
  echo -e ""
}

check_run() {
	if [[ "$(systemctl is-active $1)" == "active" ]]; then
		ok "$1 is running"
		sleep 1
	else
		error "$1 is not running"
		newline
		exit 1
	fi
}

check_screen() {
	if screen -ls | grep -qw $1; then
		ok "$1 is running"
		sleep 1
	else
		error "$1 is not running"
		newline
		exit 1
	fi
}

check_install() {
	if [[ 0 -eq $? ]]; then
		ok "$1 is installed"
		sleep 1
	else
		error "$1 is not installed"
		newline
		exit 1
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
    error "Ubuntu 20.04 or higher is required to use this autoscript"
    exit 1
  elif [[ "$os" == "debian" && "$os_version" -lt 10 ]]; then
    error "Debian 10 or higher is required to use this autoscript"
    exit 1
  fi
}

repo='https://raw.githubusercontent.com/mrjohntora/autoscript-metavpn/main/'
netinfo=$(ip link | awk -F: '$0 !~ "lo|vir|wl|^[^0-9]"{print $2;getline}' | head -n 1)
localhost=$(hostname -s)
hostname=$(hostname -d)

clear
newline 
info "Checking system requirements"
sleep 1
check_system
if [[ "$EUID" -ne 0 ]]; then
  error "This autoscript needs to be run with root privileges"
  newline
  exit 1
fi
sleep 1
ok "System meets operational requirements"
newline
sleep 2

clear
newline
info "Installing package update"
sleep 1
apt update && apt upgrade -y
sleep 1
ok "Package updated successfully"
newline
sleep 2

clear
newline
info "Installing package dependency"
sleep 1
apt install systemd curl wget screen cmake zip unzip vnstat tar openssl git uuid socat -y
sleep 1
check_install curl
sleep 1
check_install wget
sleep 1
check_install screen
sleep 1
check_install cmake
sleep 1
check_install vnstat
sleep 1
check_install openssl
sleep 1
check_install git
sleep 1
check_install uuid
sleep 1
check_install socat
sleep 1
ok "Package dependency installed successfully"
newline
sleep 2

clear
newline
echo -e "${INFO} ${B}Enter a valid domain:${N} \c"
read domain
sleep 1
info "Checking domain"
sleep 1
domain_ip=$(ping "${domain}" -c 1 | sed '1{s/[^(]*(//;s/).*//;q}')
ip=$(wget -qO- ipv4.icanhazip.com)
if [[ ${domain_ip} == "${ip}" ]]; then
	ok "Domain IP matches the public IP"
else
	error "Domain IP does not match the public IP"
	newline
	exit 1
fi
newline
sleep 2

clear
newline
info "Optimizing system"
sleep 1
sed -i '/^\*\ *soft\ *nofile\ *[[:digit:]]*/d' /etc/security/limits.conf
sed -i '/^\*\ *hard\ *nofile\ *[[:digit:]]*/d' /etc/security/limits.conf
echo -e "* soft nofile 65536
* hard nofile 65536" >> /etc/security/limits.conf
locale-gen en_US
sleep 1
ok "System optimized successfully"
newline
sleep 2

clear
newline
info "Change local timezone"
sleep 1
ln -sf /usr/share/zoneinfo/Asia/Kuala_Lumpur /etc/localtime
if [[ "$os" == "ubuntu" ]]; then
  systemctl start systemd-timesyncd
elif [[ "$os" == "debian" ]]; then
  apt purge ntp -y
  systemctl start systemd-timesyncd 
fi
sleep 1
ok "Timezone changed successfully"
newline
sleep 2

clear
newline
info "Disabling IPv6 setting"
sleep 1
sysctl -w net.ipv6.conf.all.disable_ipv6=1
sysctl -w net.ipv6.conf.default.disable_ipv6=1
sysctl -w net.ipv6.conf.lo.disable_ipv6=1
echo -e "net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1" >> /etc/sysctl.conf
sysctl -p
sleep 1
ok "IPv6 disabled successfully"
newline
sleep 2

clear
newline
info "Reset Iptables setting"
sleep 1
apt install iptables-persistent -y
check_install iptables-persistent
ufw disable
iptables-save | awk '/^[*]/ { print $1 } 
                     /^:[A-Z]+ [^-]/ { print $1 " ACCEPT" ; }
                     /COMMIT/ { print $0; }' | iptables-restore
sleep 1
ok "Iptables setting reset successfully"
newline
sleep 2

clear
newline
info "Installing Cron"
sleep 1
apt install cron -y
check_install cron
sleep 1
newline
info "Configuring Cron"
sleep 1
mkdir /metavpn
wget -O /metavpn/cron.daily "${repo}files/cron.daily"
chmod +x /metavpn/cron.daily
(crontab -l;echo "0 6 * * * /metavpn/cron.daily") | crontab -
sleep 1
ok "Cron configured successfully"
newline
sleep 2

clear
newline
info "Configuring SSH"
sleep 1
echo "WELCOME TO META VPN" > /etc/issue.net
sed -i "s/#Banner none/Banner \/etc\/issue.net/g" /etc/ssh/sshd_config
mkdir /metavpn/ssh
touch /metavpn/ssh/ssh-clients.txt
systemctl restart ssh
check_run ssh
sleep 1
ok "SSH Configured successfully"
newline
sleep 2

clear
newline
info "Installing Dropbear"
sleep 1
apt install dropbear -y
check_install dropbear
sleep 1
newline
info "Configuring Dropbear"
sleep 1
sed -i "s/NO_START=1/NO_START=0/g" /etc/default/dropbear
sed -i "s/DROPBEAR_PORT=22/DROPBEAR_PORT=110/g" /etc/default/dropbear
echo -e "/bin/false" >> /etc/shells
wget -O /etc/dropbear_issue.net "${repo}files/dropbear_issue.net"
sed -i 's|DROPBEAR_BANNER=""|DROPBEAR_BANNER="/etc/dropbear_issue.net"|g' /etc/default/dropbear
systemctl restart dropbear
check_run dropbear
sleep 1
ok "Dropbear configured successfully"
newline
sleep 2

clear
newline
info "Installing Stunnel"
sleep 1
apt install stunnel4 -y
check_install stunnel4
sleep 1
newline
info "Configuring Stunnel"
sleep 1
sed -i "s/ENABLED=0/ENABLED=1/g" /etc/default/stunnel4
openssl req -new -newkey rsa:2048 -days 3650 -nodes -x509 -sha256 -subj "/CN=Meta VPN/emailAddress=admin@metavpn.tk/O=DigitalOcean/OU=Meta VPN/C=MY" -keyout /etc/stunnel/stunnel.pem -out /etc/stunnel/stunnel.pem
wget -O /etc/stunnel/stunnel.conf "${repo}files/stunnel.conf"
systemctl restart stunnel4
check_run stunnel4
sleep 1
ok "Stunnel configured successfully"
newline
sleep 2

clear
newline
info "Installing OpenVPN"
sleep 1
apt install openvpn -y
check_install openvpn
sleep 1
newline
info "Configuring OpenVPN"
sleep 1
wget "${repo}files/openvpn/EasyRSA-3.0.8.tgz"
tar xvf EasyRSA-3.0.8.tgz
mv EasyRSA-3.0.8 /etc/openvpn/easy-rsa
cp /etc/openvpn/easy-rsa/vars.example /etc/openvpn/easy-rsa/vars
sed -i 's/#set_var EASYRSA_REQ_COUNTRY\t"US"/set_var EASYRSA_REQ_COUNTRY\t"MY"/g' /etc/openvpn/easy-rsa/vars
sed -i 's/#set_var EASYRSA_REQ_PROVINCE\t"California"/set_var EASYRSA_REQ_PROVINCE\t"Wilayah Persekutuan"/g' /etc/openvpn/easy-rsa/vars
sed -i 's/#set_var EASYRSA_REQ_CITY\t"San Francisco"/set_var EASYRSA_REQ_CITY\t"Kuala Lumpur"/g' /etc/openvpn/easy-rsa/vars
sed -i 's/#set_var EASYRSA_REQ_ORG\t"Copyleft Certificate Co"/set_var EASYRSA_REQ_ORG\t\t"DigitalOcean"/g' /etc/openvpn/easy-rsa/vars
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
iptables -t nat -I POSTROUTING -s 10.8.0.0/24 -o ${netinfo} -j MASQUERADE
iptables -t nat -I POSTROUTING -s 10.9.0.0/24 -o ${netinfo} -j MASQUERADE
systemctl start openvpn@server-udp
systemctl start openvpn@server-tcp
systemctl enable openvpn@server-udp
systemctl enable openvpn@server-tcp
#check_run openvpn@server-udp
#check_run openvpn@server-tcp
sleep 1
newline
info "Configuring OpenVPN client"
sleep 1
mkdir /metavpn/openvpn
wget -O /metavpn/openvpn/client-udp.ovpn-script-script "${repo}files/openvpn/client-udp.ovpn-script-script"
wget -O /metavpn/openvpn/client-tcp.ovpn-script-script "${repo}files/openvpn/client-tcp.ovpn-script-script"
sed -i "s/xx/$ip/g" /metavpn/openvpn/client-udp.ovpn-script-script
echo -e "\n<ca>" >> /metavpn/openvpn/client-tcp.ovpn-script-script
cat "/etc/openvpn/key/ca.crt" >> /metavpn/openvpn/client-tcp.ovpn-script-script
echo -e "</ca>" >> /metavpn/openvpn/client-tcp.ovpn-script-script
echo -e "\n<ca>" >> /metavpn/openvpn/client-udp.ovpn-script-script
cat "/etc/openvpn/key/ca.crt" >> /metavpn/openvpn/client-udp.ovpn-script-script
echo -e "</ca>" >> /metavpn/openvpn/client-udp.ovpn-script-script
sleep 1
ok "OpenVPN client configured successfully"
newline
sleep 2

clear
newline
info "Installing Squid"
sleep 1
apt install squid -y
check_install squid
wget -O /etc/squid/squid.conf "${repo}files/squid.conf"
sed -i "s/xx/$domain/g" /etc/squid/squid.conf
sed -i "s/ip/$ip/g" /etc/squid/squid.conf
systemctl restart squid
check_run squid
sleep 1
ok "Squid installed successfully"
newline
sleep 2

clear
newline
info "Installing OHP Server"
sleep 1
apt install python -y
check_install python
wget -O /usr/bin/ohpserver "${repo}files/ohpserver"
chmod +x /usr/bin/ohpserver
screen -AmdS ohp-dropbear ohpserver -port 3128 -proxy 127.0.0.1:8080 -tunnel 127.0.0.1:110
screen -AmdS ohp-openvpn ohpserver -port 8000 -proxy 127.0.0.1:8080 -tunnel 127.0.0.1:992
check_screen ohp-dropbear
check_screen ohp-openvpn
sleep 1
ok "OHP Server installed successfully"
newline
sleep 2

clear
newline
info "Installing BadVPN UDPGW"
sleep 1
wget -O badvpn.zip "${repo}files/badvpn.zip"
unzip badvpn.zip
mkdir badvpn-master/build-badvpn
cd badvpn-master/build-badvpn
cmake .. -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1
make install
cd
rm -rf badvpn-master
rm -f badvpn.zip
screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7300
check_screen badvpn
sleep 1
ok "BadVPN UDPGW installed successfully"
newline
sleep 2

clear
newline
info "Installing Xray"
sleep 1
rm -f /etc/apt/sources.list.d/nginx.list
apt install lsb-release gnupg2 -y
check_install lsb-release gnupg2
echo "deb http://nginx.org/packages/ubuntu $(lsb_release -cs) nginx" > /etc/apt/sources.list.d/nginx.list
curl -fsSL https://nginx.org/keys/nginx_signing.key | apt-key add -
apt update
apt install lsof libpcre3 libpcre3-dev zlib1g-dev libssl-dev jq -y
check_install lsof
sleep 1
check_install libpcre3
sleep 1
check_install libpcre3-dev
sleep 1
check_install zlib1g-dev
sleep 1
check_install libssl-dev
sleep 1
check_install jq
sleep 1
mkdir -p /usr/local/bin
curl -sL https://github.com/XTLS/Xray-install/raw/main/install-release.sh | bash -s -- install
check_install xray
echo $domain > /usr/local/etc/xray/domain
wget -O /usr/local/etc/xray/xtls.json "${repo}files/xray/xray_xtls.json"
wget -O /usr/local/etc/xray/ws.json "${repo}files/xray/xray_ws.json"
sed -i "s/xx/${domain}/g" /usr/local/etc/xray/ws.json
sleep 1
ok "Xray installed successfully"
sleep 2

clear
newline
info "Installing Nginx"
sleep 1
if ! command -v nginx > /dev/null 2>&1; then
	apt install nginx -y
fi
check_install nginx
sleep 1
newline
info "Configuring Nginx"
sleep 1
rm -rf /etc/nginx/conf.d
mkdir -p /etc/nginx/conf.d
wget -O /etc/nginx/conf.d/${domain}.conf "${repo}files/xray/web.conf"
sed -i "s/xx/${domain}/g" /etc/nginx/conf.d/${domain}.conf
nginxConfig=$(systemctl status nginx | grep loaded | awk '{print $3}' | tr -d "(;")
sed -i "/^ExecStart=.*/i ExecStartPost=/bin/sleep 0.1" $nginxConfig
systemctl daemon-reload
systemctl restart nginx
systemctl enable nginx > /dev/null 2>&1
rm -rf /var/www/html
mkdir -p /var/www/html
wget -O /var/www/html/index.html "${repo}files/web/index.html"
mkdir -p /var/www/html/css
wget -O /var/www/html/css/style.css "${repo}files/web/style.css"
nginxUser=$(ps -eo pid,comm,euser,supgrp | grep nginx | tail -n 1 | awk '{print $2}')
nginxGroup=$(ps -eo pid,comm,euser,supgrp | grep nginx | tail -n 1 | awk '{print $3}')
chown -R root:www-data /var/www/html
chown -R nobody:nogroup /var/www/html
chown -R $USER:$USER /var/www/html
find /var/www/html/ -type d -exec chmod 750 {} \;
find /var/www/html/ -type f -exec chmod 640 {} \;
sleep 1
ok "Nginx configured successfully"
newline
sleep 2

clear
newline
info "Configuring Xray"
sleep 1
signedcert=$(xray tls cert -domain="$domain" -name="Meta VPN" -org="DigitalOcean" -expire=87600h)
echo $signedcert | jq '.certificate[]' | sed 's/\"//g' | tee /usr/local/etc/xray/self_signed_cert.pem > /dev/null 2>&1
echo $signedcert | jq '.key[]' | sed 's/\"//g' > /usr/local/etc/xray/self_signed_key.pem
openssl x509 -in /usr/local/etc/xray/self_signed_cert.pem -noout
chown -R nobody.nogroup /usr/local/etc/xray/self_signed_cert.pem
chown -R nobody.nogroup /usr/local/etc/xray/self_signed_key.pem
chown -R nobody:nogroup /usr/local/etc/xray/self_signed_cert.pem
chown -R nobody:nogroup /usr/local/etc/xray/self_signed_key.pem
mkdir /metavpn/xray
touch /metavpn/xray/xray-clients.txt
curl -sL https://get.acme.sh | bash
"$HOME"/.acme.sh/acme.sh --set-default-ca --server letsencrypt
systemctl restart nginx
if "$HOME"/.acme.sh/acme.sh --issue -d "${domain}" --webroot "/var/www/html" -k ec-256 --force > /dev/null 2>&1; then 
  ok "SSL certificate generated successfully"
	sleep 1
	if "$HOME"/.acme.sh/acme.sh --installcert -d "${domain}" --fullchainpath /metavpn/xray/xray.crt --keypath /metavpn/xray/xray.key --reloadcmd "systemctl restart xray@xtls" --ecc --force > /dev/null 2>&1; then
		ok "SSL certificate installed successfully"
		sleep 1
	fi
else
	error "SSL certificate is not generated and installed"
	sleep 1
fi
chown -R nobody.nogroup /metavpn/xray/xray.crt
chown -R nobody.nogroup /metavpn/xray/xray.key
chown -R nobody:nogroup /metavpn/xray/xray.crt
chown -R nobody:nogroup /metavpn/xray/xray.key
systemctl daemon-reload
systemctl restart nginx
systemctl restart xray@xtls
systemctl restart xray@ws
systemctl enable xray@xtls
systemctl enable xray@ws
check_run nginx
check_run xray@xtls
check_run xray@ws
(crontab -l;echo "0 * * * * echo '# Xray-XTLS access log (Script by Meta VPN)' > /var/log/xray/access-xtls.log") | crontab -
(crontab -l;echo "0 * * * * echo '# Xray-WS access log (Script by Meta VPN)' > /var/log/xray/access-ws.log") | crontab -
sleep 1
ok "Xray configured successfully"
newline
sleep 2

clear
newline
info "Installing WireGuard"
sleep 1
apt install wireguard resolvconf qrencode -y
check_install wireguard
sleep 1
check_install resolvconf
sleep 1
check_install qrencode
sleep 1
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
PostUp = sleep 1; iptables -A FORWARD -i ${netinfo} -o wg0 -j ACCEPT; iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o ${netinfo} -j MASQUERADE
PostDown = iptables -D FORWARD -i ${netinfo} -o wg0 -j ACCEPT; iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o ${netinfo} -j MASQUERADE" >> /etc/wireguard/wg0.conf
systemctl start wg-quick@wg0
systemctl enable wg-quick@wg0
mkdir /metavpn/wireguard
touch /metavpn/wireguard/wireguard-clients.txt
systemctl stop wg-quick@wg0
iptables-save > /metavpn/iptables.rules
systemctl start wg-quick@wg0
check_run wg-quick@wg0
sleep 1
ok "WireGuard installed successfully"
newline
sleep 2

clear
newline
info "Installing Speedtest"
sleep 1
curl -s https://install.speedtest.net/app/cli/install.deb.sh
apt install speedtest -y
check_install speedtest
sleep 1
ok "Speedtest installed successfully"
newline
sleep 2

clear
newline
info "Installing Fail2Ban"
sleep 1
apt install fail2ban -y
check_install fail2ban
systemctl restart fail2ban
check_run fail2ban
sleep 1
ok "Fail2Ban installed successfully"
newline
sleep 2

clear
newline
info "Installing DDOS Deflate"
sleep 1
apt install dnsutils tcpdump dsniff grepcidr net-tools -y
check_install dnsutils
sleep 1
check_install tcpdump
sleep 1
check_install dsniff
sleep 1
check_install grepcidr
sleep 1
check_install net-tools
sleep 1
wget -O ddos.zip "${repo}files/ddos-deflate.zip"
unzip ddos.zip
cd ddos-deflate
chmod +x install.sh
./install.sh
cd
rm -rf ddos.zip ddos-deflate
check_run ddos
sleep 1
ok "DDOS Deflate installed successfully"
newline
sleep 2

clear
newline
info "Checking rc.local service"
sleep 1
systemctl status rc-local
if [[ 0 -ne $? ]]; then
	info "Installing rc.local"
	sleep 1
	wget -O /etc/systemd/system/rc-local.service "${repo}files/rc-local.service"
	sleep 1
	newline 
	info "Configuring rc.local"
	sleep 1
	wget -O /etc/rc.local "${repo}files/rc.local"
	chmod +x /etc/rc.local
	systemctl start rc-local
	systemctl enable rc-local
	check_run rc-local
else
	info "Configuring rc.local"
	sleep 1
	wget -O /etc/rc.local "${repo}files/rc.local"
	systemctl start rc-local
	systemctl enable rc-local
	check_run rc-local
fi
sleep 1
ok "rc.local configured successfully"
newline
sleep 2

clear
newline
info "Setup menu option script"
sleep 1
wget -O /usr/bin/menu "${repo}files/menu/menu.sh"
wget -O /usr/bin/ovpn-script "${repo}files/menu/ovpn-script.sh"
wget -O /usr/bin/xray-script "${repo}files/menu/xray-script.sh"
wget -O /usr/bin/wg-script "${repo}files/menu/wg-script.sh"
wget -O /usr/bin/check-script "${repo}files/menu/check-script.sh"
wget -O /usr/bin/nench-script "${repo}files/menu/nench-script.sh"
chmod +x /usr/bin/{menu,ovpn-script-script,xray-script,wg-script,check-script,nench-script}
sleep 1
ok "Menu setup successfully"
newline
sleep 2

clear
newline
ok "Autoscript installation completed"
ok "Press enter to reboot system \c"
read reply
case $reply in
*)
  rm -f /root/install.sh 
  cat /dev/null > ~/.bash_history 
  echo -e "clear 
  cat /dev/null > ~/.bash_history 
  history -c" >> ~/.bash_logout 
  reboot 
  ;;
esac
