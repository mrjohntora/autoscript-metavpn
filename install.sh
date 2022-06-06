#!/bin/bash

###################################
##  Auto-Script VPS by Meta VPN  ##
##             v 2.0             ##
##       Created by Iriszz       ##
##      [ www.metavpn.top ]      ##
###################################

# Initialize variables
PURPLE='\033[0;35m'
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'
repoDir='https://raw.githubusercontent.com/mrjohntora/autoscript-metavpn/main/'
netInt=$(ip link | awk -F: '$0 !~ "lo|vir|wl|^[^0-9]"{print $2;getline}' | head -n 1)

# Check services
checkRun() {
	if [[ "$(systemctl is-active $1)" == "active" ]]; then
		echo -e "${GREEN}Service '$1' is running.${NC}"
		sleep 1
	else
		echo -e "${RED}Service '$1' is not running.${NC}\n"
		exit 1
	fi
}
checkScreen() {
	if screen -ls | grep -qw $1; then
		echo -e "${GREEN}Service '$1' is running.${NC}"
		sleep 1
	else
		echo -e "${RED}Service '$1' is not running.${NC}\n"
		exit 1
	fi
}
checkInstall() {
	if [[ 0 -eq $? ]]; then
		echo -e "${GREEN}Package '$1' is installed.${NC}"
		sleep 1
	else
		echo -e "${RED}Package '$1' is not installed.${NC}\n"
		exit 1
	fi
}

clear

# Check environment
function os_check() {
	source '/etc/os-release'
	if [[ "${ID}" != "ubuntu" && $(echo "${VERSION_ID}" | cut -d '.' -f1) -lt 20 ]]; then
		echo -e "${RED}This script is only for Ubuntu 18 and above.${NC}\n"
		exit 1
	fi
}
echo -e "${PURPLE}[+] Checking environment ...${NC}"
sleep 1
if [[ $EUID -ne 0 ]]; then
	echo -e "${RED}This script must be run as root!${NC}\n"
	exit 1
fi
apt update > /dev/null 2>&1
apt install -y virt-what > /dev/null 2>&1
if ! [[ "$(virt-what)" == "kvm" || "$(virt-what)" == "hyperv" ]]; then
	echo -e "${RED}This script is only for KVM virtualization.${NC}\n"
	exit 1
fi
os_check

# Update packages
echo -e "${PURPLE}[+] Updating packages ...${NC}"
sleep 1
apt update > /dev/null 2>&1
apt upgrade -y > /dev/null 2>&1
apt autoremove -y > /dev/null 2>&1

# Install script dependencies
echo -e "${PURPLE}[+] Installing script dependencies ...${NC}"
apt install -y systemd curl wget curl screen cmake zip unzip vnstat tar openssl git uuid-runtime > /dev/null 2>&1
checkInstall "systemd curl wget curl screen cmake unzip vnstat tar openssl git uuid-runtime"

# Get domain
echo -e ""
read -p "Enter your domain name (www.metavpn.top) : " domain
domain_ip=$(ping "${domain}" -c 1 | sed '1{s/[^(]*(//;s/).*//;q}')
ip=$(wget -qO- ipv4.icanhazip.com)
echo -e "${PURPLE}\n[+] Checking domain name ...${NC}"
sleep 1
if [[ ${domain_ip} == "${ip}" ]]; then
	echo -e "${GREEN}IP matched with the server.${NC}"
	sleep 1
elif grep -qw "$domain" /etc/hosts; then
	echo -e "${GREEN}IP matched with hostname.${NC}"
else
	echo -e "${RED}IP does not match with the server. Make sure to point A record to your server.${NC}\n"
	exit 1
fi

# Optimize settings
echo -e "${PURPLE}[+] Optimizing settings ...${NC}"
sleep 1
sed -i '/^\*\ *soft\ *nofile\ *[[:digit:]]*/d' /etc/security/limits.conf
sed -i '/^\*\ *hard\ *nofile\ *[[:digit:]]*/d' /etc/security/limits.conf
echo -e "* soft nofile 65536
* hard nofile 65536" >> /etc/security/limits.conf
locale-gen en_US > /dev/null 2>&1

# Change timezone
echo -e "${PURPLE}[+] Changing timezone to Asia/Kuala_Lumpur (GMT +8) ...${NC}"
sleep 1
ln -sf /usr/share/zoneinfo/Asia/Kuala_Lumpur /etc/localtime

# Disable IPv6
echo -e "${PURPLE}[+] Disabling IPv6 ...${NC}"
sleep 1
sysctl -w net.ipv6.conf.all.disable_ipv6=1 > /dev/null 2>&1
sysctl -w net.ipv6.conf.default.disable_ipv6=1 > /dev/null 2>&1
sysctl -w net.ipv6.conf.lo.disable_ipv6=1 > /dev/null 2>&1
echo -e "net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1" >> /etc/sysctl.conf
sysctl -p > /dev/null 2>&1

# Reset iptables
echo -e "${PURPLE}[+] Resetting iptables ...${NC}"
sleep 1
apt install -y iptables-persistent
checkInstall iptables-persistent
ufw disable > /dev/null 2>&1
iptables-save | awk '/^[*]/ { print $1 } 
                     /^:[A-Z]+ [^-]/ { print $1 " ACCEPT" ; }
                     /COMMIT/ { print $0; }' | iptables-restore

# Configure Cron
if [ $(dpkg-query -W -f='${Status}' cron 2>/dev/null | grep -c "ok installed") -eq 0 ]; then
	echo -e "${PURPLE}[+] Installing cron ...${NC}"
	sleep 1
	apt install -y cron > /dev/null 2>&1
	checkInstall cron
fi
echo -e "${PURPLE}[+] Configuring cron ...${NC}"
sleep 1
mkdir /metavpn
wget -O /metavpn/cron.daily "${repoDir}files/cron.daily" > /dev/null 2>&1
chmod +x /metavpn/cron.daily
(crontab -l;echo "0 6 * * * /metavpn/cron.daily") | crontab -

# Configure SSH
echo -e "${PURPLE}[+] Configuring SSH ...${NC}"
sleep 1
echo "WELCOME TO META VPN" > /etc/issue.net
sed -i "s/#Banner none/Banner \/etc\/issue.net/g" /etc/ssh/sshd_config
mkdir /metavpn/ssh
touch /metavpn/ssh/ssh-clients.txt
systemctl restart ssh
checkRun ssh

# Install Dropbear
echo -e "${PURPLE}[+] Installing Dropbear ...${NC}"
sleep 1
apt install -y dropbear > /dev/null 2>&1
checkInstall dropbear
echo -e "${PURPLE}[+] Configuring Dropbear ...${NC}"
sleep 1
sed -i "s/NO_START=1/NO_START=0/g" /etc/default/dropbear
sed -i "s/DROPBEAR_PORT=22/DROPBEAR_PORT=110/g" /etc/default/dropbear
echo -e "/bin/false" >> /etc/shells
wget -O /etc/dropbear_issue.net "${repoDir}files/dropbear_issue.net" > /dev/null 2>&1
sed -i 's|DROPBEAR_BANNER=""|DROPBEAR_BANNER="/etc/dropbear_issue.net"|g' /etc/default/dropbear
systemctl restart dropbear
checkRun dropbear

# Install Stunnel
echo -e "${PURPLE}[+] Installing Stunnel ...${NC}"
sleep 1
apt install -y stunnel4 > /dev/null 2>&1
checkInstall stunnel4
echo -e "${PURPLE}[+] Configuring Stunnel ...${NC}"
sleep 1
sed -i "s/ENABLED=0/ENABLED=1/g" /etc/default/stunnel4
openssl req -new -newkey rsa:2048 -days 3650 -nodes -x509 -sha256 -subj "/CN=Iriszz/emailAddress=admin@metavpn.tk/O=Meta VPN/OU=Meta VPN/C=MY" -keyout /etc/stunnel/stunnel.pem -out /etc/stunnel/stunnel.pem > /dev/null 2>&1
wget -O /etc/stunnel/stunnel.conf "${repoDir}files/stunnel.conf" > /dev/null 2>&1
systemctl restart stunnel4
checkRun stunnel4

# Install OpenVPN
echo -e "${PURPLE}[+] Installing OpenVPN ...${NC}"
sleep 1
apt install -y openvpn > /dev/null 2>&1
checkInstall openvpn
echo -e "${PURPLE}[+] Configuring OpenVPN ...${NC}"
sleep 1
wget "${repoDir}files/openvpn/EasyRSA-3.0.8.tgz" > /dev/null 2>&1
tar xvf EasyRSA-3.0.8.tgz > /dev/null 2>&1
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
./easyrsa --batch init-pki > /dev/null 2>&1
./easyrsa --batch build-ca nopass > /dev/null 2>&1
./easyrsa gen-dh > /dev/null 2>&1
./easyrsa build-server-full server nopass > /dev/null 2>&1
cd
mkdir /etc/openvpn/key
cp /etc/openvpn/easy-rsa/pki/issued/server.crt /etc/openvpn/key/
cp /etc/openvpn/easy-rsa/pki/ca.crt /etc/openvpn/key/
cp /etc/openvpn/easy-rsa/pki/dh.pem /etc/openvpn/key/
cp /etc/openvpn/easy-rsa/pki/private/server.key /etc/openvpn/key/
wget -O /etc/openvpn/server-udp.conf "${repoDir}files/openvpn/server-udp.conf" > /dev/null 2>&1
wget -O /etc/openvpn/server-tcp.conf "${repoDir}files/openvpn/server-tcp.conf" > /dev/null 2>&1
sed -i "s/#AUTOSTART="all"/AUTOSTART="all"/g" /etc/default/openvpn
echo -e "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf
sysctl -p > /dev/null 2>&1
rm EasyRSA-3.0.8.tgz
iptables -t nat -I POSTROUTING -s 10.8.0.0/24 -o ${netInt} -j MASQUERADE
iptables -t nat -I POSTROUTING -s 10.9.0.0/24 -o ${netInt} -j MASQUERADE
systemctl start openvpn@server-udp
systemctl start openvpn@server-tcp
systemctl enable openvpn@server-udp > /dev/null 2>&1
systemctl enable openvpn@server-tcp > /dev/null 2>&1
checkRun openvpn@server-udp
checkRun openvpn@server-tcp

# Configure OpenVPN client configuration
echo -e "${PURPLE}[+] Configuring OpenVPN configuration ...${NC}"
sleep 1
mkdir /metavpn/openvpn
wget -O /metavpn/openvpn/client-udp.ovpn "${repoDir}files/openvpn/client-udp.ovpn" > /dev/null 2>&1
wget -O /metavpn/openvpn/client-tcp.ovpn "${repoDir}files/openvpn/client-tcp.ovpn" > /dev/null 2>&1
sed -i "s/xx/$ip/g" /metavpn/openvpn/client-udp.ovpn
#sed -i "s/xx/$ip/g" /metavpn/openvpn/client-tcp.ovpn
echo -e "\n<ca>" >> /metavpn/openvpn/client-tcp.ovpn
cat "/etc/openvpn/key/ca.crt" >> /metavpn/openvpn/client-tcp.ovpn
echo -e "</ca>" >> /metavpn/openvpn/client-tcp.ovpn
echo -e "\n<ca>" >> /metavpn/openvpn/client-udp.ovpn
cat "/etc/openvpn/key/ca.crt" >> /metavpn/openvpn/client-udp.ovpn
echo -e "</ca>" >> /metavpn/openvpn/client-udp.ovpn

# Install Squid
echo -e "${PURPLE}[+] Installing Squid ...${NC}"
sleep 1
apt install -y squid > /dev/null 2>&1
checkInstall squid
wget -O /etc/squid/squid.conf "${repoDir}files/squid.conf" > /dev/null 2>&1
sed -i "s/xx/$domain/g" /etc/squid/squid.conf
sed -i "s/ip/$ip/g" /etc/squid/squid.conf
systemctl restart squid
checkRun squid

# Install Open HTTP Puncher
echo -e "${PURPLE}[+] Installing OHP ...${NC}"
sleep 1
apt install -y python > /dev/null 2>&1
checkInstall python
wget -O /usr/bin/ohpserver "${repoDir}files/ohpserver" > /dev/null 2>&1
chmod +x /usr/bin/ohpserver
screen -AmdS ohp-dropbear ohpserver -port 3128 -proxy 127.0.0.1:8080 -tunnel 127.0.0.1:110
screen -AmdS ohp-openvpn ohpserver -port 8000 -proxy 127.0.0.1:8080 -tunnel 127.0.0.1:992
checkScreen ohp-dropbear
checkScreen ohp-openvpn

# Install BadVPN UDPGw
echo -e "${PURPLE}[+] Installing BadVPN UDPGw ...${NC}"
sleep 1
wget -O badvpn.zip "${repoDir}files/badvpn.zip" > /dev/null 2>&1
unzip badvpn.zip > /dev/null 2>&1
mkdir badvpn-master/build-badvpn
cd badvpn-master/build-badvpn
cmake .. -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1 > /dev/null 2>&1
make install > /dev/null 2>&1
cd
rm -rf badvpn-master
rm -f badvpn.zip
screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7300
checkScreen badvpn

# Install Xray
echo -e "${PURPLE}[+] Installing Xray ...${NC}"
sleep 1
rm -f /etc/apt/sources.list.d/nginx.list
apt install -y lsb-release gnupg2 > /dev/null 2>&1
checkInstall lsb-release gnupg2
echo "deb http://nginx.org/packages/ubuntu $(lsb_release -cs) nginx" > /etc/apt/sources.list.d/nginx.list
curl -fsSL https://nginx.org/keys/nginx_signing.key | apt-key add - > /dev/null 2>&1
apt update > /dev/null 2>&1
apt install -y lsof libpcre3 libpcre3-dev zlib1g-dev libssl-dev jq > /dev/null 2>&1
checkInstall "lsof libpcre3 libpcre3-dev zlib1g-dev libssl-dev jq"
mkdir -p /usr/local/bin
curl -sL https://github.com/XTLS/Xray-install/raw/main/install-release.sh | bash -s -- install > /dev/null 2>&1
checkInstall xray
echo $domain > /usr/local/etc/xray/domain
wget -O /usr/local/etc/xray/xtls.json "${repoDir}files/xray/xray_xtls.json" > /dev/null 2>&1
wget -O /usr/local/etc/xray/ws.json "${repoDir}files/xray/xray_ws.json" > /dev/null 2>&1
sed -i "s/xx/${domain}/g" /usr/local/etc/xray/ws.json
echo -e "${PURPLE}[+] Installing Nginx ...${NC}"
sleep 1
if ! command -v nginx > /dev/null 2>&1; then
	apt install -y nginx > /dev/null 2>&1
fi
checkInstall nginx
echo -e "${PURPLE}[+] Configuring Nginx ...${NC}"
sleep 1
rm -rf /etc/nginx/conf.d
mkdir -p /etc/nginx/conf.d
wget -O /etc/nginx/conf.d/${domain}.conf "${repoDir}files/xray/web.conf" > /dev/null 2>&1
sed -i "s/xx/${domain}/g" /etc/nginx/conf.d/${domain}.conf
nginxConfig=$(systemctl status nginx | grep loaded | awk '{print $3}' | tr -d "(;")
sed -i "/^ExecStart=.*/i ExecStartPost=/bin/sleep 0.1" $nginxConfig
systemctl daemon-reload
systemctl restart nginx
systemctl enable nginx > /dev/null 2>&1
rm -rf /var/www/html
mkdir -p /var/www/html/css
wget -O /var/www/html/index.html "${repoDir}files/web/index.html" > /dev/null 2>&1
wget -O /var/www/html/css/style.css "${repoDir}files/web/style.css" > /dev/null 2>&1
nginxUser=$(ps -eo pid,comm,euser,supgrp | grep nginx | tail -n 1 | awk '{print $2}')
nginxGroup=$(ps -eo pid,comm,euser,supgrp | grep nginx | tail -n 1 | awk '{print $3}')
chown -R root:www-data /var/www/html
chown -R $USER:$USER /var/www/html
find /var/www/html/ -type d -exec chmod 750 {} \;
find /var/www/html/ -type f -exec chmod 640 {} \;
echo -e "${PURPLE}[+] Configuring Xray ...${NC}"
sleep 1
signedcert=$(xray tls cert -domain="$domain" -name="Iriszz" -org="Meta VPN" -expire=87600h)
echo $signedcert | jq '.certificate[]' | sed 's/\"//g' | tee /usr/local/etc/xray/self_signed_cert.pem > /dev/null 2>&1
echo $signedcert | jq '.key[]' | sed 's/\"//g' > /usr/local/etc/xray/self_signed_key.pem
openssl x509 -in /usr/local/etc/xray/self_signed_cert.pem -noout
chown -R nobody.nogroup /usr/local/etc/xray/self_signed_cert.pem
chown -R nobody.nogroup /usr/local/etc/xray/self_signed_key.pem
mkdir /metavpn/xray
touch /metavpn/xray/xray-clients.txt
curl -sL https://get.acme.sh | bash > /dev/null 2>&1
"$HOME"/.acme.sh/acme.sh --set-default-ca --server letsencrypt > /dev/null 2>&1
systemctl restart nginx
if "$HOME"/.acme.sh/acme.sh --issue -d "${domain}" --webroot "/var/www/html" -k ec-256 --force > /dev/null 2>&1; then
	echo -e "SSL certificate generated."
	sleep 1
	if "$HOME"/.acme.sh/acme.sh --installcert -d "${domain}" --fullchainpath /metavpn/xray/xray.crt --keypath /metavpn/xray/xray.key --reloadcmd "systemctl restart xray@xtls" --ecc --force > /dev/null 2>&1; then
		echo -e "SSL certificate installed."
		sleep 1
	fi
else
	echo -e "${RED}Error installing/configuring SSL certificate.${NC}\n"
	exit 1
fi
chown -R nobody.nogroup /metavpn/xray/xray.crt
chown -R nobody.nogroup /metavpn/xray/xray.key
systemctl daemon-reload
systemctl restart nginx
systemctl restart xray@xtls
systemctl restart xray@ws
systemctl enable xray@xtls > /dev/null 2>&1
systemctl enable xray@ws > /dev/null 2>&1
checkRun nginx
checkRun xray@xtls
checkRun xray@ws
(crontab -l;echo "0 * * * * echo '# Xray-XTLS access log (Script by Meta VPN)' > /var/log/xray/access-xtls.log") | crontab -
(crontab -l;echo "0 * * * * echo '# Xray-WS access log (Script by Meta VPN)' > /var/log/xray/access-ws.log") | crontab -

# Install WireGuard
echo -e "${PURPLE}[+] Installing WireGuard ...${NC}"
sleep 1
apt install -y wireguard resolvconf qrencode > /dev/null 2>&1
checkInstall "wireguard resolvconf qrencode"
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
PostUp = sleep 1; iptables -A FORWARD -i ${netInt} -o wg0 -j ACCEPT; iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o ${netInt} -j MASQUERADE
PostDown = iptables -D FORWARD -i ${netInt} -o wg0 -j ACCEPT; iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o ${netInt} -j MASQUERADE" >> /etc/wireguard/wg0.conf
systemctl start wg-quick@wg0
systemctl enable wg-quick@wg0 > /dev/null 2>&1
mkdir /metavpn/wireguard
touch /metavpn/wireguard/wireguard-clients.txt
checkRun wg-quick@wg0

# Install Speedtest CLI
echo -e "${PURPLE}[+] Installing Speedtest CLI ...${NC}"
sleep 1
curl -s https://install.speedtest.net/app/cli/install.deb.sh | bash > /dev/null 2>&1
apt install -y speedtest > /dev/null 2>&1
checkInstall speedtest

# Install fail2ban
echo -e "${PURPLE}[+] Installing Fail2Ban ...${NC}"
sleep 1
apt install -y fail2ban > /dev/null 2>&1
checkInstall fail2ban
systemctl restart fail2ban
checkRun fail2ban

# Install DDoS Deflate
echo -e "${PURPLE}[+] Installing DDoS Deflate ...${NC}"
sleep 1
apt install -y dnsutils tcpdump dsniff grepcidr net-tools > /dev/null 2>&1
checkInstall "dnsutils tcpdump dsniff grepcidr net-tools"
wget -O ddos.zip "${repoDir}files/ddos-deflate.zip" > /dev/null 2>&1
unzip ddos.zip > /dev/null 2>&1
cd ddos-deflate
chmod +x install.sh
./install.sh > /dev/null 2>&1
cd
rm -rf ddos.zip ddos-deflate
checkRun ddos

# Configure rc.local
echo -e "${PURPLE}[+] Checking for rc.local service ...${NC}"
sleep 1
systemctl status rc-local > /dev/null 2>&1
if [[ 0 -ne $? ]]; then
	echo -e "${PURPLE}[+] rc.local is not installed, installing rc.local ...${NC}"
	sleep 1
	wget -O /etc/systemd/system/rc-local.service "${repoDir}files/rc-local.service" > /dev/null 2>&1
	echo -e "${PURPLE}[+] Configuring rc.local ...${NC}"
	sleep 1
	wget -O /etc/rc.local "${repoDir}files/rc.local" > /dev/null 2>&1
	chmod +x /etc/rc.local
	systemctl start rc-local
	systemctl enable rc-local > /dev/null 2>&1
	checkRun rc-local
else
	echo -e "${PURPLE}[+] rc.local is enabled, configuring rc.local ...${NC}"
	sleep 1
	wget -O /etc/rc.local "${repoDir}files/rc.local" > /dev/null 2>&1
	systemctl start rc-local
	systemctl enable rc-local > /dev/null 2>&1
	checkRun rc-local
fi

# Block Torrent (iptables)
#echo -e "${PURPLE}[+] Configuring iptables to block Torrent ...${NC}"
#sleep 1
#iptables -A FORWARD -m string --algo bm --string "BitTorrent" -j DROP
#iptables -A FORWARD -m string --algo bm --string "BitTorrent protocol" -j DROP
#iptables -A FORWARD -m string --algo bm --string "peer_id=" -j DROP
#iptables -A FORWARD -m string --algo bm --string ".torrent" -j DROP
#iptables -A FORWARD -m string --algo bm --string "announce.php?passkey=" -j DROP
#iptables -A FORWARD -m string --algo bm --string "torrent" -j DROP
#iptables -A FORWARD -m string --algo bm --string "announce" -j DROP
#iptables -A FORWARD -m string --algo bm --string "info_hash" -j DROP

# Save iptables
echo -e "${PURPLE}[+] Saving iptables ...${NC}"
sleep 1
systemctl stop wg-quick@wg0
iptables-save > /metavpn/iptables.rules
systemctl start wg-quick@wg0

# Configure Google Drive backup
#echo -e "${PURPLE}[+] Configuring Google Drive backup ...${NC}"
#sleep 1
#apt install golang -y > /dev/null 2>&1
#go get github.com/prasmussen/gdrive
#checkInstall gdrive
#cp /root/go/bin/gdrive /usr/bin/
#chmod +x /usr/bin/gdrive
#echo -e ""
#gdrive about
#echo -e ""

# Configure menu
echo -e "${PURPLE}[+] Configuring menu ...${NC}"
sleep 1
wget -O /usr/bin/menu "${repoDir}files/menu/menu.sh" > /dev/null 2>&1
wget -O /usr/bin/ovpn "${repoDir}files/menu/ovpn.sh" > /dev/null 2>&1
wget -O /usr/bin/xray "${repoDir}files/menu/xray.sh" > /dev/null 2>&1
wget -O /usr/bin/wireguard "${repoDir}files/menu/wireguard.sh" > /dev/null 2>&1
wget -O /usr/bin/check "${repoDir}files/menu/check.sh" > /dev/null 2>&1
wget -O /usr/bin/nench "${repoDir}files/menu/nench.sh" > /dev/null 2>&1
chmod +x /usr/bin/{menu,ovpn,xray,wireguard,check,nench}

# Cleanup and reboot
rm -f /root/install.sh
echo -e ""
echo -e "${GREEN}Script executed succesfully.${NC}"
echo -e ""
read -n 1 -r -s -p $"Press enter to reboot >> "
echo -e "\n"
cat /dev/null > ~/.bash_history
echo -e "clear
cat /dev/null > ~/.bash_history
history -c" >> ~/.bash_logout
reboot
