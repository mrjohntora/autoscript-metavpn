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

goback() {
  echo -e "Enter any keys to go back \c" 
	read back 
	case $back in 
	  *)
	    wireguard
      ;;
	esac
}

source /etc/wireguard/params

add_user() {
	endpoint="${ip}:51820"

	clear
	newline
	echo -e "Add WireGuard User"
	echo -e "=================="
	echo -e " Username: \c"
	read user
	if grep -qw "^### Client ${user}\$" /etc/wireguard/wg0.conf; then
		newline
		error "$user already exist"
		newline
		goback
	fi 
	echo -e " Duration Day: \c"
	read duration
	exp=$(date -d +${duration}days +%Y-%m-%d)
	expired=$(date -d "${exp}" +"%d %b %Y")

	for dot_ip in {2..254}; do
		dot_exists=$(grep -c "10.66.66.${dot_ip}" /etc/wireguard/wg0.conf)
		if [[ ${dot_exists} == '0' ]]; then
			break
		fi
	done
	if [[ ${dot_exists} == '1' ]]; then
		newline
		error "The subnet configured only supports 253 clients"
		newline
		goback
	fi

	client_ipv4="10.66.66.${dot_ip}"
	client_priv_key=$(wg genkey)
	client_pub_key=$(echo "${client_priv_key}" | wg pubkey)
	client_pre_shared_key=$(wg genpsk)

	echo -e "$user\t$exp" >> /metavpn/wireguard/wireguard-clients.txt
	echo -e "[Interface]
PrivateKey = ${client_priv_key}
Address = ${client_ipv4}/32
DNS = 8.8.8.8,8.8.4.4

[Peer]
PublicKey = ${server_pub_key}
PresharedKey = ${client_pre_shared_key}
Endpoint = ${endpoint}
AllowedIPs = 0.0.0.0/0" >> /metavpn/wireguard/${user}.conf
	echo -e "\n### Client ${user}
[Peer]
PublicKey = ${client_pub_key}
PresharedKey = ${client_pre_shared_key}
AllowedIPs = ${client_ipv4}/32" >> /etc/wireguard/wg0.conf
	systemctl daemon-reload
	systemctl restart wg-quick@wg0

	clear
	newline
	echo -e "WireGuard User Information"
	echo -e "=========================="
	echo -e " Username\t: $user"
	echo -e " Expired Date\t: $expired"
	newline 
	goback
}

delete_user(){
	clear
	newline
	echo -e "Delete WireGuard User"
	echo -e "====================="
	echo -e " Username: \c"
	read user
	if grep -qw "^### Client ${user}\$" /etc/wireguard/wg0.conf; then
		sed -i "/^### Client ${user}\$/,/^$/d" /etc/wireguard/wg0.conf
		if grep -q "### Client" /etc/wireguard/wg0.conf; then
			line=$(grep -n AllowedIPs /etc/wireguard/wg0.conf | tail -1 | awk -F: '{print $1}')
			head -${line} /etc/wireguard/wg0.conf > /tmp/wg0.conf
			mv /tmp/wg0.conf /etc/wireguard/wg0.conf
		else
			head -6 /etc/wireguard/wg0.conf > /tmp/wg0.conf
			mv /tmp/wg0.conf /etc/wireguard/wg0.conf
		fi
		rm -f /metavpn/wireguard/${user}.conf
		sed -i "/\b$user\b/d" /metavpn/wireguard/wireguard-clients.txt
		systemctl daemon-reload
		systemctl restart wg-quick@wg0
		newline
		ok "$user deleted successfully"
		newline 
		goback
	else
		newline
		error "$user does not exist"
		newline 
		goback
	fi
}

extend_user() {
	clear
	newline
	echo -e "Extend WireGuard User"
	echo -e "====================="
	echo -e " Username: \c"
	read user
	if ! grep -qw "$user" /metavpn/wireguard/wireguard-clients.txt; then
		newline
		error "$user does not exist"
		newline
		goback
	fi 
	echo -e " Duration Day: \c"
	read extend

	exp_old=$(cat /metavpn/wireguard/wireguard-clients.txt | grep -w $user | awk '{print $2}')
	diff=$((($(date -d "${exp_old}" +%s)-$(date +%s))/(86400)))
	duration=$(expr $diff + $extend + 1)
	exp_new=$(date -d +${duration}days +%Y-%m-%d)
	exp=$(date -d "${exp_new}" +"%d %b %Y")

	sed -i "/\b$user\b/d" /metavpn/wireguard/wireguard-clients.txt
	echo -e "$user\t$exp_new" >> /metavpn/wireguard/wireguard-clients.txt

	clear
	newline
	echo -e "WireGuard User Information"
	echo -e "=========================="
	echo -e " Username\t: $user"
	echo -e " Expired Date\t: $exp"
	newline 
	goback
}

user_list() {
	clear
	newline
	echo -e "==========================="
	echo -e "Username          Exp. Date"
	echo -e "==========================="
	while read expired
	do
		user=$(echo $expired | awk '{print $1}')
		exp=$(echo $expired | awk '{print $2}')
		exp_date=$(date -d"${exp}" "+%d %b %Y")
		printf "%-17s %2s\n" "$user" "$exp_date"
	done < /metavpn/wireguard/wireguard-clients.txt
	total=$(wc -l /metavpn/wireguard/wireguard-clients.txt | awk '{print $1}')
	echo -e "==========================="
	echo -e "Total Accounts: $total     "
	echo -e "==========================="
	newline 
	goback
}

show_config() {
	clear
	newline
	echo -e "WireGuard Configuration"
	echo -e "======================="
	echo -e " Username\t: \c"
	read user
	if grep -qw "^### Client ${user}\$" /etc/wireguard/wg0.conf; then
		exp=$(cat /metavpn/wireguard/wireguard-clients.txt | grep -w "$user" | awk '{print $2}')
		exp_date=$(date -d"${exp}" "+%d %b %Y")
		echo -e " Expired\t: $exp_date"
		newline
		qrencode -t ansiutf8 -l L < /metavpn/wireguard/${user}.conf
		newline
		echo -e "Configuration"
		echo -e "============="
		newline
		cat /metavpn/wireguard/${user}.conf
		newline 
		goback
	else
		newline
		error "$user does not exist"
		newline
		goback
	fi
}

clear
newline
echo -e "=============================="
echo -e "        WireGuard Menu        "
echo -e "=============================="
newline
echo -e "  [1] Add WireGuard User"
echo -e "  [2] Delete WireGuard User"
echo -e "  [3] Extend WireGuard User"
echo -e "  [4] WireGuard User List"
echo -e "  [5] WireGuard Configuration"
echo -e "  [6] Back"
newline
echo -e "=============================="
echo -e " Select Menu: \c"
read menu
case $menu in
1)
	add_user 
	goback
	;;
2)
	delete_user 
	goback
	;;
3)
	extend_user 
	goback
	;;
4)
	user_list 
	goback
	;;
5)
	show_config 
	goback
	;;
6)
	wireguard
	;;
*) 
	clear 
	newline
	error "Invalid option"
	newline
	goback
	;;
esac