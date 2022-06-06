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

goback() {
  echo -e "Enter any keys to go back \c" 
	read back 
	case $back in 
	  *)
	    xray
      ;;
	esac
}

add_user() {
	clear
	newline
	echo -e "Add Xray User"
	echo -e "============="
	echo -e " Username: \c"
	read user
	if grep -qw "$user" /metavpn/xray/xray-clients.txt; then
		newline
		error "$user already exist"
		newline 
		goback
	fi 
	echo -e " Duration Day: \c"
	read duration

	uuid=$(uuidgen)
	while grep -qw "$uuid" /metavpn/xray/xray-clients.txt; do
		uuid=$(uuidgen)
	done
	exp=$(date -d +${duration}days +%Y-%m-%d)
	expired=$(date -d "${exp}" +"%d %b %Y")
	domain=$(cat /usr/local/etc/xray/domain)
	host=$(hostname -d)
	email="admin@${domain}"
	echo -e "${user}\t${uuid}\t${exp}" >> /metavpn/xray/xray-clients.txt

	cat /usr/local/etc/xray/xtls.json | jq '.inbounds[0].settings.clients += [{"id": "'${uuid}'","flow": "xtls-rprx-direct","level": 0,email": "'${email}'"}]' > /usr/local/etc/xray/xtls_tmp.json
	mv -f /usr/local/etc/xray/xtls_tmp.json /usr/local/etc/xray/xtls.json
	cat /usr/local/etc/xray/ws.json | jq '.inbounds[0].settings.clients += [{"id": "'${uuid}'","email": "'${email}'"}]' > /usr/local/etc/xray/ws_tmp.json
	mv -f /usr/local/etc/xray/ws_tmp.json /usr/local/etc/xray/ws.json
	systemctl daemon-reload
	systemctl restart xray@xtls
	systemctl restart xray@ws

	clear
	newline
	echo -e "Xray User Information"
	echo -e "====================="
	echo -e " Username\t: $user"
	echo -e " Expired Date\t: $expired"
	newline 
	goback
}

delete_user() {
	clear
	newline
	echo -e "Delete Xray User"
	echo -e "================"
	echo -e " Username: \c"
	read user
	if ! grep -qw "$user" /metavpn/xray/xray-clients.txt; then
		newline
		error "$user does not exist"
		newline
		goback
	fi
	uuid="$(cat /metavpn/xray/xray-clients.txt | grep -w "$user" | awk '{print $2}')"

	cat /usr/local/etc/xray/xtls.json | jq 'del(.inbounds[0].settings.clients[] | select(.id == "'${uuid}'"))' > /usr/local/etc/xray/xtls_tmp.json
	mv -f /usr/local/etc/xray/xtls_tmp.json /usr/local/etc/xray/xtls.json
	cat /usr/local/etc/xray/ws.json | jq 'del(.inbounds[0].settings.clients[] | select(.id == "'${uuid}'"))' > /usr/local/etc/xray/ws_tmp.json
	mv -f /usr/local/etc/xray/ws_tmp.json /usr/local/etc/xray/ws.json
	sed -i "/\b$user\b/d" /metavpn/xray/xray-clients.txt
	systemctl daemon-reload
	systemctl restart xray@xtls
	systemctl restart xray@ws
	newline
	ok "$user deleted successfully"
	newline 
	goback
}

extend_user() {
	clear
	newline
	echo -e "Extend Xray User"
	echo -e "================"
	echo -e " Username: \c"
	read user
	if ! grep -qw "$user" /metavpn/xray/xray-clients.txt; then
		newline
		error "$user does not exist"
		newline
		goback
	fi 
	echo -e " Duration Day: \c"
	read extend

	uuid=$(cat /metavpn/xray/xray-clients.txt | grep -w $user | awk '{print $2}')
	exp_old=$(cat /metavpn/xray/xray-clients.txt | grep -w $user | awk '{print $3}')
	diff=$((($(date -d "${exp_old}" +%s)-$(date +%s))/(86400)))
	duration=$(expr $diff + $extend + 1)
	exp_new=$(date -d +${duration}days +%Y-%m-%d)
	exp=$(date -d "${exp_new}" +"%d %b %Y")

	sed -i "/\b$user\b/d" /metavpn/xray/xray-clients.txt
	echo -e "$user\t$uuid\t$exp_new" >> /metavpn/xray/xray-clients.txt

	clear
	newline
	echo -e "Xray User Information"
	echo -e "====================="
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
	while read expired; do
		user=$(echo $expired | awk '{print $1}')
		exp=$(echo $expired | awk '{print $3}')
		exp_date=$(date -d"${exp}" "+%d %b %Y")
		printf "%-17s %2s\n" "$user" "$exp_date"
	done < /metavpn/xray/xray-clients.txt
	total=$(wc -l /metavpn/xray/xray-clients.txt | awk '{print $1}')
	echo -e "==========================="
	echo -e "Total Accounts: $total     "
	echo -e "==========================="
	newline 
	goback
}

user_monitor() {
	data=($(cat /metavpn/xray/xray-clients.txt | awk '{print $1}'))
	data2=($(netstat -anp | grep ESTABLISHED | grep tcp6 | grep xray | grep -w 443 | awk '{print $5}' | cut -d: -f1 | sort | uniq))
	domain=$(cat /usr/local/etc/xray/domain)
	clear
	newline
	echo -e "==========================="
	echo -e "  Xray-XTLS Login Monitor  "
	echo -e "==========================="
	n=0
	for user in "${data[@]}"; do
		touch /tmp/ipxray.txt
		for ip in "${data2[@]}"; do
			total=$(cat /var/log/xray/access-xtls.log | grep -w ${user}@${domain} | awk '{print $3}' | cut -d: -f1 | grep -w $ip | sort | uniq)
			if [[ "$total" == "$ip" ]]; then
				echo -e "$total" >> /tmp/ipxray.txt
				n=$((n+1))
			fi
		done
		total=$(cat /tmp/ipxray.txt)
		if [[ -n "$total" ]]; then
			total2=$(cat /tmp/ipxray.txt | nl)
			echo -e "$user:"
			echo -e "$total2"
		fi
		rm -f /tmp/ipxray.txt
	done
	echo -e "==========================="
	echo -e "Total Logins: $n           "
	echo -e "==========================="
	newline
	echo -e "==========================="
	echo -e "   Xray-WS Login Monitor   "
	echo -e "==========================="
	n=0
	data3=($(netstat -anp | grep ESTABLISHED | grep tcp | grep nginx | grep -w 80 | awk '{print $5}' | cut -d: -f1 | sort | uniq))
	for user in "${data[@]}"; do
		touch /tmp/ipxray.txt
		for ip in "${data3[@]}"; do
			total=$(cat /var/log/xray/access-ws.log | grep -w ${user}@${domain} | awk '{print $3}' | cut -d: -f1 | grep -w $ip | sort | uniq)
			if [[ "$total" == "$ip" ]]; then
				echo -e "$total" >> /tmp/ipxray.txt
				n=$((n+1))
			fi
		done
		total=$(cat /tmp/ipxray.txt)
		if [[ -n "$total" ]]; then
			total2=$(cat /tmp/ipxray.txt | nl)
			echo -e "$user:"
			echo -e "$total2"
		fi
		rm -f /tmp/ipxray.txt
	done
	echo -e "==========================="
	echo -e "Total Logins: $n           "
	echo -e "==========================="
	newline 
	goback
}

show_config() {
	newline 
  clear
	echo -e "Xray Configuration"
	echo -e "=================="
  echo -e " Add a sni bug (y/n)? \c"
  read add
  case $add in
  y)
    echo -e " Enter sni bug: \c"
    read bug
	  if [[ $bug != "$1" ]]; then
	  bug=$(hostname -f) 
	  fi 
	  ;;
  n)
    bug=$(hostname -f)
    ;;
  esac
	echo -e " Username: \c"
	read user
	if ! grep -qw "$user" /metavpn/xray/xray-clients.txt; then
		newline
		error "$user does not exist"
		newline
		goback
	fi
	uuid=$(cat /metavpn/xray/xray-clients.txt | grep -w "$user" | awk '{print $2}')
	domain=$(cat /usr/local/etc/xray/domain)
	exp=$(cat /metavpn/xray/xray-clients.txt | grep -w "$user" | awk '{print $3}')
	exp_date=$(date -d"${exp}" "+%d %b %Y")

	echo -e " Expired: $exp_date"
	newline
	echo -e "Xray Vless XTLS"
	echo -e "==============="
	echo -e " Host\t\t: $domain"
	echo -e " Port\t\t: 443"
	echo -e " ID\t\t: $uuid"
	echo -e " Flow\t\t: xtls-rprx-direct"
	echo -e " Encryption\t: none"
	echo -e " Network\t: tcp"
	echo -e " Header Type\t: none"
	echo -e " TLS\t\t: xtls" 
	echo -e " Bug\t\t: $bug"
	newline
	echo -e " Link: vless://$uuid@$domain:443?security=xtls&encryption=none&flow=xtls-rprx-direct&sni=$bug#XRAY_XTLS-$user"
	newline
	qrencode -t ansiutf8 -l L "vless://$uuid@$domain:443?security=xtls&encryption=none&flow=xtls-rprx-direct&sni=$bug#XRAY_XTLS-$user"
	newline
	echo -e "Xray Vless WS"
	echo -e "============="
	echo -e " Host\t\t: $domain"
	echo -e " Port\t\t: 80"
	echo -e " ID\t\t: $uuid"
	echo -e " Encryption\t: none"
	echo -e " Network\t: ws"
	echo -e " Path\t\t: /xray" 
	echo -e " Bug\t\t: $bug"
	newline
	echo -e " Link: vless://$uuid@$domain:80?path=%2Fxray&security=none&encryption=none&host=$bug&type=ws#XRAY_WS-$user"
	newline
	qrencode -t ansiutf8 -l L "vless://$uuid@$domain:80?path=%2Fxray&security=none&encryption=none&host=$bug&type=ws#XRAY_WS-$user"
	newline 
	goback
}

clear
newline
echo -e "========================="
echo -e "     Xray Vless Menu     "
echo -e "========================="
newline
echo -e "  [1] Add Xray User"
echo -e "  [2] Delete Xray User"
echo -e "  [3] Extend Xray User"
echo -e "  [4] Xray User List"
echo -e "  [5] Xray User Monitor"
echo -e "  [6] Xray Configuration"
echo -e "  [7] Back"
newline
echo -e "========================="
echo -e " Select Menu: \c"
read menu
case $menu in
1)
	add_user
	;;
2)
	delete_user
	;;
3)
	extend_user
	;;
4)
	user_list
	;;
5)
	user_monitor
	;;
6)
	show_config
	;;
7)
	menu
	;;
*) 
	clear 
	newline
	error "Invalid option"
	newline
	goback
	;;
esac