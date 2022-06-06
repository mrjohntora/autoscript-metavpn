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
	    ovpn
      ;;
	esac
}

bughost() {
  echo -e " Add a bug host (y/n)? \c"
  read bughost
  case $bughost in
  y)
  echo -e " Enter bug host: \c"
  read bug
  	if [[ $bug != "$1" ]]; then
  	cp /metavpn/openvpn/client-tcp.ovpn /metavpn/openvpn/{$bug}.ovpn
  	sed -i "s+remote xx 992+remote $ip:992@$bug/+g" /metavpn/openvpn/{$bug}.ovpn
  	sed -i "s+;http-proxy xx 8080+http-proxy $ip 8080+g" /metavpn/openvpn/{$bug}.ovpn 
  	sed -i "s+;http-proxy-retry+http-proxy-retry+g" /metavpn/openvpn/client-tcp.ovpn
  	newline
    cat /metavpn/openvpn/{$bug}.ovpn 
    rm -r /metavpn/openvpn/{$bug}.ovpn
    newline 
    goback
  	fi 
  	;;
  n) 
    cp /metavpn/openvpn/client-tcp.ovpn /metavpn/openvpn/tcp.ovpn
  	sed -i "s+remote xx 992+remote $ip 992+g" /metavpn/openvpn/tcp.ovpn
  	newline
    cat /metavpn/openvpn/tcp.ovpn 
    rm -r /metavpn/openvpn/tcp.ovpn
    newline 
    goback
    ;;
  esac
}

add_user() {
	clear
	newline 
	echo -e "Add OpenVPN User"
	echo -e "================"
	echo -e " Username: \c"
	read user
	if getent passwd $user > /dev/null 2>&1; then
		newline
		error "$user already exist"
		newline 
		goback
	fi 
	echo -e " Password: \c"
	read pass 
	echo -e " Duration Day: \c"
	read duration
	useradd -e $(date -d +${duration}days +%Y-%m-%d) -s /bin/false -M $user
	echo -e "$pass\n$pass\n"|passwd $user &> /dev/null
	echo -e "${user}\t${pass}\t$(date -d +${duration}days +%Y-%m-%d)" >> /metavpn/ssh/ssh-clients.txt

	exp=$(date -d +${duration}days +"%d %b %Y") 
	
	echo -e " Enter a valid bug host or just enter to setup it later"
	echo -e " Bug host: \c"
	read bug


	clear
	newline 
	echo -e "OpenVPN User Information"
	echo -e "========================"
	echo -e " Username\t: $user "
	echo -e " Password\t: $pass"
	echo -e " Expired Date\t: $exp"
	newline 
	goback
}

delete_user() {
	clear 
	newline
	echo -e "Delete OpenVPN User"
	echo -e "==================="
	echo -e " Username: \c"
	read user
	if getent passwd $user > /dev/null 2>&1; then
		userdel $user
		sed -i "/\b$user\b/d" /metavpn/ssh/ssh-clients.txt
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
	echo -e "Extend OpenVPN User"
	echo -e "==================="
	echo -e " Username: \c"
	read user
	if ! getent passwd $user > /dev/null 2>&1; then
		newline
		error "$user does not exist"
		newline 
		goback
	fi 
	echo -e " Duration Day: \c"
	read extend

	exp_old=$(chage -l $user | grep "Account expires" | awk -F": " '{print $2}')
	diff=$((($(date -d "${exp_old}" +%s)-$(date +%s))/(86400)))
	duration=$(expr $diff + $extend + 1)

	chage -E $(date -d +${duration}days +%Y-%m-%d) $user
	exp_new=$(chage -l $user | grep "Account expires" | awk -F": " '{print $2}')
	exp=$(date -d "${exp_new}" +"%d %b %Y")

	clear 
	newline
	echo -e "OpenVPN User Information"
	echo -e "========================"
	echo -e " Username\t: $user "
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
	n=0
	while read expired; do
		account=$(echo $expired | cut -d: -f1)
		id=$(echo $expired | grep -v nobody | cut -d: -f3)
		exp=$(chage -l $account | grep "Account expires" | awk -F": " '{print $2}')

		if [[ $id -ge 1000 ]] && [[ $exp != "never" ]]; then
			exp_date=$(date -d "${exp}" +"%d %b %Y")
			printf "%-17s %2s\n" "$account" "$exp_date"
			n=$((n+1))
		fi
	done < /etc/passwd
	echo -e "==========================="
	echo -e "Total Accounts: $n         "
	echo -e "==========================="
	newline 
	goback
}

user_monitor() {
	data=($(ps aux | grep -i dropbear | awk '{print $2}'))
	clear
	newline
	echo -e "================================="
	echo -e "     Dropbear Login Monitor      "
	echo -e "================================="
	n=0
	for pid in "${data[@]}"; do
		num=$(cat /var/log/auth.log | grep -i dropbear | grep -i "Password auth succeeded" | grep "dropbear\[$pid\]" | wc -l)
		user=$(cat /var/log/auth.log | grep -i dropbear | grep -i "Password auth succeeded" | grep "dropbear\[$pid\]" | awk '{print $10}' | tr -d "'")
		ip=$(cat /var/log/auth.log | grep -i dropbear | grep -i "Password auth succeeded" | grep "dropbear\[$pid\]" | awk '{print $12}')
		if [ $num -eq 1 ]; then
			echo -e "$pid - $user - $ip"
			n=$((n+1))
		fi
	done
	echo -e "================================="
	echo -e "Total Logins: $n                 "
	echo -e "================================="
	newline
	echo -e "================================="
	echo -e "   OpenVPN (TCP) Login Monitor   "
	echo -e "================================="
	a=$(grep -n "Common Name,Real Address,Bytes Received,Bytes Sent,Connected Since" /var/log/openvpn/server-tcp-status.log | awk -F":" '{print $1}')
	b=$(expr $(grep -n "ROUTING TABLE" /var/log/openvpn/server-tcp-status.log | awk -F":" '{print $1}') - 1)
	c=$(expr ${b} - ${a})
	cat /var/log/openvpn/server-tcp-status.log | head -n $b | tail -n $c | sed -e 's/,/\t/g' > /tmp/openvpn-tcp-login.txt
	n=0
	while read login; do
		user=$(echo $login | awk '{print $1}')
		ip=$(echo $login | awk '{print $2}')
		echo -e "$user - $ip"
		n=$((n+1))
	done < /tmp/openvpn-tcp-login.txt
	echo -e "================================="
	echo -e "Total Logins: $n                 "
	echo -e "================================="
	newline
	echo -e "================================="
	echo -e "   OpenVPN (UDP) Login Monitor   "
	echo -e "================================="
	a=$(grep -n "Common Name,Real Address,Bytes Received,Bytes Sent,Connected Since" /var/log/openvpn/server-udp-status.log | awk -F":" '{print $1}')
	b=$(expr $(grep -n "ROUTING TABLE" /var/log/openvpn/server-udp-status.log | awk -F":" '{print $1}') - 1)
	c=$(expr ${b} - ${a})
	cat /var/log/openvpn/server-udp-status.log | head -n $b | tail -n $c | sed -e 's/,/\t/g' > /tmp/openvpn-udp-login.txt
	n=0
	while read login; do
		user=$(echo $login | awk '{print $1}')
		ip=$(echo $login | awk '{print $2}')
		echo -e "$user - $ip"
		n=$((n+1))
	done < /tmp/openvpn-udp-login.txt
	echo -e "================================="
	echo -e "Total Logins: $n                 "
	echo -e "================================="
	newline 
	goback
}

show_information() {
	clear
	newline
	echo -e "SSH Information"
	echo -e "==============="
	echo -e " Username\t: \c"
	read user
	if getent passwd $user > /dev/null 2>&1; then
		pass=$(cat /metavpn/ssh/ssh-clients.txt | grep -w "$user" | awk '{print $2}')
		exp=$(cat /metavpn/ssh/ssh-clients.txt | grep -w "$user" | awk '{print $3}')
		exp_date=$(date -d"${exp}" "+%d %b %Y")
		ip=$(wget -qO- ipv4.icanhazip.com)
		echo -e " Password\t: $pass"
		echo -e " Expired\t: $exp_date"
		newline
		echo -e "Host Information"
		echo -e "================"
		echo -e " Host\t\t: $ip"
		echo -e " Dropbear\t: 110"
		echo -e " Stunnel\t: 444"
		echo -e " Squid Proxy\t: 8080"
		echo -e " OHP Dropbear\t: 3128"
		echo -e " OHP OpenVPN\t: 8000" 
		echo -e " OpenVPN TCP\t: 443"
		echo -e " OpenVPN UDP\t: 1194"
		echo -e " BadVPN UDPGW\t: 7300"
		newline 
		goback
	else
		newline
		error "$user does not exist"
		newline 
		goback
	fi
}

ovpn_config() {
	clear
	newline
	echo -e "OpenVPN Configuration"
	echo -e "====================="
	newline
	echo -e "  [1] OpenVPN TCP"
	echo -e "  [2] OpenVPN UDP"
	echo -e "  [3] Back"
	newline 
	echo -e "====================="
	echo -e " Select Config: \c"
	read config 
	case $config in
  1)
  	clear
  	echo -e "OpenVPN TCP Config"
  	echo -e "=================="
  	bughost
  	;;
  2)
  	clear
  	echo -e "OpenVPN UDP Config"
  	echo -e "=================="
  	newline
  	cat /metavpn/openvpn/client-udp.ovpn
  	newline 
  	goback
  	;;
  3)
    openvpn
  	;;
  *) 
    clear 
	  newline
		error "Invalid option"
		newline
		goback
		;;
	esac
}

clear
newline
echo -e "============================"
echo -e "        OpenVPN MENU        "
echo -e "============================"
newline
echo -e "  [1] Add OpenVPN User"
echo -e "  [2] Delete OpenVPN User"
echo -e "  [3] Extend OpenVPN User"
echo -e "  [4] OpenVPN User List"
echo -e "  [5] OpenVPN User Monitor"
echo -e "  [6] Show Information"
echo -e "  [7] OpenVPN Configuration"
echo -e "  [8] Back"
newline
echo -e "============================"
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
	show_information
	;;
7)
	ovpn_config
	;;
8)
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