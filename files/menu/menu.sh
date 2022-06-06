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
	    menu
      ;;
	esac
}

update_script() {
  repo="https://raw.githubusercontent.com/mrjohntora/autoscript-metavpn/main/"
  clear 
  newline
	info "Updating script"
	sleep 2
	rm -f /usr/bin/{menu,ovpn,xray,wireguard,check,backup}
	rm -f /metavpn/cron.daily
	wget -O /usr/bin/menu "${repo}files/menu/menu.sh"
	wget -O /usr/bin/ovpn "${repo}files/menu/ovpn.sh"
	wget -O /usr/bin/xray "${repo}files/menu/xray.sh"
	wget -O /usr/bin/wireguard "${repo}files/menu/wireguard.sh"
	wget -O /usr/bin/check "${repo}files/menu/check.sh" 
	wget -O /usr/bin/backup "${repo}files/menu/backup.sh"
	wget -O /usr/bin/nench "${repo}files/nench.sh" 
	wget -O /metavpn/cron.daily "${repo}files/cron.daily"
	chmod +x /usr/bin/{menu,ovpn,xray,wireguard,check,backup,nench}
	chmod +x /metavpn/cron.daily
	sleep 2
	ok "Successful updated script" 
	newline 
	goback
}

clear
while true
do
newline
echo -e "==========================="
echo -e "       Meta VPN Menu       "
echo -e "==========================="
newline
echo -e " VPN Account:"
echo -e "   [1] OpenVPN Menu"
echo -e "   [2] Xray Vless Menu"
echo -e "   [3] WireGuard Menu"
newline
echo -e " VPN System:"
echo -e "   [4] Server Speedtest"
echo -e "   [5] Server Benchmark"
echo -e "   [6] Service Status"
echo -e "   [7] Update Script"
newline
echo -e "   [0] Exit"
newline
echo -e "==========================="
echo -e " Select Menu: \c"
read menu
case $menu in
	1)
		ovpn
		;;
	2)
		xray
		;;
	3)
		wireguard
		;;
	4)
		clear
		speedtest 
		goback
		;;
	5)
		clear
		nench
		;;
	6)
		clear
		check
		;;
	7)
		update_script
		;;
	0)
		clear
		exit 1
		;;
	*) 
	  clear 
	  newline
		error "Invalid option"
		newline
		goback
		;;
esac
done
