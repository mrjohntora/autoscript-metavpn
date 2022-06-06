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

check_service() {
  if systemctl is-active $1 > /dev/null 2>&1; then
    ok "running"
  else
    error "not running"
  fi
}

check_screen() {
  if screen -ls | grep -qw $1; then 
    ok "running"
  else
    error "not running"
  fi
}

clear
newline
echo -e "===================================="
echo -e "           Service Status           "
echo -e "===================================="
newline
echo -e " SSH\t\t: $(check_service ssh)"
echo -e " Dropbear\t: $(check_service dropbear)"
echo -e " Stunnel\t: $(check_service stunnel4)"
echo -e " OpenVPN (UDP)\t: $(check_service openvpn@server-udp)"
echo -e " OpenVPN (TCP)\t: $(check_service openvpn@server-tcp)"
echo -e " Squid Proxy\t: $(check_service squid)"
echo -e " OHP Dropbear\t: $(check_screen ohp-dropbear)"
echo -e " OHP OpenVPN\t: $(check_screen ohp-openvpn)"
echo -e " BadVPN UDPGw\t: $(check_screen badvpn)"
echo -e " Nginx\t\t: $(check_service nginx)"
echo -e " Xray XTLS\t: $(check_service xray@xtls)"
echo -e " Xray WS\t: $(check_service xray@ws)"
echo -e " WireGuard\t: $(check_service wg-quick@wg0)"
echo -e " Fail2Ban\t: $(check_service fail2ban)"
echo -e " DDoS Deflate\t: $(check_service ddos)"
newline
echo -e "===================================="
newline
goback