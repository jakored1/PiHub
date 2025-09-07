#!/bin/bash

# Written by https://github.com/jakored1

set -e

ETHERNET_INTERFACE="eth0"
WIFI_INTERFACE="wlan0"
DEVICE_HOSTNAME="iPhone"
TTL=""
INSTALL_PROGRAMS=""
SCRIPTS_FOLDER="/home/$SUDO_USER/Desktop/"
TOOL_INSTALL_DIRECTORY="/opt"
DEBUG_MODE="n"

PACKAGES_INSTALLED_FILE="/root/.rpi5_wifi_bridge_extra_packages_installed"

SCRIPT_PATH="$0"
help_menu () {
	echo -e "usage:"
	echo -e "\t-h, --help\tshow this menu"
	echo -e "\t-e\t\tethernet interface (default '$ETHERNET_INTERFACE')"
	echo -e "\t-w\t\twifi interface (default '$WIFI_INTERFACE')"
	echo -e "\t-n\t\thostname - whitespace is not allowed in hostname (default '$DEVICE_HOSTNAME')"
	echo -e "\t--install\tto install extra programs and drivers"
 	echo -e "\t-d\t\tenable debug mode (will print out all commands that are being executed)"
	echo -e "\t-t\t\tset ipv4 and ipv6 ttl (optional, default is to leave current values, recommended value is between 64 to 255)"
	echo -e ""
	echo -e "examples:"
	echo -e "\tsudo $SCRIPT_PATH -h"
	echo -e "\tsudo $SCRIPT_PATH"
	echo -e "\tsudo $SCRIPT_PATH -e eth0 -w wlan0 -n samsung --install -t 80"
}

# Iterating over arguments
while test $# -gt 0
do
	case "$1" in
		-h) help_menu; exit 0
			;;
		--help) help_menu; exit 0
			;;
		-e) ETHERNET_INTERFACE="$2"
			shift 1
			;;
		-w) WIFI_INTERFACE="$2"
			shift 1
			;;
		-n) DEVICE_HOSTNAME="$2"
			shift 1
			;;
   		-d) DEBUG_MODE="y"
			;;
		-t) TTL="$2"
			shift 1
			;;
		--install) INSTALL_PROGRAMS="Yes"
			;;
	esac
	shift
done

[ $EUID -ne 0 ] && echo "run with sudo: 'sudo $0'" >&2 && exit 1


echo "------------------"
echo "--- DISCLAIMER ---"
echo "------------------"
echo "This script was made to run on Raspberry Pi 5, with Desktop"
echo "If this is not the OS/RPi version you have, some stuff might not work"
echo "This script *should* work flawlessly, but if it crashes at some point, you can just go over the script and run all the commands manually"
echo "(it's just a bunch of commands that set and install stuff, nothing too fancy)"
read -p "Continue? (Y/N): " confirm && [[ $confirm == [yY] || $confirm == [yY][eE] || $confirm == [yY][eE][sS] ]] || exit 0

if [[ "$DEBUG_MODE" == "y" ]]; then
	set -x
fi

echo ""
echo "#########################################"
echo "# Deleting 'user' & 'root' Bash History #"
echo "#########################################"
unset HISTFILE
sed -i -e 's/HISTFILESIZE=2000/HISTFILESIZE=0/g' /home/$SUDO_USER/.bashrc
sed -i -e 's/HISTFILESIZE=2000/HISTFILESIZE=0/g' /root/.bashrc
if [ -f /home/$SUDO_USER/.bash_history ]; then
    rm /home/$SUDO_USER/.bash_history
fi
if [ -f /root/.bash_history ]; then
    rm /root/.bash_history
fi
# sed -i -e 's/SAVEHIST=2000/SAVEHIST=0/g' /home/$SUDO_USER/.zshrc
# sed -i -e 's/SAVEHIST=2000/SAVEHIST=0/g' /root/.zshrc
# rm /home/$SUDO_USER/.zsh_history
# rm /root/.zsh_history

echo ""
echo "################################"
echo "# Making Bash Case-Insensitive #"
echo "################################"
if grep -Fxq "set completion-ignore-case On" /etc/inputrc
then
    :
else
	echo 'set completion-ignore-case On' >> /etc/inputrc
fi

echo ""
echo "#######################"
echo "# Disabling Bluetooth #"
echo "#######################"
if grep -Fxq "dtoverlay=disable-bt" /boot/firmware/config.txt
then
    :
else
	echo "dtoverlay=disable-bt" >> /boot/firmware/config.txt
fi
systemctl disable bluetooth.service
systemctl stop bluetooth.service

echo ""
echo "##################"
echo "# Disabling Cups #"
echo "##################"
systemctl disable cups-browsed.service
systemctl stop cups-browsed.service
systemctl disable cups.service
systemctl stop cups.service

echo ""
echo "################################################"
echo "# Configuring NetworkManager To Use Random MAC #"
echo "################################################"
cat <<EOF > /etc/NetworkManager/conf.d/00-macrandomize.conf
[device]
wifi.scan-rand-mac-address=yes

[connection]
wifi.cloned-mac-address=random
ethernet.cloned-mac-address=random

[dhcp]
send-hostname=false
EOF
systemctl restart NetworkManager
sleep 5

echo ""
echo "########################"
echo "# Connect to a Network #"
echo "########################"
nmtui

echo ""
echo "############################################"
echo "# Updating/Upgrading & Installing Packages #"
echo "############################################"
if ! apt-get update; then
	echo "The command \"sudo apt-get update\" failed, please fix this error and try again"
	exit 1
fi
if ! apt-get upgrade -y; then
	echo "The command \"sudo apt-get upgrade -y\" failed, please fix this error and try again"
	exit 1
fi
# install some packages
apt-get install -y iptables-persistent python3-full python3-virtualenv dnsutils mlocate plocate

echo ""
echo "#########################"
echo "# Installing SSH Server #"
echo "#########################"
apt-get install -y openssh-server
systemctl stop ssh.service
rm -rf /etc/ssh/default_keys 
mkdir /etc/ssh/default_keys
mv /etc/ssh/ssh_host_* /etc/ssh/default_keys/
dpkg-reconfigure openssh-server
systemctl start ssh.service
systemctl enable ssh.service

echo ""
echo "#########################"
echo "# Setting Up VNC Server #"
echo "#########################"
echo "*READ THE FOLLOWING*"
echo "> After you press 'enter', a screen will appear"
echo "> In the screen, this is what you need to select:"
echo "    Interface Options --> VNC --> Yes"
echo "> This will setup a VNC server on the default VNC port 5900"
echo "> After you get a success message, select 'Finish' to exit the raspi-config screen"
echo ""
read -p "Press 'enter' when ready"
raspi-config

echo ""
echo "###############################"
echo "# Clearing All IPtables Rules #"
echo "###############################"
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT
iptables -t nat -F
iptables -t mangle -F
iptables -t raw -F 
iptables -F
iptables -X
ip6tables -P INPUT ACCEPT
ip6tables -P FORWARD ACCEPT
ip6tables -P OUTPUT ACCEPT
ip6tables -t nat -F
ip6tables -t mangle -F
ip6tables -t raw -F
ip6tables -F
ip6tables -X

if [ -z "${TTL}" ]; then
	:
else
	echo ""
	echo "################"
	echo "# Changing TTL #"
	echo "################"
	sysctl -w net.ipv4.ip_default_ttl=$TTL
	# sysctl -w net.ipv6.ip_default_ttl=$TTL  # doesn't exist for ipv6
	iptables -t mangle -A PREROUTING -i "${WIFI_INTERFACE}" -j TTL --ttl-inc 1
fi

echo ""
echo "#################################################"
echo "# Configuring Firewall Rules For Wifi Interface #"
echo "#################################################"
# Blocks all input traffic that is not RELATED/ESTABLISHED so we are not scanned by someone else
iptables -A INPUT -i $WIFI_INTERFACE -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -A INPUT -i $WIFI_INTERFACE -j DROP
ip6tables -A INPUT -i $WIFI_INTERFACE -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
ip6tables -A INPUT -i $WIFI_INTERFACE -j DROP
iptables-save > /etc/iptables/rules.v4
ip6tables-save > /etc/iptables/rules.v6

echo ""
echo "####################################"
echo "# Creating Ethernet Bridge Service #"
echo "####################################"
if nmcli con show | grep -q "wifibridge"; then
	nmcli c delete wifibridge
fi
nmcli c add con-name wifibridge type ethernet ifname $ETHERNET_INTERFACE ipv4.method shared ipv6.method ignore ipv4.dhcp-send-hostname no ipv6.dhcp-send-hostname no
nmcli con up wifibridge
nmcli con show

echo ""
echo "#####################"
echo "# Changing Hostname #"
echo "#####################"
hostnamectl set-hostname "${DEVICE_HOSTNAME}"
sed -i "s/127.0.1.1.*/127.0.1.1\t${DEVICE_HOSTNAME}/" /etc/hosts

echo ""
echo "#################################"
echo "# Disable Hostname Through DHCP #"
echo "#################################"
if grep -Fxq "hostname-mode=none" /etc/NetworkManager/NetworkManager.conf
then
    :
else
	perl -pi -e '$_ .= qq(hostname-mode=none) if /\[main\]/' /etc/NetworkManager/NetworkManager.conf
fi

echo ""
echo "#########################"
echo "# Disable ICMP Redirect #"
echo "#########################"
sysctl -w net.ipv4.conf.all.accept_redirects=0
sysctl -w net.ipv4.conf.default.accept_redirects=0
sysctl -w net.ipv4.conf.all.secure_redirects=0
sysctl -w net.ipv4.conf.default.secure_redirects=0
sysctl -w net.ipv6.conf.all.accept_redirects=0
sysctl -w net.ipv6.conf.default.accept_redirects=0
sysctl -w net.ipv4.conf.all.send_redirects=0
sysctl -w net.ipv4.conf.default.send_redirects=0

echo ""
echo "###################"
echo "# Randomizing MAC #"
echo "###################"
apt-get install -y macchanger
ifconfig "${WIFI_INTERFACE}" down
macchanger -r "${WIFI_INTERFACE}"
ifconfig "${WIFI_INTERFACE}" up

if [ -z "${INSTALL_PROGRAMS}" ]; then
	echo ""
	echo "######################"
	echo "# Disable NTP Client #"
	echo "######################"
	systemctl disable systemd-timesyncd.service || true
	systemctl stop systemd-timesyncd.service || true
	systemctl disable ntpsec || true
	systemctl stop ntpsec || true
	systemctl disable chronyd || true
	systemctl stop chronyd || true
fi 

cat <<EOF > $SCRIPTS_FOLDER/connect_to_wifi.sh
#!/bin/bash
WIFI_INTERFACE="wlan0"
DEVICE_HOSTNAME=""
TTL=""
SCRIPT_PATH="\$0"
help_menu () {
	echo -e "Securely connect to a wifi network"
	echo -e ""
	echo -e "usage:"
	echo -e "\t-h, --help\tshow this menu"
	echo -e "\t-i\t\twifi interface (default '\$WIFI_INTERFACE')"
	echo -e "\t-n\t\tchange hostname (requires reboot) - whitespace is not allowed in hostname (default - leave current hostname)"
	echo -e "\t-t\t\tset ipv4 and ipv6 ttl (optional, default is to leave current values, recommended value is between 64 to 255)"
	echo -e ""
	echo -e "examples:"
	echo -e "\tsudo \$SCRIPT_PATH -h"
	echo -e "\tsudo \$SCRIPT_PATH"
	echo -e "\tsudo \$SCRIPT_PATH -i wlan0 -n Samsung -t 255"
}

if [ "\$#" == 0 ]; then
	help_menu
	exit 0
fi

[ \$EUID -ne 0 ] && echo "run with sudo: 'sudo \$0'" >&2 && exit 1

# Iterating over arguments
while test \$# -gt 0
do
	case "\$1" in
		-h|--help) help_menu; exit 0
			;;
		-i) WIFI_INTERFACE="\$2"
			shift 1
			;;
		-n) DEVICE_HOSTNAME="\$2"
			shift 1
			;;
		-t) TTL="\$2"
			shift 1
			;;
	esac
	shift
done

if [ ! -z "\${DEVICE_HOSTNAME}" ]; then
	echo "--> changing hostname requires a reboot"
	echo "> Are you sure you want to change your hostname?"
	read -p "(Y/N): " confirm && [[ \$confirm == [yY] || \$confirm == [yY][eE] || \$confirm == [yY][eE][sS] ]] || exit 0
	hostnamectl set-hostname "\${DEVICE_HOSTNAME}"
	sed -i "s/127.0.1.1.*/127.0.1.1\t\${DEVICE_HOSTNAME}/" /etc/hosts
	echo "rebooting in:"
	echo "5"; sleep 1
	echo "4"; sleep 1
	echo "3"; sleep 1
	echo "2"; sleep 1
	echo "1"; sleep 1
	echo "reboot"
	reboot
fi

echo "--> clearing all iptables rules"
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT
iptables -t nat -F
iptables -t mangle -F
iptables -t raw -F 
iptables -F
iptables -X
ip6tables -P INPUT ACCEPT
ip6tables -P FORWARD ACCEPT
ip6tables -P OUTPUT ACCEPT
ip6tables -t nat -F
ip6tables -t mangle -F
ip6tables -t raw -F
ip6tables -F
ip6tables -X

echo ""
echo "--> telling network manager to manage interface"
nmcli dev set \$WIFI_INTERFACE managed yes
sleep 10

echo ""
echo "--> setting wifi interface to managed mode"
ip link set \$WIFI_INTERFACE down
iw dev \$WIFI_INTERFACE set type managed
rfkill unblock all
ip link set \$WIFI_INTERFACE up

if [ -n "\${TTL}" ]; then
	echo ""
	echo "--> changing ttl"
	sysctl -w net.ipv4.ip_default_ttl=\$TTL
	# sysctl -w net.ipv6.ip_default_ttl=\$TTL  # doesn't exist for ipv6
	iptables -t mangle -A PREROUTING -i "\${WIFI_INTERFACE}" -j TTL --ttl-inc 1
fi

echo ""
echo "--> configuring iptables rules for wifi interface"
iptables -A INPUT -i \$WIFI_INTERFACE -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -A INPUT -i \$WIFI_INTERFACE -j DROP
ip6tables -A INPUT -i \$WIFI_INTERFACE -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
ip6tables -A INPUT -i \$WIFI_INTERFACE -j DROP
iptables-save > /etc/iptables/rules.v4
ip6tables-save > /etc/iptables/rules.v6

echo ""
echo "--> disable ICMP redirect"
sysctl -w net.ipv4.conf.all.accept_redirects=0
sysctl -w net.ipv4.conf.default.accept_redirects=0
sysctl -w net.ipv4.conf.all.secure_redirects=0
sysctl -w net.ipv4.conf.default.secure_redirects=0
sysctl -w net.ipv6.conf.all.accept_redirects=0
sysctl -w net.ipv6.conf.default.accept_redirects=0
sysctl -w net.ipv4.conf.all.send_redirects=0
sysctl -w net.ipv4.conf.default.send_redirects=0

echo ""
echo "--> randomizing MAC"
ifconfig "\${WIFI_INTERFACE}" down
macchanger -r "\${WIFI_INTERFACE}"
ifconfig "\${WIFI_INTERFACE}" up

echo ""
echo "--> connect to a network"
nmtui

echo ""
echo "*NOTE*"
echo "> If there is no internet access after connecting to the wifi network,"
echo "> you might have to run the following command:"
echo "> sudo ip route add default via WIFI_DEFAULT_GATEWAY_IP"
echo "> For example, if the default gateway of the wifi network you connected to is 192.168.68.1, then run:"
echo "> sudo ip route add default via 192.168.68.1"

echo ""
echo "Done"
EOF
chown $SUDO_USER:$SUDO_USER $SCRIPTS_FOLDER/connect_to_wifi.sh
chmod +x $SCRIPTS_FOLDER/connect_to_wifi.sh


echo ""
echo "< ------ INSTALLATION DONE ------ >"
echo "> Wifi Bridge installation is done."
if [ -z "${INSTALL_PROGRAMS}" ]; then
	exit 0
else
	echo "> --install flag found, continuing programs & drivers installation"
fi

if [ -f "$PACKAGES_INSTALLED_FILE" ]; then
	echo ""
	echo "> It seems you have already installed packages in the past"
	echo "> Things might not install correctly if this is run again"
	echo "> Are you sure you want to try installing programs/drivers again?"
	read -p "(Y/N): " confirm && [[ $confirm == [yY] || $confirm == [yY][eE] || $confirm == [yY][eE][sS] ]] || exit 0
fi
touch $PACKAGES_INSTALLED_FILE

echo ""
echo "##################"
echo "# Installing Git #"
echo "##################"
apt-get install -y git

echo ""
echo "###################"
echo "# Installing Nmap #"
echo "###################"
apt-get install -y nmap

echo ""
echo "########################"
echo "# Installing Wireshark #"
echo "########################"
apt-get install -y wireshark

echo ""
echo "###################################"
echo "# Installing Driver For RTL8814AU #"
echo "###################################"
apt-get install -y raspberrypi-kernel-headers bc mokutil build-essential libelf-dev dkms
git clone https://gitlab.com/kalilinux/packages/realtek-rtl88xxau-dkms.git
cd realtek-rtl88xxau-dkms
sed -i 's/CONFIG_RTL8812A = y/CONFIG_RTL8812A = n/' Makefile
sed -i 's/CONFIG_RTL8821A = y/CONFIG_RTL8821A = n/' Makefile
make dkms_install
# to check if installed run "dkms status"
# to remove driver run "make dkms_remove"
cd -
rm -rf realtek-rtl88xxau-dkms
cat <<EOF > $SCRIPTS_FOLDER/set_monitor_mode.sh
#!/bin/bash

# To set wlan interface to monitor mode:
# sudo ip link set wlan0 down
# sudo iw dev wlan0 set type monitor
# sudo rfkill unblock all
# sudo ip link set wlan0 up
# 
# For setting TX power:
# sudo iw wlan0 set txpower fixed 3000
#
# Following script automates the process

WIFI_INTERFACE="wlan0"
MANAGED_MODE=""
SCRIPT_PATH="\$0"
help_menu () {
	echo -e "Set a wifi interface to monitor/managed mode"
	echo -e ""
	echo -e "usage:"
	echo -e "\t-h, --help\tshow this menu"
	echo -e "\t-i\t\twifi interface (default '\$WIFI_INTERFACE')"
	echo -e "\t-m\t\tif flag is set, this will set wifi interface to 'managed' mode"
	echo -e ""
	echo -e "examples:"
	echo -e "\tsudo \$SCRIPT_PATH -h"
	echo -e "\tsudo \$SCRIPT_PATH"
	echo -e "\tsudo \$SCRIPT_PATH -i wlan0"
	echo -e "\tsudo \$SCRIPT_PATH -i wlan0 -m"
}

if [ "\$#" == 0 ]; then
	help_menu
	exit 0
fi

[ \$EUID -ne 0 ] && echo "run with sudo: 'sudo \$0'" >&2 && exit 1

# Iterating over arguments
while test \$# -gt 0
do
	case "\$1" in
		-h|--help) help_menu; exit 0
			;;
		-i) WIFI_INTERFACE="\$2"
			shift 1
			;;
		-m) MANAGED_MODE="Yes"
			;;
	esac
	shift
done

if [ -z "\${MANAGED_MODE}" ]; then
	echo "--> telling network manager to ignore interface"
	nmcli dev set \$WIFI_INTERFACE managed no
	sleep 10

	echo "--> setting interface to monitor mode"
	ip link set \$WIFI_INTERFACE down
	iw dev \$WIFI_INTERFACE set type monitor
	rfkill unblock all
	ip link set \$WIFI_INTERFACE up
else
	echo "--> telling network manager to manage interface"
	nmcli dev set \$WIFI_INTERFACE managed yes
	sleep 10

	echo "--> setting interface to managed mode"
	ip link set \$WIFI_INTERFACE down
	iw dev \$WIFI_INTERFACE set type managed
	rfkill unblock all
	ip link set \$WIFI_INTERFACE up
fi
echo "Done"
EOF
chown $SUDO_USER:$SUDO_USER $SCRIPTS_FOLDER/set_monitor_mode.sh
chmod +x $SCRIPTS_FOLDER/set_monitor_mode.sh

echo ""
echo "#################################"
echo "# Installing Linux-Wifi-Hotspot #"
echo "#################################"
apt-get install -y libgtk-3-dev build-essential gcc g++ pkg-config make hostapd libqrencode-dev libpng-dev git haveged fzf
git clone https://github.com/lakinduakash/linux-wifi-hotspot /tmp/linux-wifi-hotspot
cd /tmp/linux-wifi-hotspot
make
make install
# commands you can use later: 
# sudo make uninstall # uninstall linux-wifi-hotspot
# wihotspot # start with a gui
cd -
rm -rf /tmp/linux-wifi-hotspot
cat <<EOF > $SCRIPTS_FOLDER/start_hotspot.sh
#!/bin/bash

WIFI_INTERFACE="wlan0"
DEVICE_HOSTNAME=""
TTL=""
SCRIPT_PATH="\$0"
HOTSPOT_INTERFACE=""
CREATE_AP_ARGS=""
HOTSPOT_NAME=""
HOTSPOT_PASSWORD=""
LIST_RUNNING=""
LIST_CLIENTS=""
STOP_AP=""
DEBUG_MODE=""
BLOCK_CLIENTS=""

SICON="[+]"
FICON="[-]"

help_menu () {
	echo -e "This script is basically a wrapper for the 'create_ap' utility with some extra features."
	echo -e "It allows you to connect to a wifi network with one interface, and use another interface (that supports monitor mode) to create a wifi hotpost that will route traffic through the network you connected to with the first interface."
	echo -e ""
	echo -e "usage:"
	echo -e "\t-h, --help\t\tshow this menu"
	echo -e "\t-ch, --create-ap-help\truns the command 'create_ap --help' to show available create_ap arguments"
	echo -e "\t-d, --debug\t\tactivate debug mode"
	echo -e "\t-i\t\t\twifi interface that will connect to a network (default '\$WIFI_INTERFACE')"
	echo -e "\t-m\t\t\tinterface that supports monitor mode, which will be used to create the wifi hotpost"
	echo -e "\t-b\t\t\tblock clients of the hotspot from connecting or interacting directly with the raspberry pi"
	echo -e "\t-c, --create-ap-args\targuments (as one string) to pass to the 'create_ap' command. ONLY PASS FLAGS! DO NOT pass arguments that explicitly ask to use specific interfaces for things (see examples). Also, DO NOT set the '--mac' flag here, use the flag in this script"
	echo -e "\t-n, --hotspot-name\tthe new hotspot name"
	echo -e "\t-p, --hotspot-password\tthe new hotspot password"
	echo -e "\t--list-running\t\tview all the running AP (hotspot) processes"
	echo -e "\t--list-clients\t\tview all the clients connected to an AP (hotspot) interface"
	echo -e "\t--stop\t\t\tstop AP (hotspot) that is running on given interface (only necessary if passing '--daemon' argument to create_ap)"
	echo -e "\t-t\t\t\tset ipv4 and ipv6 ttl (optional, default is to leave current values, recommended value is between 64 to 255)"
	echo -e ""
	echo -e "examples:"
	echo -e "\tsudo \$SCRIPT_PATH -h"
	echo -e "\tsudo \$SCRIPT_PATH -ch"
	echo -e "\tsudo \$SCRIPT_PATH -i wlan0 -m wlan1 -c '-m nat -w 2 --isolate-clients --daemon --no-virt -g 192.168.12.1 -d --hidden' -n 'My Network' -p '12345678' -b -d"
	echo -e "\tsudo \$SCRIPT_PATH --list-running"
	echo -e "\tsudo \$SCRIPT_PATH --list-clients -m wlan1"
	echo -e "\tsudo \$SCRIPT_PATH --stop -m wlan1"
	echo -e ""
	echo -e "tip: use the '--daemon' argument for create_ap to make the hotspot run in the background. You can then use the other flags in this script (--list-running,--list-clients,--stop) to view clients, active hotspots, and close active hotspots. This is the best way to use this script."
}

exit_program () {
	if [ "\$1" -ne 0 ]; then
		echo -n "\$FICON "
	else
		echo -n "\$SICON "
	fi
	echo "\$2"
	exit \$1
}

if [ "\$#" == 0 ]; then
	help_menu
	exit 0
fi

[ \$EUID -ne 0 ] && echo "run with sudo: 'sudo \$0'" >&2 && exit 1

# Iterating over arguments
while test \$# -gt 0
do
	case "\$1" in
		-h|--help) help_menu; exit 0
			;;
		-ch|--create-ap-help) create_ap --help; exit 0
			;;
		-i) WIFI_INTERFACE="\$2"
			shift 1
			;;
		-c|--create-ap-args) CREATE_AP_ARGS="\$2"
			shift 1
			;;
		-n|--hotspot-name) HOTSPOT_NAME="\$2"
			shift 1
			;;
		-p|--hotspot-password) HOTSPOT_PASSWORD="\$2"
			shift 1
			;;
		-m) HOTSPOT_INTERFACE="\$2"
			shift 1
			;;
		-t) TTL="\$2"
			shift 1
			;;
		-b) BLOCK_CLIENTS="y"
			;;
		-d|--debug) DEBUG_MODE="y"
			;;
		--list-running) LIST_RUNNING="y"
			;;
		--list-clients) LIST_CLIENTS="y"
			;;
		--stop) STOP_AP="y"
			;;
	esac
	shift
done

# activate debug mode
if [ "\$DEBUG_MODE" == "y" ]; then
	set -x
fi

# check if user wants to list running APs
if [ "\$LIST_RUNNING" == "y" ]; then
	echo "\$SICON running 'create_ap --list-running'"
	create_ap --list-running
	if [ "\$?" -ne 0 ]; then
		echo "\$FICON above error is from the 'create_ap' program, not this script"
		exit_program 1 "done"
	fi
	exit_program 0 "done"
fi
# check if user wants to list connected clients
if [ "\$LIST_CLIENTS" == "y" ]; then
	if [ -z "\${HOTSPOT_INTERFACE}" ]; then
		exit_program 1 "missing argument '-m' <hotspot_interface>"
	fi
	echo "\$SICON running 'create_ap --list-clients "\$HOTSPOT_INTERFACE"'"
	create_ap --list-clients "\$HOTSPOT_INTERFACE"
	if [ "\$?" -ne 0 ]; then
		echo "\$FICON above error is from the 'create_ap' program, not this script"
		exit_program 1 "done"
	fi
	exit_program 0 "done"
fi
# check if user wants to stop AP
if [ "\$STOP_AP" == "y" ]; then
	if [ -z "\${HOTSPOT_INTERFACE}" ]; then
		exit_program 1 "missing argument '-m' <hotspot_interface>"
	fi
	echo "\$SICON running 'create_ap --stop "\$HOTSPOT_INTERFACE"'"
	create_ap --stop "\$HOTSPOT_INTERFACE"
	if [ "\$?" -ne 0 ]; then
		echo "\$FICON above error is from the 'create_ap' program, not this script"
		exit_program 1 "done"
	fi
	exit_program 0 "done"
fi

# from this point on set exit on error just in case
set -e
# validate required arguments
missing_args=()
[ -z "\$WIFI_INTERFACE" ] && missing_args+=("\$FICON missing argument '-i' <wifi_interface>")
[ -z "\$CREATE_AP_ARGS" ] && missing_args+=("\$FICON missing argument '-c' <create_ap_args>")
[ -z "\$HOTSPOT_NAME" ] && missing_args+=("\$FICON missing argument '-n' <hotspot_name>")
[ -z "\$HOTSPOT_PASSWORD" ] && missing_args+=("\$FICON missing argument '-p' <hotspot_password>")
[ -z "\$HOTSPOT_INTERFACE" ] && missing_args+=("\$FICON missing argument '-m' <hotspot_interface>")
# print missing args and exit
if [ \${#missing_args[@]} -ne 0 ]; then
    for err in "\${missing_args[@]}"; do
        echo "\$err"
    done
    exit_program 1 "done"
fi
# clear iptables
echo "\$SICON clearing all iptables rules"
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT
iptables -t nat -F
iptables -t mangle -F
iptables -t raw -F 
iptables -F
iptables -X
ip6tables -P INPUT ACCEPT
ip6tables -P FORWARD ACCEPT
ip6tables -P OUTPUT ACCEPT
ip6tables -t nat -F
ip6tables -t mangle -F
ip6tables -t raw -F
ip6tables -F
ip6tables -X
# manage wifi interface
echo "\$SICON telling network manager to manage wifi interface (\$WIFI_INTERFACE)"
nmcli dev set \$WIFI_INTERFACE managed yes
sleep 10
# set interface to managed mode
echo "\$SICON setting wifi interface (\$WIFI_INTERFACE) to managed mode"
ip link set \$WIFI_INTERFACE down
iw dev \$WIFI_INTERFACE set type managed
rfkill unblock all
ip link set \$WIFI_INTERFACE up
# set ttl if user set flags
if [ -n "\${TTL}" ]; then
	echo "\$SICON changing ttl"
	sysctl -w net.ipv4.ip_default_ttl=\$TTL
	# sysctl -w net.ipv6.ip_default_ttl=\$TTL  # doesn't exist for ipv6
	iptables -t mangle -A PREROUTING -i "\${WIFI_INTERFACE}" -j TTL --ttl-inc 1
fi
# configure iptables for wifi interface
echo "\$SICON configuring iptables rules for wifi interface (\$WIFI_INTERFACE)"
iptables -A INPUT -i \$WIFI_INTERFACE -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -A INPUT -i \$WIFI_INTERFACE -j DROP
ip6tables -A INPUT -i \$WIFI_INTERFACE -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
ip6tables -A INPUT -i \$WIFI_INTERFACE -j DROP
# iptables-save > /etc/iptables/rules.v4
# ip6tables-save > /etc/iptables/rules.v6
# disable ICMP redirect
echo "\$SICON disable ICMP redirect"
sysctl -w net.ipv4.conf.all.accept_redirects=0
sysctl -w net.ipv4.conf.default.accept_redirects=0
sysctl -w net.ipv4.conf.all.secure_redirects=0
sysctl -w net.ipv4.conf.default.secure_redirects=0
sysctl -w net.ipv6.conf.all.accept_redirects=0
sysctl -w net.ipv6.conf.default.accept_redirects=0
sysctl -w net.ipv4.conf.all.send_redirects=0
sysctl -w net.ipv4.conf.default.send_redirects=0
# randomize mac for wifi interface
echo "\$SICON randomizing MAC for wifi interface (\$WIFI_INTERFACE)"
ifconfig "\${WIFI_INTERFACE}" down
macchanger -r "\${WIFI_INTERFACE}"
ifconfig "\${WIFI_INTERFACE}" up
# connect to a network
countdown=5
while [ \$countdown -gt 0 ]; do
    echo -ne "\$SICON connect to a network ('nmtui' interface will pop up in \$countdown)\r"
    sleep 1
    countdown=\$((countdown - 1))
done
echo ""
nmtui
echo ""
echo "> *NOTE*"
echo "> If there is no internet access after connecting to the wifi network on interface '\$WIFI_INTERFACE',"
echo "> you might have to run the following command:"
echo "> sudo ip route add default via WIFI_DEFAULT_GATEWAY_IP"
echo "> For example, if the default gateway of the wifi network you connected to is 192.168.68.1, then run:"
echo "> sudo ip route add default via 192.168.68.1"
# telling network manager to ignore hotspot interface
echo "\$SICON telling network manager to ignore hotspot interface (\$HOTSPOT_INTERFACE)"
nmcli dev set \$HOTSPOT_INTERFACE managed no
sleep 10
# randomize mac for hotspot interface
echo "\$SICON randomizing MAC for hotspot interface (\$HOTSPOT_INTERFACE)"
ifconfig "\${HOTSPOT_INTERFACE}" down
macchanger -r "\${HOTSPOT_INTERFACE}"
ifconfig "\${HOTSPOT_INTERFACE}" up
# set hotspot interface to monitor mode
echo "\$SICON setting hotspot interface (\$HOTSPOT_INTERFACE) to monitor mode"
ip link set \$HOTSPOT_INTERFACE down
iw dev \$HOTSPOT_INTERFACE set type monitor
rfkill unblock all
ip link set \$HOTSPOT_INTERFACE up
# configure iptables for hotspot interface if needed
if [ "\$BLOCK_CLIENTS" == "y" ]; then
	echo "\$SICON configuring iptables rules for hotspot interface (\$HOTSPOT_INTERFACE)"
	iptables -A INPUT -i \$HOTSPOT_INTERFACE -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
	iptables -A INPUT -i \$HOTSPOT_INTERFACE -j DROP
	ip6tables -A INPUT -i \$HOTSPOT_INTERFACE -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
	ip6tables -A INPUT -i \$HOTSPOT_INTERFACE -j DROP
	# iptables-save > /etc/iptables/rules.v4
	# ip6tables-save > /etc/iptables/rules.v6
fi
# start hotspot
eval "create_ap \$CREATE_AP_ARGS \"\$HOTSPOT_INTERFACE\" \"\$WIFI_INTERFACE\" \"\$HOTSPOT_NAME\" \"\$HOTSPOT_PASSWORD\""
EOF
chown $SUDO_USER:$SUDO_USER $SCRIPTS_FOLDER/start_hotspot.sh
chmod +x $SCRIPTS_FOLDER/start_hotspot.sh

echo ""
echo "##########################"
echo "# Installing Aircrack-NG #"
echo "##########################"
apt-get install -y aircrack-ng

echo ""
echo "##################"
echo "# Installing Tor #"
echo "##################"
apt-get install -y tor jq
systemctl disable tor
systemctl stop tor
cat <<ROUTE_THROUGH_TOR > $SCRIPTS_FOLDER/route_through_tor.sh
#!/bin/bash

set -e

SCRIPT_PATH="\$0"
SCRIPT_PID="\$\$"
# interface we access the internet from
WIFI_INTERFACE="wlan0"
# interface that is our NAT router
ETH_INTERFACE="eth0"
# exclude locals
TOR_EXCLUDE="192.168.0.0/16 172.16.0.0/12 10.0.0.0/8 127.0.0.0/9 127.128.0.0/10"
# tor uid
TOR_USER="debian-tor"
TOR_UID=\$(id -ur \$TOR_USER)
# tor trans port
TOR_PORT="9040"
# tor dns port
TOR_DNS="9053"
# backup dir (create it if it doesn't exist)
BACKUP_DIR="/root/.configs_backup"
# tor virtual address network
TOR_VIRTUAL_ADDRESS_NETWORK="10.192.0.0/10"

help_menu () {
	echo -e "usage:"
	echo -e "\t-h, --help\tshow this menu"
	echo -e "\t-w\twifi interface through which you connect to the internet (default '\$WIFI_INTERFACE')"
	echo -e "\t-e\tethernet interface that acts as NAT router (default '\$ETH_INTERFACE')"
	echo -e ""
	echo -e "examples:"
	echo -e "\tsudo \$SCRIPT_PATH -h"
	echo -e "\tsudo \$SCRIPT_PATH -e eth0 -w wlan1"
}

if [ "\$#" = 0 ]; then
	help_menu
	exit 0
fi

# Iterating over arguments
while test \$# -gt 0
do
	case "\$1" in
		-h|--help) help_menu; exit 0
			;;
		-w) WIFI_INTERFACE="\$2"
			shift 1
			;;
		-e) ETH_INTERFACE="\$2"
			shift 1
			;;
	esac
	shift
done

[ \$EUID -ne 0 ] && echo "run with sudo: 'sudo \$0'" >&2 && exit 1

create_backup_dir () {
	# Creating backup dir
	echo "--> creating backup dir at \$BACKUP_DIR"
	mkdir \$BACKUP_DIR || true
	rm -rf \$BACKUP_DIR/* || true	
}

delete_backup_dir () {
	# Deleting backup dir
	echo "--> deleting backup dir at \$BACKUP_DIR"
	rm -rf \$BACKUP_DIR || true	
}

start_ntp_services () {
	echo "--> starting ntp client services as tor requires a synchronized clock"
	systemctl start systemd-timesyncd.service &>"/dev/null" || true
	systemctl start ntpsec &>"/dev/null" || true
	systemctl start chronyd &>"/dev/null" || true
	for i in \$(seq 10 -1 1); do
		echo -ne "--> waiting \$i seconds for clock to sync\033[0K\r"
		sleep 1
	done
}

stop_ntp_services () {
	echo "--> stopping ntp client services"
	systemctl stop systemd-timesyncd.service &>"/dev/null" || true
	systemctl stop ntpsec &>"/dev/null" || true
	systemctl stop chronyd &>"/dev/null" || true
}

backup_resolv_conf () {
	echo "--> backing up nameservers (/etc/resolv.conf)"
	mv /etc/resolv.conf \$BACKUP_DIR/resolv.conf.bak
}

configure_resolv_conf () {
	echo "--> configuring nameservers (/etc/resolv.conf)"
	cat <<EOF > /etc/resolv.conf
# You can add more name servers if you want
nameserver 127.0.0.1
# Cloudflare DNS
nameserver 1.1.1.1
nameserver 1.0.0.1
# Cisco DNS
nameserver 208.67.222.222
nameserver 208.67.220.220
# Google DNS
nameserver 8.8.8.8
nameserver 8.8.4.4
EOF
	chmod 644 /etc/resolv.conf
}

restore_resolv_conf () {
	echo "--> reconfiguring nameservers (/etc/resolv.conf)"
	mv -f \$BACKUP_DIR/resolv.conf.bak /etc/resolv.conf
}

backup_sysctl () {
	echo "--> backing up sysctl rules"
	sysctl -a >\$BACKUP_DIR/sysctl.conf.bak
}

configure_sysctl () {
	echo "--> activating sysctl net.ipv4.conf.all.route_localnet"
	# Very important to allow us to route localhost traffic
	sysctl -w net.ipv4.conf.all.route_localnet=1 &>"/dev/null"

	echo "--> applying sysctl rules"
	# Disable Explicit Congestion Notification in TCP
	sysctl -w net.ipv4.tcp_ecn=0 &>"/dev/null"
	# window scaling
	sysctl -w net.ipv4.tcp_window_scaling=1 &>"/dev/null"
	# increase linux autotuning tcp buffer limits
	sysctl -w net.ipv4.tcp_rmem="8192 87380 16777216" &>"/dev/null"
	sysctl -w net.ipv4.tcp_wmem="8192 65536 16777216" &>"/dev/null"
	# increase TCP max buffer size
	sysctl -w net.core.rmem_max=16777216 &>"/dev/null"
	sysctl -w net.core.wmem_max=16777216 &>"/dev/null"
	# Increase number of incoming connections backlog
	sysctl -w net.core.netdev_max_backlog=16384 &>"/dev/null"
	sysctl -w net.core.dev_weight=64 &>"/dev/null"
	# Increase number of incoming connections
	sysctl -w net.core.somaxconn=32768 &>"/dev/null"
	# Increase the maximum amount of option memory buffers
	sysctl -w net.core.optmem_max=65535 &>"/dev/null"
	# Increase the tcp-time-wait buckets pool size to prevent simple DOS attacks
	sysctl -w net.ipv4.tcp_max_tw_buckets=1440000 &>"/dev/null"
	# try to reuse time-wait connections, but don't recycle them
	# (recycle can break clients behind NAT)
	sysctl -w net.ipv4.tcp_tw_reuse=1 &>"/dev/null"
	# Limit number of orphans, each orphan can eat up to 16M (max wmem) of unswappable memory
	sysctl -w net.ipv4.tcp_max_orphans=16384 &>"/dev/null"
	sysctl -w net.ipv4.tcp_orphan_retries=0 &>"/dev/null"
	# don't cache ssthresh from previous connection
	sysctl -w net.ipv4.tcp_no_metrics_save=1 &>"/dev/null"
	sysctl -w net.ipv4.tcp_moderate_rcvbuf=1 &>"/dev/null"
	# Increase size of RPC datagram queue length
	sysctl -w net.unix.max_dgram_qlen=50 &>"/dev/null"
	# Don't allow the arp table to become bigger than this
	sysctl -w net.ipv4.neigh.default.gc_thresh3=2048 &>"/dev/null"
	# Tell the gc when to become aggressive with arp table cleaning. Adjust this based on size of the LAN. 1024 is suitable for most /24 networks
	sysctl -w net.ipv4.neigh.default.gc_thresh2=1024 &>"/dev/null"
	# Adjust where the gc will leave arp table alone - set to 32.
	sysctl -w net.ipv4.neigh.default.gc_thresh1=32 &>"/dev/null"
	# Adjust to arp table gc to clean-up more often
	sysctl -w net.ipv4.neigh.default.gc_interval=30 &>"/dev/null"
	# Increase TCP queue length
	sysctl -w net.ipv4.neigh.default.proxy_qlen=96 &>"/dev/null"
	sysctl -w net.ipv4.neigh.default.unres_qlen=6 &>"/dev/null"
	# Enable Explicit Congestion Notification (RFC 3168), disable it if it doesn't work for you
	sysctl -w net.ipv4.tcp_ecn=1 &>"/dev/null"
	sysctl -w net.ipv4.tcp_reordering=3 &>"/dev/null"
	# How many times to retry killing an alive TCP connection
	sysctl -w net.ipv4.tcp_retries2=15 &>"/dev/null"
	sysctl -w net.ipv4.tcp_retries1=3 &>"/dev/null"
	# Avoid falling back to slow start after a connection goes idle
	# Keeps our cwnd large with the keep alive connections (kernel > 3.6)
	sysctl -w net.ipv4.tcp_slow_start_after_idle=0 &>"/dev/null"
	# Allow the TCP fastopen flag to be used, beware some firewalls do not like TFO! (kernel > 3.7)
	sysctl -w net.ipv4.tcp_fastopen=3 &>"/dev/null"
	# This will enusre that immediatly subsequent connections use the new values
	sysctl -w net.ipv4.route.flush=1 &>"/dev/null"
	sysctl -w net.ipv6.route.flush=1 &>"/dev/null"
	# TCP SYN cookie protection
	sysctl -w net.ipv4.tcp_syncookies=1 &>"/dev/null"
	# TCP rfc1337
	sysctl -w net.ipv4.tcp_rfc1337=1 &>"/dev/null"
	# Reverse path filtering
	sysctl -w net.ipv4.conf.default.rp_filter=1 &>"/dev/null"
	sysctl -w net.ipv4.conf.all.rp_filter=1 &>"/dev/null"
	# Log martian packets
	sysctl -w net.ipv4.conf.default.log_martians=1 &>"/dev/null"
	sysctl -w net.ipv4.conf.all.log_martians=1 &>"/dev/null"
	# Disable ICMP redirecting
	sysctl -w net.ipv4.conf.all.accept_redirects=0 &>"/dev/null"
	sysctl -w net.ipv4.conf.default.accept_redirects=0 &>"/dev/null"
	sysctl -w net.ipv4.conf.all.secure_redirects=0 &>"/dev/null"
	sysctl -w net.ipv4.conf.default.secure_redirects=0 &>"/dev/null"
	sysctl -w net.ipv6.conf.all.accept_redirects=0 &>"/dev/null"
	sysctl -w net.ipv6.conf.default.accept_redirects=0 &>"/dev/null"
	sysctl -w net.ipv4.conf.all.send_redirects=0 &>"/dev/null"
	sysctl -w net.ipv4.conf.default.send_redirects=0 &>"/dev/null"
	# Enable Ignoring to ICMP Request
	sysctl -w net.ipv4.icmp_echo_ignore_all=1 &>"/dev/null"

	echo "--> disabling ipv6"
	# Disable IPv6
	sysctl -w net.ipv6.conf.all.disable_ipv6=1 &>"/dev/null"
	sysctl -w net.ipv6.conf.default.disable_ipv6=1 &>"/dev/null"
}

restore_sysctl () {
	echo "--> restoring sysctl rules"
	# Piping to true cause for some reason some stuff doesn't reload properly
	sysctl -p \$BACKUP_DIR/sysctl.conf.bak &>"/dev/null" || true
	rm -f \$BACKUP_DIR/sysctl.conf.bak
}

backup_iptables () {
	echo "--> backing up current iptables rules"
	iptables-save > \$BACKUP_DIR/iptables.rules.bak
	ip6tables-save > \$BACKUP_DIR/ip6tables.rules.bak	
}

clear_iptables () {
	# Flush all iptables rules
	echo "--> clearing all iptables rules"
	iptables -P INPUT ACCEPT
	iptables -P FORWARD ACCEPT
	iptables -P OUTPUT ACCEPT
	iptables -t nat -F
	iptables -t mangle -F
	iptables -t raw -F 
	iptables -F
	iptables -X
	ip6tables -P INPUT ACCEPT
	ip6tables -P FORWARD ACCEPT
	ip6tables -P OUTPUT ACCEPT
	ip6tables -t nat -F
	ip6tables -t mangle -F
	ip6tables -t raw -F
	ip6tables -F
	ip6tables -X
}

configure_iptables () {
	echo "--> applying iptables rules to route local system through tor"
	# set iptables nat
	iptables -t nat -A OUTPUT -m owner --uid-owner \$TOR_UID -j RETURN

	# set dns redirect
	iptables -t nat -A OUTPUT -p udp --dport 53 -j REDIRECT --to-ports \$TOR_DNS
	iptables -t nat -A OUTPUT -p tcp --dport 53 -j REDIRECT --to-ports \$TOR_DNS
	iptables -t nat -A OUTPUT -p udp -m owner --uid-owner \$TOR_UID -m udp --dport 53 -j REDIRECT --to-ports \$TOR_DNS

	# resolve .onion domains mapping \$TOR_VIRTUAL_ADDRESS_NETWORK address space
	iptables -t nat -A OUTPUT -p tcp -d \$TOR_VIRTUAL_ADDRESS_NETWORK -j REDIRECT --to-ports \$TOR_PORT
	iptables -t nat -A OUTPUT -p udp -d \$TOR_VIRTUAL_ADDRESS_NETWORK -j REDIRECT --to-ports \$TOR_PORT

	# exclude locals
	for NET in \$TOR_EXCLUDE; do
		iptables -t nat -A OUTPUT -d \$NET -j RETURN
		iptables -A OUTPUT -d "\$NET" -j ACCEPT
	done

	# redirect all other output through tor
	iptables -t nat -A OUTPUT -p tcp --syn -j REDIRECT --to-ports \$TOR_PORT
	iptables -t nat -A OUTPUT -p udp -j REDIRECT --to-ports \$TOR_PORT
	iptables -t nat -A OUTPUT -p icmp -j REDIRECT --to-ports \$TOR_PORT
	# iptables -t nat -A OUTPUT -p tcp -j DNAT --to-destination 127.0.0.1:\$TOR_PORT
	# iptables -t nat -A OUTPUT -p udp -j DNAT --to-destination 127.0.0.1:\$TOR_PORT
	# iptables -t nat -A OUTPUT -p icmp -j DNAT --to-destination 127.0.0.1:\$TOR_PORT

	# accept already established connections
	iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

	# allow only tor output
	iptables -A OUTPUT -m owner --uid-owner \$TOR_UID -j ACCEPT
	iptables -A OUTPUT -j REJECT

	echo "--> applying iptables rules to route incoming traffic from '\$ETH_INTERFACE' system through tor"
	# route traffic from the ethernet interface to the wifi interface
	for NET in \$TOR_EXCLUDE; do
		iptables -t nat -A PREROUTING -i \$ETH_INTERFACE -d \$NET -j RETURN
	done
	iptables -t nat -A PREROUTING -i \$ETH_INTERFACE -p tcp -j DNAT --to 127.0.0.1:\$TOR_PORT
	iptables -t nat -A PREROUTING -i \$ETH_INTERFACE -p udp -j DNAT --to 127.0.0.1:\$TOR_PORT
	iptables -t nat -A PREROUTING -i \$ETH_INTERFACE -p icmp -j DNAT --to 127.0.0.1:\$TOR_PORT
}

configure_iptables_wifi_interface () {
	echo "--> applying iptables rules to block all input traffic on '\$WIFI_INTERFACE' that is not RELATED/ESTABLISHED so we are not scanned by someone else on our LAN"
	# Blocks all input traffic that is not RELATED/ESTABLISHED so we are not scanned by someone else
	iptables -A INPUT -i \$WIFI_INTERFACE -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
	iptables -A INPUT -i \$WIFI_INTERFACE -j DROP
}

restore_iptables_rules () {
	echo "--> restoring previous iptables rules"
	iptables-restore < \$BACKUP_DIR/iptables.rules.bak
	ip6tables-restore < \$BACKUP_DIR/ip6tables.rules.bak
	rm -f \$BACKUP_DIR/iptables.rules.bak
	rm -f \$BACKUP_DIR/ip6tables.rules.bak
}

create_torrc() {
	echo "--> creating new torrc config in /tmp/torrc"
	cat <<EOF > /tmp/torrc
User \$TOR_USER
DataDirectory /var/lib/tor
VirtualAddrNetwork \$TOR_VIRTUAL_ADDRESS_NETWORK
AutomapHostsOnResolve 1
AutomapHostsSuffixes .exit,.onion
TransPort 127.0.0.1:\$TOR_PORT IsolateClientAddr IsolateSOCKSAuth IsolateClientProtocol IsolateDestPort IsolateDestAddr
SocksPort 127.0.0.1:9050 IsolateClientAddr IsolateSOCKSAuth IsolateClientProtocol IsolateDestPort IsolateDestAddr
ControlPort 9051
HashedControlPassword 16:FDE8ED505C45C8BA602385E2CA5B3250ED00AC0920FEC1230813A1F86F
DNSPort 127.0.0.1:\$TOR_DNS
HardwareAccel 1
TestSocks 1
AllowNonRFC953Hostnames 0
WarnPlaintextPorts 23,109,110,143,80
ClientRejectInternalAddresses 1
NewCircuitPeriod 40
MaxCircuitDirtiness 600
MaxClientCircuitsPending 48
UseEntryGuards 1
EnforceDistinctSubnets 1
EOF
	chmod 644 /tmp/torrc
}

remove_torrc () {
	rm /tmp/torrc
}

start_tor () {
	echo "--> starting tor"
	tor -f /tmp/torrc > /dev/null 2>&1 & 
	for i in \$(seq 10 -1 1); do
		echo -ne "--> waiting \$i seconds for tor to start\033[0K\r"
		sleep 1
	done
}

stop_tor () {
	echo "--> stopping tor"
	# Piping to true cause I think the Ctrl+C already kills the process
	sudo killall tor &>"/dev/null" || true
}

exit_script () {
	echo ""
	# Restore sysctl rules
	restore_sysctl
	# Clear iptables rules
	clear_iptables
	# Restore iptables rules
	restore_iptables_rules
	# Stop tor
	stop_tor
	# Delete torrc file
	remove_torrc
	# Restore /etc/resolv.conf
	restore_resolv_conf
	# Stopping ntp services
	stop_ntp_services
	# Delete backup dir
	delete_backup_dir

	echo "Done"
	# Kill script
	trap - SIGINT SIGTERM
	kill \$SCRIPT_PID
}

echo "This script will route your traffic like so:"
echo " --------     -------"
echo " | RPi5 | --> | TOR | --> Internet"
echo " --------     -------"
read -p "Continue? (Y/N): " confirm && [[ \$confirm == [yY] || \$confirm == [yY][eE] || \$confirm == [yY][eE][sS] ]] || exit 0
echo "Starting..."

# Create backup dir
create_backup_dir

# Start ntp services
start_ntp_services

# Backup /etc/resolv.conf
backup_resolv_conf

# Backup iptables
backup_iptables

# Backup sysctl
backup_sysctl

# Create torrc file
create_torrc

# Configuring name servers
configure_resolv_conf

# Start tor
start_tor

# Clearing iptables rules
clear_iptables

# Setting iptables rules
configure_iptables
configure_iptables_wifi_interface

# Configuring sysctl
configure_sysctl

# Set trap for Ctrl+C
trap exit_script SIGINT SIGTERM

# Endless loop to listen for user input
while true; do
	echo ""
	echo "Done!"
	echo "All traffic exiting from interface '\$WIFI_INTERFACE' is being redirected through tor"
	echo '> Make sure you are secure by visiting these sites:'
	echo '> https://browserleaks.com/'
	echo '> https://bash.ws/my-ip'
	echo '> https://www.dnsleaktest.com/'
	echo '> https://www.deviceinfo.me/'
	echo '> https://mullvad.net/en/check'
	echo '> Check them both from the raspberry pi, and from the hosts that are being routed through the pi, to make sure everything is being routed through tor'
	echo ""
	echo "--> Press 'Enter' to change tor identity (stop and start tor)"
	echo "--> Press 'Ctrl+C' to stop the program and restore previous configurations"
	read -p "> Waiting for input..."
	echo ""
	stop_tor
	sleep 2
	start_tor
	echo ""
done
ROUTE_THROUGH_TOR
chown $SUDO_USER:$SUDO_USER $SCRIPTS_FOLDER/route_through_tor.sh
chmod +x $SCRIPTS_FOLDER/route_through_tor.sh

echo ""
echo "#####################"
echo "# Installing Wifite #"
echo "#####################"
apt-get install -y bully hashcat hcxdumptool hcxtools reaver tshark python3-psycopg2 python3-scapy libpcap-dev libssl-dev
git clone https://github.com/derv82/wifite2.git $TOOL_INSTALL_DIRECTORY/wifite2
chown $SUDO_USER:$SUDO_USER -R $TOOL_INSTALL_DIRECTORY/wifite2/
cat <<EOF > /usr/local/bin/wifite2
#!/bin/bash
# Script to run wifite2 from base dir
cd $TOOL_INSTALL_DIRECTORY/wifite2/
python3 Wifite.py "\$@"
EOF
chmod +x /usr/local/bin/wifite2

echo ""
echo "######################"
echo "# Installing Fluxion #"
echo "######################"
apt-get install -y x11-utils xorg cowpatty lighttpd dsniff mdk4 mdk3 xterm php-cgi hostapd
systemctl disable lighttpd.service
systemctl stop lighttpd.service
systemctl disable hostapd.service
systemctl stop hostapd.service
git clone https://www.github.com/FluxionNetwork/fluxion.git $TOOL_INSTALL_DIRECTORY/fluxion
chown $SUDO_USER:$SUDO_USER -R $TOOL_INSTALL_DIRECTORY/fluxion/
cat <<EOF > /usr/local/bin/fluxion
#!/bin/bash
# Script to run fluxion from base dir
cd $TOOL_INSTALL_DIRECTORY/fluxion/
./fluxion.sh "\$@"
EOF
chmod +x /usr/local/bin/fluxion

echo ""
echo "########################"
echo "# Installing Airgeddon #"
echo "########################"
apt-get update
apt-get install -y bettercap ettercap-graphical tcpdump john crunch tmux
systemctl disable bettercap.service
systemctl stop bettercap.service
git clone --depth 1 https://github.com/v1s1t0r1sh3r3/airgeddon.git $TOOL_INSTALL_DIRECTORY/airgeddon
chown $SUDO_USER:$SUDO_USER -R $TOOL_INSTALL_DIRECTORY/airgeddon/
cat <<EOF > /usr/local/bin/airgeddon
#!/bin/bash
# Script to run airgeddon from base dir
cd $TOOL_INSTALL_DIRECTORY/airgeddon/
./airgeddon.sh "\$@"
EOF
chmod +x /usr/local/bin/airgeddon

echo ""
echo "#####################"
echo "# Installing Kismet #"
echo "#####################"
rm -rfv /usr/local/bin/kismet* /usr/local/share/kismet* /usr/local/etc/kismet*
wget -O - https://www.kismetwireless.net/repos/kismet-release.gpg.key --quiet | gpg --dearmor | tee /usr/share/keyrings/kismet-archive-keyring.gpg >/dev/null
echo 'deb [signed-by=/usr/share/keyrings/kismet-archive-keyring.gpg] https://www.kismetwireless.net/repos/apt/release/bookworm bookworm main' | tee /etc/apt/sources.list.d/kismet.list >/dev/null
apt-get update
apt-get install -y kismet
rm /usr/share/keyrings/kismet-archive-keyring.gpg
rm /etc/apt/sources.list.d/kismet.list
apt-get update

echo ""
echo "#########################"
echo "# Installing AngryOxide #"
echo "#########################"
apt-get install -y jq
CPU_ARCHTIECTURE=$(lscpu | grep Architecture | awk {'print $2'})
json=$(curl -s "https://api.github.com/repos/Ragnt/AngryOxide/releases")
latest_tag=$(echo "$json" | jq -r '.[0].tag_name')
version=$(echo "$latest_tag" | awk -F 'v' '{print $2}')
mkdir $TOOL_INSTALL_DIRECTORY/AngryOxide
wget -O $TOOL_INSTALL_DIRECTORY/AngryOxide/angryoxide-linux-$CPU_ARCHTIECTURE-musl.tar.gz https://github.com/Ragnt/AngryOxide/releases/download/$latest_tag/angryoxide-linux-$CPU_ARCHTIECTURE-musl.tar.gz
cd $TOOL_INSTALL_DIRECTORY/AngryOxide/
tar -xvf angryoxide-linux-$CPU_ARCHTIECTURE-musl.tar.gz
if [[ "$version" < "0.8.5" ]]; then
    sudo mv angryoxide /usr/local/bin/
    COMPLETIONS=$(pkg-config --variable=completionsdir bash-completion)
    sudo mv completions/bash_angryoxide_completions $COMPLETIONS/angryoxide
    rm -rf completions/ angryoxide-linux-$CPU_ARCHTIECTURE-musl.tar.gz
else
    chmod +x install.sh
    sudo ./install.sh install
    rm -rf angryoxide completions/ angryoxide-linux-$CPU_ARCHTIECTURE-musl.tar.gz
fi
rm -rf $TOOL_INSTALL_DIRECTORY/AngryOxide/
cd -

echo ""
echo "########################"
echo "# Installing Responder #"
echo "########################"
apt-get install -y python3-netifaces
git clone https://gitlab.com/kalilinux/packages/responder.git $TOOL_INSTALL_DIRECTORY/responder
chown $SUDO_USER:$SUDO_USER -R $TOOL_INSTALL_DIRECTORY/responder/
cat <<EOF > /usr/local/bin/responder
#!/bin/bash
# Script to run responder from base dir
cd $TOOL_INSTALL_DIRECTORY/responder/
python3 Responder.py "\$@"
EOF
chmod +x /usr/local/bin/responder

echo ""
echo "#######################"
echo "# Installing SSLStrip #"
echo "#######################"
apt-get install -y python3-netifaces python3-twisted python3-openssl python3-cryptography
git clone https://gitlab.com/kalilinux/packages/sslstrip.git $TOOL_INSTALL_DIRECTORY/sslstrip
chown $SUDO_USER:$SUDO_USER -R $TOOL_INSTALL_DIRECTORY/sslstrip/
cat <<EOF > /usr/local/bin/sslstrip
#!/bin/bash
# Script to run sslstrip from base dir
cd $TOOL_INSTALL_DIRECTORY/sslstrip/
python3 sslstrip.py "\$@"
EOF
chmod +x /usr/local/bin/sslstrip

echo ""
echo "##############################"
echo "# Install Mullvad-VPN Client #"
echo "##############################"
# Download the Mullvad signing key
sudo curl -fsSLo /usr/share/keyrings/mullvad-keyring.asc https://repository.mullvad.net/deb/mullvad-keyring.asc
# Add the Mullvad repository server to apt
echo "deb [signed-by=/usr/share/keyrings/mullvad-keyring.asc arch=$( dpkg --print-architecture )] https://repository.mullvad.net/deb/stable $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/mullvad.list
# Update repos and install
apt-get update
apt-get install -y mullvad-vpn
# Remove Mullvad repo and signing key
rm /usr/share/keyrings/mullvad-keyring.asc
rm /etc/apt/sources.list.d/mullvad.list
# Updating again
apt-get update
cat <<TOR_OVER_VPN > $SCRIPTS_FOLDER/tor_over_vpn.sh
#!/bin/bash

set -e

SCRIPT_PATH="\$0"
# interface we access the internet from
WIFI_INTERFACE="wlan0"
# interface that is our NAT router
ETH_INTERFACE="eth0"
# exclude locals
TOR_EXCLUDE="192.168.0.0/16 172.16.0.0/12 10.0.0.0/8 127.0.0.0/9 127.128.0.0/10"
# tor uid
TOR_USER="debian-tor"
TOR_UID=\$(id -ur \$TOR_USER)
# tor trans port
TOR_PORT="9040"
# tor dns port
TOR_DNS="9053"
# backup dir (create it if it doesn't exist)
BACKUP_DIR="/root/.configs_backup"
# tor virtual address network
TOR_VIRTUAL_ADDRESS_NETWORK="10.192.0.0/10"
# For later use in the script
CURRENT_NET_PATH="vpn"

help_menu () {
	echo -e "usage:"
	echo -e "\t-h, --help\tshow this menu"
	echo -e "\t-w\twifi interface through which you connect to the internet, NOT the VPN interface (default '\$WIFI_INTERFACE')"
	echo -e "\t-e\tethernet interface that acts as NAT router (default '\$ETH_INTERFACE')"
	echo -e ""
	echo -e "examples:"
	echo -e "\tsudo \$SCRIPT_PATH -h"
	echo -e "\tsudo \$SCRIPT_PATH -e eth0 -w wlan1"
}

if [ "\$#" = 0 ]; then
	help_menu
	exit 0
fi

# Iterating over arguments
while test \$# -gt 0
do
	case "\$1" in
		-h|--help) help_menu; exit 0
			;;
		-w) WIFI_INTERFACE="\$2"
			shift 1
			;;
		-e) ETH_INTERFACE="\$2"
			shift 1
			;;
	esac
	shift
done

[ \$EUID -ne 0 ] && echo "run with sudo: 'sudo \$0'" >&2 && exit 1

create_backup_dir () {
	# Creating backup dir
	echo "--> creating backup dir at \$BACKUP_DIR"
	mkdir \$BACKUP_DIR || true
	rm -rf \$BACKUP_DIR/* || true	
}

delete_backup_dir () {
	# Deleting backup dir
	echo "--> deleting backup dir at \$BACKUP_DIR"
	rm -rf \$BACKUP_DIR || true	
}

start_ntp_services () {
	echo "--> starting ntp client services to have a synchronized clock"
	systemctl start systemd-timesyncd.service &>"/dev/null" || true
	systemctl start ntpsec &>"/dev/null" || true
	systemctl start chronyd &>"/dev/null" || true
	for i in \$(seq 10 -1 1); do
		echo -ne "--> waiting \$i seconds for clock to sync\033[0K\r"
		sleep 1
	done
}

stop_ntp_services () {
	echo "--> stopping ntp client services"
	systemctl stop systemd-timesyncd.service &>"/dev/null" || true
	systemctl stop ntpsec &>"/dev/null" || true
	systemctl stop chronyd &>"/dev/null" || true
}

backup_resolv_conf () {
	echo "--> backing up nameservers (/etc/resolv.conf)"
	cp -f /etc/resolv.conf \$BACKUP_DIR/resolv.conf.bak
}

configure_resolv_conf () {
	echo "--> configuring nameservers (/etc/resolv.conf)"
	cat <<EOF > /etc/resolv.conf
# You can add more name servers if you want
nameserver 127.0.0.1
# Cloudflare DNS
nameserver 1.1.1.1
nameserver 1.0.0.1
# Cisco DNS
nameserver 208.67.222.222
nameserver 208.67.220.220
# Google DNS
nameserver 8.8.8.8
nameserver 8.8.4.4
EOF
	chmod 644 /etc/resolv.conf
}

restore_resolv_conf () {
	echo "--> reconfiguring nameservers (/etc/resolv.conf)"
	cp -f \$BACKUP_DIR/resolv.conf.bak /etc/resolv.conf
}

backup_sysctl () {
	echo "--> backing up sysctl rules"
	sysctl -a >\$BACKUP_DIR/sysctl.conf.bak
}

configure_sysctl () {
	echo "--> activating sysctl net.ipv4.conf.all.route_localnet"
	# Very important to allow us to route localhost traffic
	sysctl -w net.ipv4.conf.all.route_localnet=1 &>"/dev/null"

	echo "--> applying sysctl rules"
	# Disable Explicit Congestion Notification in TCP
	sysctl -w net.ipv4.tcp_ecn=0 &>"/dev/null"
	# window scaling
	sysctl -w net.ipv4.tcp_window_scaling=1 &>"/dev/null"
	# increase linux autotuning tcp buffer limits
	sysctl -w net.ipv4.tcp_rmem="8192 87380 16777216" &>"/dev/null"
	sysctl -w net.ipv4.tcp_wmem="8192 65536 16777216" &>"/dev/null"
	# increase TCP max buffer size
	sysctl -w net.core.rmem_max=16777216 &>"/dev/null"
	sysctl -w net.core.wmem_max=16777216 &>"/dev/null"
	# Increase number of incoming connections backlog
	sysctl -w net.core.netdev_max_backlog=16384 &>"/dev/null"
	sysctl -w net.core.dev_weight=64 &>"/dev/null"
	# Increase number of incoming connections
	sysctl -w net.core.somaxconn=32768 &>"/dev/null"
	# Increase the maximum amount of option memory buffers
	sysctl -w net.core.optmem_max=65535 &>"/dev/null"
	# Increase the tcp-time-wait buckets pool size to prevent simple DOS attacks
	sysctl -w net.ipv4.tcp_max_tw_buckets=1440000 &>"/dev/null"
	# try to reuse time-wait connections, but don't recycle them
	# (recycle can break clients behind NAT)
	sysctl -w net.ipv4.tcp_tw_reuse=1 &>"/dev/null"
	# Limit number of orphans, each orphan can eat up to 16M (max wmem) of unswappable memory
	sysctl -w net.ipv4.tcp_max_orphans=16384 &>"/dev/null"
	sysctl -w net.ipv4.tcp_orphan_retries=0 &>"/dev/null"
	# don't cache ssthresh from previous connection
	sysctl -w net.ipv4.tcp_no_metrics_save=1 &>"/dev/null"
	sysctl -w net.ipv4.tcp_moderate_rcvbuf=1 &>"/dev/null"
	# Increase size of RPC datagram queue length
	sysctl -w net.unix.max_dgram_qlen=50 &>"/dev/null"
	# Don't allow the arp table to become bigger than this
	sysctl -w net.ipv4.neigh.default.gc_thresh3=2048 &>"/dev/null"
	# Tell the gc when to become aggressive with arp table cleaning. Adjust this based on size of the LAN. 1024 is suitable for most /24 networks
	sysctl -w net.ipv4.neigh.default.gc_thresh2=1024 &>"/dev/null"
	# Adjust where the gc will leave arp table alone - set to 32.
	sysctl -w net.ipv4.neigh.default.gc_thresh1=32 &>"/dev/null"
	# Adjust to arp table gc to clean-up more often
	sysctl -w net.ipv4.neigh.default.gc_interval=30 &>"/dev/null"
	# Increase TCP queue length
	sysctl -w net.ipv4.neigh.default.proxy_qlen=96 &>"/dev/null"
	sysctl -w net.ipv4.neigh.default.unres_qlen=6 &>"/dev/null"
	# Enable Explicit Congestion Notification (RFC 3168), disable it if it doesn't work for you
	sysctl -w net.ipv4.tcp_ecn=1 &>"/dev/null"
	sysctl -w net.ipv4.tcp_reordering=3 &>"/dev/null"
	# How many times to retry killing an alive TCP connection
	sysctl -w net.ipv4.tcp_retries2=15 &>"/dev/null"
	sysctl -w net.ipv4.tcp_retries1=3 &>"/dev/null"
	# Avoid falling back to slow start after a connection goes idle
	# Keeps our cwnd large with the keep alive connections (kernel > 3.6)
	sysctl -w net.ipv4.tcp_slow_start_after_idle=0 &>"/dev/null"
	# Allow the TCP fastopen flag to be used, beware some firewalls do not like TFO! (kernel > 3.7)
	sysctl -w net.ipv4.tcp_fastopen=3 &>"/dev/null"
	# This will enusre that immediatly subsequent connections use the new values
	sysctl -w net.ipv4.route.flush=1 &>"/dev/null"
	sysctl -w net.ipv6.route.flush=1 &>"/dev/null"
	# TCP SYN cookie protection
	sysctl -w net.ipv4.tcp_syncookies=1 &>"/dev/null"
	# TCP rfc1337
	sysctl -w net.ipv4.tcp_rfc1337=1 &>"/dev/null"
	# Reverse path filtering
	sysctl -w net.ipv4.conf.default.rp_filter=1 &>"/dev/null"
	sysctl -w net.ipv4.conf.all.rp_filter=1 &>"/dev/null"
	# Log martian packets
	sysctl -w net.ipv4.conf.default.log_martians=1 &>"/dev/null"
	sysctl -w net.ipv4.conf.all.log_martians=1 &>"/dev/null"
	# Disable ICMP redirecting
	sysctl -w net.ipv4.conf.all.accept_redirects=0 &>"/dev/null"
	sysctl -w net.ipv4.conf.default.accept_redirects=0 &>"/dev/null"
	sysctl -w net.ipv4.conf.all.secure_redirects=0 &>"/dev/null"
	sysctl -w net.ipv4.conf.default.secure_redirects=0 &>"/dev/null"
	sysctl -w net.ipv6.conf.all.accept_redirects=0 &>"/dev/null"
	sysctl -w net.ipv6.conf.default.accept_redirects=0 &>"/dev/null"
	sysctl -w net.ipv4.conf.all.send_redirects=0 &>"/dev/null"
	sysctl -w net.ipv4.conf.default.send_redirects=0 &>"/dev/null"
	# Enable Ignoring to ICMP Request
	sysctl -w net.ipv4.icmp_echo_ignore_all=1 &>"/dev/null"

	echo "--> disabling ipv6"
	# Disable IPv6
	sysctl -w net.ipv6.conf.all.disable_ipv6=1 &>"/dev/null"
	sysctl -w net.ipv6.conf.default.disable_ipv6=1 &>"/dev/null"
}

restore_sysctl () {
	echo "--> restoring sysctl rules"
	# Piping to true cause for some reason some stuff doesn't reload properly
	sysctl -p \$BACKUP_DIR/sysctl.conf.bak &>"/dev/null" || true
	rm -f \$BACKUP_DIR/sysctl.conf.bak
}

backup_iptables () {
	echo "--> backing up current iptables rules"
	iptables-save > \$BACKUP_DIR/iptables.rules.bak
	ip6tables-save > \$BACKUP_DIR/ip6tables.rules.bak	
}

clear_iptables () {
	# Flush all iptables rules
	echo "--> clearing all iptables rules"
	iptables -P INPUT ACCEPT
	iptables -P FORWARD ACCEPT
	iptables -P OUTPUT ACCEPT
	iptables -t nat -F
	iptables -t mangle -F
	iptables -t raw -F 
	iptables -F
	iptables -X
	ip6tables -P INPUT ACCEPT
	ip6tables -P FORWARD ACCEPT
	ip6tables -P OUTPUT ACCEPT
	ip6tables -t nat -F
	ip6tables -t mangle -F
	ip6tables -t raw -F
	ip6tables -F
	ip6tables -X
}

configure_iptables () {
	echo "--> applying iptables rules to route local system through tor"
	# set iptables nat
	iptables -t nat -A OUTPUT -m owner --uid-owner \$TOR_UID -j RETURN

	# set dns redirect
	iptables -t nat -A OUTPUT -p udp --dport 53 -j REDIRECT --to-ports \$TOR_DNS
	iptables -t nat -A OUTPUT -p tcp --dport 53 -j REDIRECT --to-ports \$TOR_DNS
	iptables -t nat -A OUTPUT -p udp -m owner --uid-owner \$TOR_UID -m udp --dport 53 -j REDIRECT --to-ports \$TOR_DNS

	# resolve .onion domains mapping \$TOR_VIRTUAL_ADDRESS_NETWORK address space
	iptables -t nat -A OUTPUT -p tcp -d \$TOR_VIRTUAL_ADDRESS_NETWORK -j REDIRECT --to-ports \$TOR_PORT
	iptables -t nat -A OUTPUT -p udp -d \$TOR_VIRTUAL_ADDRESS_NETWORK -j REDIRECT --to-ports \$TOR_PORT

	# exclude locals
	for NET in \$TOR_EXCLUDE; do
		iptables -t nat -A OUTPUT -d \$NET -j RETURN
		iptables -A OUTPUT -d "\$NET" -j ACCEPT
	done

	# redirect all other output through tor
	iptables -t nat -A OUTPUT -p tcp --syn -j REDIRECT --to-ports \$TOR_PORT
	iptables -t nat -A OUTPUT -p udp -j REDIRECT --to-ports \$TOR_PORT
	iptables -t nat -A OUTPUT -p icmp -j REDIRECT --to-ports \$TOR_PORT
	# iptables -t nat -A OUTPUT -p tcp -j DNAT --to-destination 127.0.0.1:\$TOR_PORT
	# iptables -t nat -A OUTPUT -p udp -j DNAT --to-destination 127.0.0.1:\$TOR_PORT
	# iptables -t nat -A OUTPUT -p icmp -j DNAT --to-destination 127.0.0.1:\$TOR_PORT

	# accept already established connections
	iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

	# allow only tor output
	iptables -A OUTPUT -m owner --uid-owner \$TOR_UID -j ACCEPT
	iptables -A OUTPUT -j REJECT

	echo "--> applying iptables rules to route incoming traffic from '\$ETH_INTERFACE' system through tor"
	# route traffic from the ethernet interface to the wifi interface
	for NET in \$TOR_EXCLUDE; do
		iptables -t nat -A PREROUTING -i \$ETH_INTERFACE -d \$NET -j RETURN
	done
	iptables -t nat -A PREROUTING -i \$ETH_INTERFACE -p tcp -j DNAT --to 127.0.0.1:\$TOR_PORT
	iptables -t nat -A PREROUTING -i \$ETH_INTERFACE -p udp -j DNAT --to 127.0.0.1:\$TOR_PORT
	iptables -t nat -A PREROUTING -i \$ETH_INTERFACE -p icmp -j DNAT --to 127.0.0.1:\$TOR_PORT
}

configure_iptables_wifi_interface () {
	echo "--> applying iptables rules to block all input traffic on '\$WIFI_INTERFACE' that is not RELATED/ESTABLISHED so we are not scanned by someone else on our LAN"
	# Blocks all input traffic that is not RELATED/ESTABLISHED so we are not scanned by someone else
	iptables -A INPUT -i \$WIFI_INTERFACE -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
	iptables -A INPUT -i \$WIFI_INTERFACE -j DROP
}

restore_iptables_rules () {
	echo "--> restoring previous iptables rules"
	iptables-restore < \$BACKUP_DIR/iptables.rules.bak
	ip6tables-restore < \$BACKUP_DIR/ip6tables.rules.bak
}

create_torrc() {
	echo "--> creating new torrc config in /tmp/torrc"
	cat <<EOF > /tmp/torrc
User \$TOR_USER
DataDirectory /var/lib/tor
VirtualAddrNetwork \$TOR_VIRTUAL_ADDRESS_NETWORK
AutomapHostsOnResolve 1
AutomapHostsSuffixes .exit,.onion
TransPort 127.0.0.1:\$TOR_PORT IsolateClientAddr IsolateSOCKSAuth IsolateClientProtocol IsolateDestPort IsolateDestAddr
SocksPort 127.0.0.1:9050 IsolateClientAddr IsolateSOCKSAuth IsolateClientProtocol IsolateDestPort IsolateDestAddr
ControlPort 9051
HashedControlPassword 16:FDE8ED505C45C8BA602385E2CA5B3250ED00AC0920FEC1230813A1F86F
DNSPort 127.0.0.1:\$TOR_DNS
HardwareAccel 1
TestSocks 1
AllowNonRFC953Hostnames 0
WarnPlaintextPorts 23,109,110,143,80
ClientRejectInternalAddresses 1
NewCircuitPeriod 40
MaxCircuitDirtiness 600
MaxClientCircuitsPending 48
UseEntryGuards 1
EnforceDistinctSubnets 1
EOF
	chmod 644 /tmp/torrc
}

remove_torrc () {
	rm /tmp/torrc
}

start_tor () {
	echo "--> starting tor"
	tor -f /tmp/torrc > /dev/null 2>&1 & 
	for i in \$(seq 10 -1 1); do
		echo -ne "--> waiting \$i seconds for tor to start\033[0K\r"
		sleep 1
	done
}

stop_tor () {
	echo "--> stopping tor"
	sudo killall tor &>"/dev/null" || true
}


echo "This script will allow you to route your traffic like so:"
echo " --------     -------     -------"
echo " | RPi5 | --> | VPN | --> | TOR | --> Internet"
echo " --------     -------     -------"
read -p "Continue? (Y/N): " confirm && [[ \$confirm == [yY] || \$confirm == [yY][eE] || \$confirm == [yY][eE][sS] ]] || exit 0
echo ""
echo "--> Enabling 'Local network sharing'"
echo "> Open mullvad-gui app and turn on 'Settings --> VPN Settings --> Local network sharing'"
echo "> DO NOT activate the VPN yet (we will do this later) - disconnect from VPN if you are currently connected"
echo "> Turning on 'Local network sharing' will allow clients connected to '\$ETH_INTERFACE' to maintain their connection to the raspberry pi, and have all their traffic be routed through the VPN as well"
echo "> If you don't use Mullvad VPN, check if there is a similiar feature for your VPN (this could probably also be done manually via iptables)"
echo ""
read -p "> Have you finished configuring the VPN? (Y/N): " confirm && [[ \$confirm == [yY] || \$confirm == [yY][eE] || \$confirm == [yY][eE][sS] ]] || exit 0
echo "> Great!"
echo ""

# Create backup dir
create_backup_dir

# Start ntp services
start_ntp_services

# Backup iptables
backup_iptables

# Backup sysctl
backup_sysctl

# Create torrc file
create_torrc

# Configuring sysctl
configure_sysctl

# Request user to connect to vpn
echo ""
echo "> Please connect to your VPN"
read -p "Press 'Enter' after you have connected to your VPN"

echo "Initial setup is done!"
sleep 3

# Endless loop to listen for user input
while true; do
	clear
	echo "Current network path is:"
	if [ "\$CURRENT_NET_PATH" = "vpn" ]; then
		echo " --------     -------"
		echo " | RPi5 | --> | VPN | --> Internet"
		echo " --------     -------"	
	fi
	if [ "\$CURRENT_NET_PATH" = "tor" ]; then
		echo " --------     -------     -------"
		echo " | RPi5 | --> | VPN | --> | TOR | --> Internet"
		echo " --------     -------     -------"	
	fi
	echo ""
	echo "DO NOT DISCONNECT FROM VPN WHILE BEING ROUTED THROUGH TOR"
	echo "> If you want to change your VPN server, first STOP routing through TOR (select option in the menu below), change your VPN server, and only then route through TOR again (select option in the menu below)."
	echo "> If not done in this order, the new VPN connection being made when changing your VPN server will be done over TOR, resulting in unwanted 'TOR --> VPN'"
	echo ""
	echo '> Make sure you are secure by visiting these sites:'
	echo '> https://browserleaks.com/'
	echo '> https://bash.ws/my-ip'
	echo '> https://www.dnsleaktest.com/'
	echo '> https://www.deviceinfo.me/'
	echo '> https://mullvad.net/en/check'
	echo '> Check them both from the raspberry pi, and from the hosts that are being routed through the pi, to make sure everything is being routed through tor'
	echo ""
	echo "Menu:"
	if [ "\$CURRENT_NET_PATH" = "vpn" ]; then
		echo "1) Route through TOR"
		echo "2) Restore changes and exit"
		read -p "> " selection
		if [ "\$selection" = "1" ]; then
			echo "Routing system through TOR"
			# Backup /etc/resolv.conf
			backup_resolv_conf
			# Configuring name servers
			configure_resolv_conf
			# Clearing iptables rules
			clear_iptables
			# Start tor
			start_tor
			# Setting iptables rules
			configure_iptables
			configure_iptables_wifi_interface
			CURRENT_NET_PATH="tor"
			continue
		fi
		if [ "\$selection" = "2" ]; then
			break
		fi
	fi
	if [ "\$CURRENT_NET_PATH" = "tor" ]; then
		echo "1) Change TOR identity (stop and start tor)"
		echo "2) Stop routing through TOR"
		echo "3) Stop routing through TOR, restore changes and exit"
		read -p "> " selection
		if [ "\$selection" = "1" ]; then
			echo ""
			echo "Changing TOR identity"
			stop_tor
			# Configuring name servers
			configure_resolv_conf
			sleep 2
			start_tor
			echo ""
			continue
		fi
		if [ "\$selection" = "2" ]; then
			echo ""
			echo "Stopping TOR"
			# Clearing iptables rules
			clear_iptables
			restore_iptables_rules
			stop_tor
			# Restore /etc/resolv.conf
			restore_resolv_conf
			CURRENT_NET_PATH="vpn"
			continue
		fi
		if [ "\$selection" = "3" ]; then
			break
		fi
	fi
	echo "Invalid selection"
done

echo ""
# Restore sysctl rules
restore_sysctl
# Clear iptables rules
clear_iptables
# Restore iptables rules
restore_iptables_rules
# Stop tor
stop_tor
# Delete torrc file
remove_torrc
# Restore /etc/resolv.conf
restore_resolv_conf
# Stopping ntp services
stop_ntp_services
# Delete backup dir
delete_backup_dir

echo "Done"
TOR_OVER_VPN
chown $SUDO_USER:$SUDO_USER $SCRIPTS_FOLDER/tor_over_vpn.sh
chmod +x $SCRIPTS_FOLDER/tor_over_vpn.sh

echo ""
echo "#################################"
echo "# Removing Unnecessary Packages #"
echo "#################################"
apt-get autoremove -y

echo ""
echo "######################"
echo "# Disable NTP Client #"
echo "######################"
systemctl disable systemd-timesyncd.service || true
systemctl stop systemd-timesyncd.service || true
systemctl disable ntpsec || true
systemctl stop ntpsec || true
systemctl disable chronyd || true
systemctl stop chronyd || true

echo ""
echo "##########################"
echo "# Rebooting in 5 Seconds #"
echo "##########################"
echo "5"; sleep 1
echo "4"; sleep 1
echo "3"; sleep 1
echo "2"; sleep 1
echo "1"; sleep 1
echo "reboot"
reboot
