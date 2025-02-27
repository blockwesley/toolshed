#!/bin/bash
# IPv4 IPTABLES Script

IPTABLESCMD="/usr/sbin/iptables"
IP6TABLESCMD="/usr/sbin/ip6tables"

#IFCMD="ip link list | awk '{print $2}' | sed -E "s/([[:xdigit:]]{1,2}:){5}[[:xdigit:]]{1,2}//" | sed s/://"
BLOCKLIST="blockedip" 
DROPMSG="BLOCKED IP DROP" 
BLOCKEDIPLOG="/usr/firewall/blocked_ips.txt"
INTERFACE="eth0"
MY_ISP_SUPERNET=

#Method to create blocked ip log file if none exist
if [ -f "${BLOCKEDIPLOG}" ];
then
	echo "Blocked IP Log File Exists"
	echo "Blocking the following IP Addresses"
	cat $BLOCKEDIPLOG | egrep -v -E "^#|^$"
else
	echo "No blocked IP Log File Exists - Creating file..."
	mkdir /etc/firewall &> /dev/null 2> /dev/null
	$BLOCKEDIPLOG &> /dev/null 2> /dev/null
fi

echo "Starting IPv4 Firewall..." 

# Flush the Firewlal and delete the nat and mangle tables.
$IPTABLESCMD -F
$IPTABLESCMD -X
$IPTABLESCMD -t nat -F
$IPTABLESCMD -t nat -X
$IPTABLESCMD -t mangle -F
$IPTABLESCMD -t mangle -X

#Load Connection Tracking Kernel Module
modprobe ip_conntrack

#Allow unrestricted loopback traffic
$IPTABLESCMD -A INPUT -i lo -j ACCEPT
$IPTABLESCMD -A OUTPUT -o lo -j ACCEPT

#Set the Policy to drop all incoming packet
$IPTABLESCMD -P INPUT DROP 
$IPTABLESCMD -P OUTPUT DROP 
$IPTABLESCMD -P FORWARD DROP 
###
### DYNAMIC BLOCK LIST
### 

#Check if blocked IP Log file exists, and pull a list of blocked IPs to create rules to drop
[ -f "$BLOCKEDIPLOG" ] && BADIPS=$(egrep -v -E "^#|^$" "${BLOCKEDIPLOG}")

#Create a new IPTABLE for blocked IPS and add each one to the rule - dropping them
if [ -f "${BLOCKEDIPLOG}" ]; 
	then 
	$IPTABLESCMD -N $BLOCKLIST 
	for ipblock in $BADIPS 
		do 
		$IPTABLESCMD -A $BLOCKLIST -s $ipblock -j LOG --log-prefix "$DROPMSG" 
		$IPTABLESCMD -A $BLOCKLIST -s $ipblock -j DROP 
		done 
	$IPTABLESCMD -I INPUT -j $BLOCKLIST 
	$IPTABLESCMD -I OUTPUT -j $BLOCKLIST 
	$IPTABLESCMD -I FORWARD -j $BLOCKLIST 
fi 

# 
#####################################  DEFAULT DEFENSIVE LINE  #################################################### 
# 


# Block sync 
$IPTABLESCMD -A INPUT -i ${INTERFACE} -p tcp ! --syn -m state --state NEW  -m limit --limit 5/m --limit-burst 7 -j LOG --log-level 4 --log-prefix "Drop Sync:" 
$IPTABLESCMD -A INPUT -i ${INTERFACE} -p tcp ! --syn -m state --state NEW -j DROP 

# Block Fragments
$IPTABLESCMD -A INPUT -i ${INTERFACE} -f  -m limit --limit 5/m --limit-burst 7 -j LOG --log-level 4 --log-prefix "Fragments Packets:" 
$IPTABLESCMD -A INPUT -i ${INTERFACE} -f -j DROP 

# Block bad stuff 
$IPTABLESCMD  -A INPUT -i ${INTERFACE} -p tcp --tcp-flags ALL FIN,URG,PSH -j DROP 
$IPTABLESCMD  -A INPUT -i ${INTERFACE} -p tcp --tcp-flags ALL ALL -j DROP 
$IPTABLESCMD  -A INPUT -i ${INTERFACE} -p tcp --tcp-flags ALL NONE -m limit --limit 5/m --limit-burst 7 -j LOG --log-level 4 --log-prefix "NULL Packets:" 
$IPTABLESCMD  -A INPUT -i ${INTERFACE} -p tcp --tcp-flags ALL NONE -j DROP # NULL packets 
$IPTABLESCMD  -A INPUT -i ${INTERFACE} -p tcp --tcp-flags SYN,RST SYN,RST -j DROP 
$IPTABLESCMD  -A INPUT -i ${INTERFACE} -p tcp --tcp-flags SYN,FIN SYN,FIN -m limit --limit 5/m --limit-burst 7 -j LOG --log-level 4 --log-prefix "XMAS Packets:" 
$IPTABLESCMD  -A INPUT -i ${INTERFACE} -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP #XMAS 
$IPTABLESCMD  -A INPUT -i ${INTERFACE} -p tcp --tcp-flags FIN,ACK FIN -m limit --limit 5/m --limit-burst 7 -j LOG --log-level 4 --log-prefix "Fin Packets Scan:" 
$IPTABLESCMD  -A INPUT -i ${INTERFACE} -p tcp --tcp-flags FIN,ACK FIN -j DROP # FIN packet scans 
$IPTABLESCMD  -A INPUT -i ${INTERFACE} -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP 

# Drop invalid packets immediately
$IPTABLESCMD -A INPUT   -m state --state INVALID -j DROP
$IPTABLESCMD -A FORWARD -m state --state INVALID -j DROP
$IPTABLESCMD -A OUTPUT  -m state --state INVALID -j DROP

# Drop bogus TCP packets
$IPTABLESCMD -A INPUT -p tcp -m tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
$IPTABLESCMD -A INPUT -p tcp -m tcp --tcp-flags SYN,RST SYN,RST -j DROP

# Drop packets from RFC1918 class networks (i.e., spoofed)

$IPTABLESCMD -A INPUT -s 10.0.0.0/8     -j DROP
$IPTABLESCMD -A INPUT -s 169.254.0.0/16 -j DROP
$IPTABLESCMD -A INPUT -s 172.16.0.0/12  -j DROP
$IPTABLESCMD -A INPUT -s 127.0.0.0/8    -j DROP
$IPTABLESCMD -A INPUT -s 224.0.0.0/4      -j DROP
$IPTABLESCMD -A INPUT -s 240.0.0.0/5      -j DROP
$IPTABLESCMD -A INPUT -s 0.0.0.0/8        -j DROP
$IPTABLESCMD -A INPUT -d 224.0.0.0/4      -j DROP
$IPTABLESCMD -A INPUT -d 240.0.0.0/5      -j DROP
$IPTABLESCMD -A INPUT -d 0.0.0.0/8        -j DROP
$IPTABLESCMD -A INPUT -d 239.255.255.0/24 -j DROP
$IPTABLESCMD -A INPUT -d 255.255.255.255  -j DROP

# 
#####################################  ADVANCED DEFENSIVE LINE  #################################################### 
# 

# Drop excessive RST packets to avoid SMURF attacks, by given the 
# next real data packet in the sequence a better chance to arrive first. 
$IPTABLESCMD -A INPUT -p tcp -m tcp --tcp-flags RST RST -m limit --limit 2/second --limit-burst 2 -j ACCEPT 
#
# Protect against SYN floods by rate limiting the number of new 
# connections from any host to 60 per second.  This does *not* do rate 
# limiting overall, because then someone could easily shut us down by 
# saturating the limit. 
$IPTABLESCMD -A INPUT -m state --state NEW -p tcp -m tcp --syn -m recent --name synflood --set 
$IPTABLESCMD -A INPUT -m state --state NEW -p tcp -m tcp --syn -m recent --name synflood --update --seconds 1 --hitcount 20 -j DROP 

# Anyone who tried to portscan us is locked out for an entire day. 
$IPTABLESCMD -A INPUT   -m recent --name portscan --rcheck --seconds 86400 -j DROP 
$IPTABLESCMD -A FORWARD -m recent --name portscan --rcheck --seconds 86400 -j DROP 
# Once the day has passed, remove them from the portscan list 
$IPTABLESCMD -A INPUT   -m recent --name portscan --remove 
$IPTABLESCMD -A FORWARD -m recent --name portscan --remove 

# These rules add scanners to the portscan list, and log the attempt. 
$IPTABLESCMD -A INPUT   -p tcp -m tcp --dport 139 -m recent --name portscan --set -j LOG --log-prefix "Portscan:" 
$IPTABLESCMD -A INPUT   -p tcp -m tcp --dport 139 -m recent --name portscan --set -j DROP 
$IPTABLESCMD -A FORWARD -p tcp -m tcp --dport 139 -m recent --name portscan --set -j LOG --log-prefix "Portscan:" 
$IPTABLESCMD -A FORWARD -p tcp -m tcp --dport 139 -m recent --name portscan --set -j DROP 
# 
#####################################  OUTBOUND CONNECTION REQUIREMENTS BEGIN  #################################################### 
# 

# Allow full outgoing connection but no incomming stuff 
$IPTABLESCMD -A INPUT -i ${INTERFACE} -m state --state ESTABLISHED,RELATED -j ACCEPT 
$IPTABLESCMD -A OUTPUT -o ${INTERFACE} -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT 

# 
#####################################  ICMP MESSAGE STUFF  #################################################### 
# 
# allow incoming 
$IPTABLESCMD -A INPUT -i ${INTERFACE} -p icmp --icmp-type 8 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT 
$IPTABLESCMD -A OUTPUT -o ${INTERFACE} -p icmp --icmp-type 0 -m state --state ESTABLISHED,RELATED -j ACCEPT 

# Allow most ICMP packets to be received (so people can check our 
# presence), but restrict the flow to avoid ping flood attacks 
$IPTABLESCMD -A INPUT -p icmp -m icmp --icmp-type 17 -j DROP 
$IPTABLESCMD -A INPUT -p icmp -m icmp --icmp-type 13 -j DROP
$IPTABLESCMD -A INPUT -p icmp -m icmp --icmp-type any -m limit --limit 1/second -j ACCEPT  

# 
#####################################  SPECIFIC INCOMING AND OUTGOING SERVICE PROVISION START  #################################################### 
# 
# Allow ssh from only my ISP broadband providers networks
#$IPTABLESCMD -A INPUT -i ${INTERFACE} -s ${MY_ISP_SUPERNET} -p tcp --destination-port 22 -j ACCEPT 
#$IPTABLESCMD -A INPUT -i ${INTERFACE} -s ${MY_ISP_SUPERNET} -p tcp --destination-port 8080 -j ACCEPT


# Allow http / https (open port 80 / 443) 
# $IPTABLESCMD -A INPUT -i ${INTERFACE} -p tcp --destination-port 80 -j ACCEPT 

# #Enable Samba Server
# echo "Enabling Samba"
# $IPTABLESCMD -A INPUT -p udp -m state --state NEW -m udp --dport 137 -j ACCEPT
# $IPTABLESCMD -A INPUT -p udp -m state --state NEW -m udp --dport 138 -j ACCEPT
# $IPTABLESCMD -A INPUT -p tcp -m state --state NEW -m tcp --dport 139 -j ACCEPT
# $IPTABLESCMD -A INPUT -p tcp -m state --state NEW -m tcp --dport 445 -j ACCEPT 

# 
#####################################  LOG AND DROP ALL REMAINING UNMATCHED  #################################################### 
# 
$IPTABLESCMD -A INPUT -j LOG 
$IPTABLESCMD -A FORWARD -j LOG
$IPTABLESCMD -A INPUT -j DROP 
$IPTABLESCMD -A FORWARD -j DROP

exit 0 

