#!/bin/sh
# IPtables/Netfilter script

# Flush tables before applying changes
iptables -F

# Default policy; 
iptables -P FORWARD 	ACCEPT
iptables -P OUTPUT	ACCEPT
iptables -P INPUT	DROP

# Allow cyber range VM communications
iptables -A INPUT -i eth0 -p tcp --dport 3389 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -o eth0 -p tcp --dport 3389 -m state --state ESTABLISHED -j ACCEPT
iptables -I INPUT -p udp -j ACCEPT
iptables -I INPUT -p icmp -j ACCEPT
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

#----------------DON'T MAKE CHANGES ABOVE THIS LINE---------------------

# Add your firewall rules here . . .

