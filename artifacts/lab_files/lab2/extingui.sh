#!/bin/sh
# IPtables/Netfilter script

PATH='/sbin'

# Flush tables
iptables -F

# Default policy is to accept everything (same as no firewall!)
iptables -P FORWARD 	ACCEPT
iptables -P OUTPUT	ACCEPT
iptables -P INPUT	ACCEPT

