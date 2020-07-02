#!/bin/bash

dev_tun=$1
tun_mtu=$2
link_mtu=$3
ifconfig_local_ip=$4
ifconfig_remote_ip=$5

bits=0

for octet in $(echo $5 | sed 's/\./ /g'); do 
   binbits=$(echo "obase=2; ibase=10; ${octet}"| bc | sed 's/0//g') 
   bits=$((bits+${#binbits}))
done

network="${ifconfig_local_ip}\/${bits}"
sed_command="/[ ]+network ${network} area 0.0.0.0.*/d"

sed -i -E "$sed_command" /etc/frr/ospfd.conf

systemctl restart frr