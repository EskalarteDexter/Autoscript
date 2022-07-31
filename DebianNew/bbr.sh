#!/bin/bash

##variables
#var_a="net.ipv4.tcp_available_congestion_control"
#var_a_want="cubic reno"

#if [[ $(sysctl $var_a | grep '$var_a = $var_a_want') ]];
#  then
#    echo -e "$var_a = $var_a_want"
#  elif [[ $(sysctl $var_a | grep '$var_a = bbr') ]];
#  then
#    echo "already have bbr"
#  else
#    echo ""
#fi
 
##if your kernel version is earlier than 4.9 then run this 2 command
#sudo apt update
#sudo apt install --install-recommends linux-generic-hwe-16.04

##setting BBR
echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf

##reload sysctl
#sysctl -p
##reload sysctl
sysctl --system
   

#if [[ $(sysctl net.ipv4.tcp_congestion_control | grep 'net.ipv4.tcp_congestion_control = bbr') ]];
#  then
#    echo "BBR Successfully Installed"
#  else
#    echo "BBR Failed to Install"
#fi
