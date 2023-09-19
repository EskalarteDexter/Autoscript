#!/bin/bash

echo "net.ipv4.ip_forward=1
net.ipv4.conf.all.rp_filter=0
net.ipv4.conf.eth0.rp_filter=0
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf

sysctl -p

iptables -t nat -A PREROUTING -p udp --dport 20000:50000 -j DNAT --to-destination :5666

systemctl enable hysteria-server.service
systemctl restart hysteria-server.service

reboot