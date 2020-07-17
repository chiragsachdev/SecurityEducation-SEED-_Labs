#!/bin/bash
sudo ifconfig tun0 192.168.53.1/24 up
sudo route add -net 192.168.53.0/24 tun0
sudo sysctl net.ipv4.ip_forward=1
