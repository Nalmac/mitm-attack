#!/bin/bash

# First setting the bridge to connect all the virtual interfaces
ip link add lab-br type bridge
ip link set lab-br up
# Protecting the host machine
nft add table bridge lab_filter
nft add chain bridge lab_filter input \
  { type filter hook input priority 0 \; policy accept \; }
#======= Legitimate DHCP server ========
ip netns add lab-srv
ip link add veth-lab-srv type veth peer name ceth-lab-srv
ip link set veth-lab-srv master lab-br
ip link set veth-lab-srv up
ip link set ceth-lab-srv netns lab-srv
ip netns exec lab-srv ip link set lo up
ip netns exec lab-srv ip link set ceth-lab-srv up
#Giving the legitimate server a static IP
ip netns exec lab-srv ip addr add 10.0.0.1/24 dev ceth-lab-srv

#======== Victim Namespace ===========
ip netns add lab-victim
ip link add veth-lab-victim type veth peer name ceth-lab-victim
ip link set veth-lab-victim master lab-br
ip link set veth-lab-victim up
ip link set ceth-lab-victim netns lab-victim
ip netns exec lab-victim ip link set lo up
ip netns exec lab-victim ip link set ceth-lab-victim up
# No static IP : the victim will use the DHCP server to get its network
# details (and we will attack that)

#======= att namespace ==========
ip netns add lab-att
ip link add veth-lab-att type veth peer name ceth-lab-att
ip link set veth-lab-att master lab-br
ip link set veth-lab-att up
ip link set ceth-lab-att netns lab-att
ip netns exec lab-att ip link set lo up
ip netns exec lab-att ip link set ceth-lab-att up
# Grabbing a static IP, to set up the rogue DHCP server
ip netns exec lab-att ip addr add 10.0.0.254/24 dev ceth-lab-att

# Deuxième veth point-à-point hôte <-> attaquant, hors bridge
ip link add veth-lab-att-rt type veth peer name ceth-lab-att-rt
# Côté hôte : on NE la met PAS sur le bridge
ip addr add 172.16.0.1/30 dev veth-lab-att-rt
ip link set veth-lab-att-rt up
# Côté attaquant : dans le namespace
ip link set ceth-lab-att-rt netns lab-att
ip netns exec lab-att ip link set ceth-lab-att-rt up
ip netns exec lab-att ip addr add 172.16.0.2/30 dev ceth-lab-att-rt

# 1. Activer le forwarding dans le namespace attaquant
ip netns exec lab-att sysctl -qw net.ipv4.ip_forward=1

# 2. Masquerader les paquets de la victime qui sortent vers l'hôte
ip netns exec lab-att nft add table ip attnat
ip netns exec lab-att nft add chain ip attnat postrouting \{ type nat hook postrouting priority srcnat \; \}
ip netns exec lab-att nft add rule ip attnat postrouting ip saddr 10.0.0.0/24 oifname "ceth-lab-att-rt" masquerade

# Route par défaut de l'attaquant vers l'hôte via ce lien dédié
ip netns exec lab-att ip route add default via 172.16.0.1

# NAT + forwarding vers internet

INET_IF="wlp3s0"
sysctl -qw net.ipv4.ip_forward=1
nft add table ip lab_nat
nft add chain ip lab_nat postrouting { type nat hook postrouting priority 100 \; }
nft add rule ip lab_nat postrouting ip saddr 172.16.0.0/30 oifname "$INET_IF" masquerade
nft add rule inet filter forward \
  ip saddr 172.16.0.0/30 oifname "wlp3s0" accept

nft add rule inet filter forward \
  ip daddr 172.16.0.0/30 iifname "wlp3s0" ct state established,related accept
