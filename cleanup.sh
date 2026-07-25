#!/bin/bash

# Tables nftables en premier
#nft delete table bridge lab_filter
#nft delete table ip lab_nat

# Namespaces (supprime les veth internes automatiquement)
ip netns del lab-victim
ip netns del lab-att
ip netns del lab-srv

# Lien de routage cote hote (la moitie qui survit a la suppression du namespace)
ip link del veth-lab-att-rt 2>/dev/null

# Bridge
ip link del lab-br

# Forwarding
sysctl -qw net.ipv4.ip_forward=0

#HANDLE=$(nft -a list chain inet filter forward | grep "lab-forward-out" | awk '{print $NF}')
#nft delete rule inet filter forward handle $HANDLE
