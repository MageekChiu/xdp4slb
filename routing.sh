#!/bin/bash

dst="172.19.0.10"
rs1="172.19.0.2"
rs2="172.19.0.3"
ip route del $dst/32
ip route add $dst/32 nexthop via $rs1 dev eth0 weight 1
while true; do
    nexthop=$(ip route show $dst/32 | awk '{print $3}')
    # nexthop=$(ip route show "$dst" | grep -oP "nexthop \K\S+")
    echo "to ${dst} via ${nexthop} now!"
    sleep 3
    
    # the requirements for blank is crazy!
    if [ "$nexthop" = "$rs1" ]; then
        new_nexthop="$rs2"
    else
        new_nexthop="$rs1"
    fi
    ip route del $dst/32
    ip route add $dst/32 nexthop via $new_nexthop dev eth0 weight 1
done