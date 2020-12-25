#!/bin/bash
# "Offloading Real-time DDoS Attack Detection to Programmable Data Planes" (IM 2019)
# Copyright (C) 2019  Ângelo Lapolli
# 
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

if [ $(id -u) != "0" ]
then
    sudo "$0" "$@"
    exit $?
fi

if [ $# -ne 2 ] || ([ "$1" != "setup" ] && [ "$1" != "delete" ])
then
    echo "Usage: $0 (setup|delete) <veth_count>"
    exit -1
fi

regex="^[0-9]+$"
if (! [[ "$2" =~ $regex ]]) || [ $(($2 % 2)) -ne 0 ]
then
    echo "Error: veth_count must be a positive even number."
    exit -1
fi

veth_pairs=$(($2/2))

i=0
while [ $i -lt $veth_pairs ]
do
    intf0="veth$(($i*2))"

    if [ "$1" = "setup" ]
    then
        intf1="veth$(($i*2+1))"
        if ! ip link show $intf0 &> /dev/null; then
            ip link add name $intf0 type veth peer name $intf1
            ip link set dev $intf0 up
            ip link set dev $intf1 up
            TOE_OPTIONS="rx tx sg tso ufo gso gro lro rxvlan txvlan rxhash"
            for TOE_OPTION in $TOE_OPTIONS; do
               /sbin/ethtool --offload $intf0 "$TOE_OPTION" off
               /sbin/ethtool --offload $intf1 "$TOE_OPTION" off
            done
        fi
        sysctl net.ipv6.conf.$intf0.disable_ipv6=1
        sysctl net.ipv6.conf.$intf1.disable_ipv6=1
    elif [ "$1" = "delete" ]
    then
        ip link delete $intf0 
    fi

    i=$((i + 1))
done
