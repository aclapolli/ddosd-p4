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

sigint_handler() {
    kill -9 $pid
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"

$SCRIPT_DIR/veth.sh setup 6

trap sigint_handler SIGINT
simple_switch -i 0@veth0 -i 1@veth2 -i 2@veth4 $SCRIPT_DIR/../build/ddosd.json &
pid=$!
sleep 1
simple_switch_CLI < $SCRIPT_DIR/control_rules.txt
wait $pid

$SCRIPT_DIR/veth.sh delete 6

exit 0
