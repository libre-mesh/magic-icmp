#!/bin/sh

help() {
	echo "Usage: $0 <ip_dest> <cmd_type> [data]"
	echo "Example: $0 ff02::1%eth0 004a 77777777"
	echo "Happy hakking ;)"
	exit 0
}

PING="ping"
FILTER="8888"
SIZE=24
IP="$1"
CMD="$2"
DATA="$3"

[ -z "$CMD" ] && help

$PING -p ${FILTER}${CMD}${DATA} ${IP} -s ${SIZE} -c1
