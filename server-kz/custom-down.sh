#!/bin/bash

for pair in "10.29.0.0/16 10.29.0.0/16" "10.28.0.0/15 10.28.0.0/15" \
            "10.29.0.0/16 192.168.11.0/24" "10.28.0.0/15 192.168.11.0/24"; do
	set -- $pair
	iptables -w -D FORWARD -m conntrack --ctstate NEW,ESTABLISHED,RELATED -s "$1" -d "$2" -j ACCEPT 2>/dev/null
done

exit 0
