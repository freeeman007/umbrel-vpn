#!/bin/bash

# Зеркало custom-up.sh: снять правила, поставленные при подъёме туннеля.
# Домашняя подсеть берётся из /root/antizapret/local.env (см. local.env.example).
CONF="${AZ_LOCAL_CONF:-/root/antizapret/local.env}"
[ -r "$CONF" ] && . "$CONF"
HOME_LAN="${HOME_LAN:-}"

drop_pair() {
	iptables -w -D FORWARD -m conntrack --ctstate NEW,ESTABLISHED,RELATED -s "$1" -d "$2" -j ACCEPT 2>/dev/null
	true
}

for src in 10.29.0.0/16 10.28.0.0/15; do
	drop_pair "$src" "$src"
	[ -n "$HOME_LAN" ] && drop_pair "$src" "$HOME_LAN"
done

exit 0
