#!/bin/bash

# снять маршрут в домашнюю сеть Umbrel, если отключился именно он
CONF="${AZ_LOCAL_CONF:-/root/antizapret/local.env}"
[ -r "$CONF" ] && . "$CONF"

# без HOME_LAN (см. local.env.example) маршрута нет — снимать нечего
if [ "$common_name" = "umbrel" ] && [ -n "$ifconfig_pool_remote_ip" ] && [ -n "${HOME_LAN:-}" ]; then
	ip route del "$HOME_LAN" via "$ifconfig_pool_remote_ip" 2>/dev/null
fi

exit 0
