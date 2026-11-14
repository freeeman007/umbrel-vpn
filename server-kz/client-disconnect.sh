#!/bin/bash

# снять маршрут в домашнюю сеть Umbrel, если отключился именно он
if [ "$common_name" = "umbrel" ] && [ -n "$ifconfig_pool_remote_ip" ]; then
	ip route del 192.168.11.0/24 via "$ifconfig_pool_remote_ip" 2>/dev/null
fi

exit 0
