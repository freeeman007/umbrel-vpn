#!/bin/bash

# AntiZapret-AWG: самовосстановление слоя AmneziaWG после обновления
/opt/antizapret-awg/awg-reintegrate.sh >/dev/null 2>&1 &

# Доступ VPN-клиентов к Umbrel (10.29.0.2) и к домашней сети за ним.
# 1) клиент <-> клиент на одном сервере: при DCO пакеты клиентов уходят в ядро,
#    а в FORWARD висит DROP по connmark для адресов вне antizapret-forward;
# 2) клиент -> 192.168.11.0/24: NAT в домашнюю сеть делает сам Umbrel,
#    серверу нужен маршрут в его LAN через адрес Umbrel в туннеле (ccd/umbrel).
for pair in "10.29.0.0/16 10.29.0.0/16" "10.28.0.0/15 10.28.0.0/15" \
            "10.29.0.0/16 192.168.11.0/24" "10.28.0.0/15 192.168.11.0/24"; do
	set -- $pair
	iptables -w -C FORWARD -m conntrack --ctstate NEW,ESTABLISHED,RELATED -s "$1" -d "$2" -j ACCEPT 2>/dev/null || \
		iptables -w -I FORWARD 1 -m conntrack --ctstate NEW,ESTABLISHED,RELATED -s "$1" -d "$2" -j ACCEPT
done

# маршрут в домашнюю сеть Umbrel ставит umbrel-lan-route.timer (адрес выдаёт пул)

exit 0
