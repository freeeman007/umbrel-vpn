#!/bin/bash

# AntiZapret-AWG: самовосстановление слоя AmneziaWG после обновления
/opt/antizapret-awg/awg-reintegrate.sh >/dev/null 2>&1 &

# Доступ VPN-клиентов к Umbrel и к домашней сети за ним.
# 1) клиент <-> клиент на одном сервере: при DCO пакеты клиентов уходят в ядро,
#    а в FORWARD висит DROP по connmark для адресов вне antizapret-forward;
# 2) клиент -> HOME_LAN: NAT в домашнюю сеть делает сам Umbrel,
#    серверу нужен маршрут в его LAN через адрес Umbrel в туннеле (ccd/umbrel).
# Домашняя подсеть берётся из /root/antizapret/local.env (см. local.env.example),
# в репозитории её нет: без файла работают только правила внутри пула.
CONF="${AZ_LOCAL_CONF:-/root/antizapret/local.env}"
[ -r "$CONF" ] && . "$CONF"
HOME_LAN="${HOME_LAN:-}"

accept_pair() {
	iptables -w -C FORWARD -m conntrack --ctstate NEW,ESTABLISHED,RELATED -s "$1" -d "$2" -j ACCEPT 2>/dev/null || \
		iptables -w -I FORWARD 1 -m conntrack --ctstate NEW,ESTABLISHED,RELATED -s "$1" -d "$2" -j ACCEPT
}

for src in 10.29.0.0/16 10.28.0.0/15; do
	accept_pair "$src" "$src"
done

if [ -n "$HOME_LAN" ]; then
	for src in 10.29.0.0/16 10.28.0.0/15; do
		accept_pair "$src" "$HOME_LAN"
	done
else
	logger -t vpn-umbrel "HOME_LAN не задан в $CONF — доступ клиентов в домашнюю сеть не открыт" 2>/dev/null || true
fi

# маршрут в домашнюю сеть Umbrel ставит umbrel-lan-route.timer (адрес выдаёт пул)

exit 0
