#!/bin/bash
# Держит маршрут HOME_LAN (домашняя сеть Umbrel) через его текущий адрес
# в туннеле. openvpn работает под nobody, поэтому client-connect не может менять
# маршруты в ядре — это делает отдельный root-таймер по статус-файлу сервера.
# Подсеть и интерфейс берутся из /root/antizapret/local.env (см. local.env.example):
# без HOME_LAN таймер ничего не делает.
CONF="${AZ_LOCAL_CONF:-/root/antizapret/local.env}"
[ -r "$CONF" ] && . "$CONF"
HOME_LAN="${HOME_LAN:-}"
OVPN_IF="${OVPN_IF:-antizapret-udp}"
[ -n "$HOME_LAN" ] || exit 0
LOG="/run/openvpn-server/status-${OVPN_IF}.log"
[ -r "$LOG" ] || exit 0

# последняя запись про CN=umbrel (4-е поле — виртуальный адрес)
IP=$(awk -F, '$1=="CLIENT_LIST" && $2=="umbrel" {ip=$4} END {print ip}' "$LOG")
[ -z "$IP" ] && exit 0

cur=$(ip route show "$HOME_LAN" 2>/dev/null)
case "$cur" in
  *"via $IP "*) exit 0 ;;
esac
ip route replace "$HOME_LAN" via "$IP" dev "$OVPN_IF" \
  && logger -t vpn-umbrel "route $HOME_LAN via $IP"
exit 0
