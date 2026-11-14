#!/bin/bash
# Держит маршрут 192.168.11.0/24 (домашняя сеть Umbrel) через его текущий адрес
# в туннеле. openvpn работает под nobody, поэтому client-connect не может менять
# маршруты в ядре — это делает отдельный root-таймер по статус-файлу сервера.
LOG=/run/openvpn-server/status-antizapret-udp.log
[ -r "$LOG" ] || exit 0

# последняя запись про CN=umbrel (4-е поле — виртуальный адрес)
IP=$(awk -F, '$1=="CLIENT_LIST" && $2=="umbrel" {ip=$4} END {print ip}' "$LOG")
[ -z "$IP" ] && exit 0

cur=$(ip route show 192.168.11.0/24 2>/dev/null)
case "$cur" in
  *"via $IP "*) exit 0 ;;
esac
ip route replace 192.168.11.0/24 via "$IP" dev antizapret-udp \
  && logger -t vpn-umbrel "route 192.168.11.0/24 via $IP"
exit 0
