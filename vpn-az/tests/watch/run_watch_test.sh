#!/bin/sh
# Проверка ветки watch: phase=on, openvpn мёртв -> должны увидеть
# "watch: openvpn умер — переподключаю" и попытку connect.
# Сеть не трогаем: ip/iptables/openvpn — заглушки из bin/.
set -u
cd "$(dirname "$0")"
T=$PWD
export LOG="$T/log.txt"
: > "$LOG"
export PATH="$T/bin:$PATH"
export DATA="$T/data"
rm -rf "$DATA"; mkdir -p "$DATA/state" "$DATA/profiles/kz"
printf 'client\ndev tun\nproto udp\nremote 127.0.0.1 1\n' > "$DATA/profiles/kz/full-vpn.ovpn"
echo on   > "$DATA/state/phase"
echo kz   > "$DATA/state/active"
echo 999999 > "$DATA/state/ovpn.kz.pid"

NET="$T/../../scripts/net.sh"
[ -f "$NET" ] || NET="$T/../../store/vpn-az/scripts/net.sh"
sh "$NET" watch >>"$LOG" 2>&1

echo "--- лог:"
cat "$LOG"
echo "--- проверки:"
grep -q "watch: openvpn умер — переподключаю" "$LOG" && echo "OK: ветка «openvpn умер» сработала" || echo "FAIL: нет переподключения"
grep -q "stub openvpn" "$LOG" && echo "OK: connect дошёл до запуска openvpn" || echo "FAIL: connect не дошёл до openvpn"
