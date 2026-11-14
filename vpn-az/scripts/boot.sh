#!/bin/sh
# boot.sh — супервизор приложения vpn-az v3: пакеты, доставка скриптов, статус-сервер.
# Скрипты тянутся с двух зеркал; в /data всегда лежит последняя рабочая копия.
set -u
DATA=${DATA:-/data}
log() { echo "$(date -u +%FT%TZ) boot: $*" ; }

# зеркала: сначала тег релиза в jsDelivr (кэш тегов иммутабельный, поэтому не бывает
# устаревших скриптов), затем raw.githubusercontent как запас. @main не использовать:
# jsDelivr держит кэш ветки часами и app.py приезжает старый.
MIRRORS="https://cdn.jsdelivr.net/gh/freeeman007/umbrel-vpn@v3.1.0/vpn-az/scripts
https://raw.githubusercontent.com/freeeman007/umbrel-vpn/main/vpn-az/scripts"

mkdir -p "$DATA" "$DATA/profiles" "$DATA/state"

trap 'log "остановка — снимаю туннель и перехват DNS"; sh "$DATA/net.sh" disconnect 2>/dev/null; sh "$DATA/net.sh" dns off 2>/dev/null; exit 0' TERM INT

# /dev/net/tun может отсутствовать до загрузки модуля tun
if [ ! -e /dev/net/tun ]; then
    mkdir -p /dev/net
    mknod /dev/net/tun c 10 200 2>/dev/null && chmod 666 /dev/net/tun
    log "создан узел /dev/net/tun"
fi

log "установка пакетов"
PKGS="openvpn wireguard-tools iptables iproute2 dnsmasq python3 curl ca-certificates musl-utils"
apk add --no-cache $PKGS >>"$DATA/apk.log" 2>&1 || { apk update >>"$DATA/apk.log" 2>&1; \
    apk add --no-cache $PKGS >>"$DATA/apk.log" 2>&1; }

# fetch <имя> <минимальный размер> — скачать с зеркал, сохранить рабочую копию
fetch() {
    _name=$1; _min=$2
    for _m in $MIRRORS; do
        if curl -fsS --max-time 25 "$_m/$_name?v=$(date +%s)" -o "$DATA/$_name.new" 2>/dev/null; then
            _sz=$(wc -c <"$DATA/$_name.new" 2>/dev/null || echo 0)
            if [ "$_sz" -ge "$_min" ]; then
                mv "$DATA/$_name.new" "$DATA/$_name"
                log "обновлён $_name ($_sz байт)"
                return 0
            fi
            log "битая копия $_name ($_sz байт), пробую другое зеркало"
            rm -f "$DATA/$_name.new"
        fi
    done
    [ -f "$DATA/$_name" ] && log "не скачал $_name, использую сохранённый"
    return 1
}

fetch net.sh 8000
fetch app.py 20000
chmod +x "$DATA/net.sh" 2>/dev/null

trim() {
    [ -f "$1" ] || return 0
    _sz=$(wc -c <"$1" 2>/dev/null || echo 0)
    [ "$_sz" -gt "${2:-500000}" ] && tail -c "${2:-500000}" "$1" > "$1.tmp" && mv "$1.tmp" "$1"
}

log "старт статус-сервера"
while :; do
    if [ -f "$DATA/app.py" ] && command -v python3 >/dev/null 2>&1; then
        python3 -u "$DATA/app.py" >>"$DATA/app.log" 2>&1
        log "app.py завершился, перезапуск через 5 с"
    else
        log "нет app.py или python3 — жду"
    fi
    trim "$DATA/app.log"; trim "$DATA/dnsmasq.log"; trim "$DATA/ovpn.log"; trim "$DATA/net.log"
    sleep 5
done
