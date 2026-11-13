#!/bin/sh
# boot.sh — супервизор приложения vpn-az v3: пакеты, обновление скриптов, статус-сервер.
# Туннель поднимает сам app.py (по кнопке или если был включён до перезапуска).
set -u
DATA=${DATA:-/data}
RAW="https://raw.githubusercontent.com/freeeman007/umbrel-vpn/main/vpn-az/scripts"
log() { echo "$(date -u +%FT%TZ) boot: $*" ; }

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

fetch() {
    for i in 1 2 3; do
        if curl -fsS --max-time 30 "$RAW/$1?v=$(date +%s)" -o "$DATA/$1.new" 2>/dev/null; then
            mv "$DATA/$1.new" "$DATA/$1"
            log "обновлён $1"
            return 0
        fi
        sleep 3
    done
    [ -f "$DATA/$1" ] && log "не скачал $1, использую сохранённый"
    return 1
}

fetch net.sh; chmod +x "$DATA/net.sh" 2>/dev/null
fetch app.py

trim() {
    [ -f "$1" ] || return 0
    _sz=$(wc -c <"$1" 2>/dev/null || echo 0)
    [ "$_sz" -gt "${2:-500000}" ] && tail -c "${2:-500000}" "$1" > "$1.tmp" && mv "$1.tmp" "$1"
}

log "старт статус-сервера"
while :; do
    if [ -f "$DATA/app.py" ] && command -v python3 >/dev/null 2>&1; then
        python3 -u "$DATA/app.py" >>"$DATA/app.log" 2>&1
        log "app.py завершился (код $?), перезапуск через 5 с"
    else
        log "нет app.py или python3 — жду"
    fi
    trim "$DATA/app.log"; trim "$DATA/dnsmasq.log"; trim "$DATA/ovpn.log"; trim "$DATA/net.log"
    sleep 5
done
