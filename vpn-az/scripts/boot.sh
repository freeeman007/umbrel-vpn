#!/bin/sh
# boot.sh — супервизор приложения vpn-az: пакеты, скачивание скриптов, туннель, статус-сервер.
set -u
DATA=${DATA:-/data}
RAW="https://raw.githubusercontent.com/freeeman007/umbrel-vpn/main/vpn-az/scripts"
log() { echo "$(date -u +%FT%TZ) boot: $*" ; }

mkdir -p "$DATA/www" "$DATA/wgphone/clients"

trap 'log "сигнал остановки — снимаю перехват DNS и интерфейсы"; sh "$DATA/net.sh" down 2>/dev/null; exit 0' TERM INT

log "установка пакетов"
apk add --no-cache wireguard-tools iptables iproute2 dnsmasq python3 curl ca-certificates musl-utils \
    >>"$DATA/apk.log" 2>&1 || { apk update >>"$DATA/apk.log" 2>&1; \
    apk add --no-cache wireguard-tools iptables iproute2 dnsmasq python3 curl ca-certificates musl-utils >>"$DATA/apk.log" 2>&1; }

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

APP_PID=""
start_app() {
    [ -f "$DATA/app.py" ] || return 0
    command -v python3 >/dev/null 2>&1 || return 0
    python3 -u "$DATA/app.py" >>"$DATA/app.log" 2>&1 &
    APP_PID=$!
    log "статус-сервер запущен (pid $APP_PID)"
}

trim() { # trim <файл> <байт>
    [ -f "$1" ] || return 0
    _sz=$(wc -c <"$1" 2>/dev/null || echo 0)
    [ "$_sz" -gt "${2:-500000}" ] && tail -c "${2:-500000}" "$1" > "$1.tmp" && mv "$1.tmp" "$1"
}

start_app
log "старт супервизора"

while :; do
    if [ -f "$DATA/.reload" ]; then
        rm -f "$DATA/.reload"
        sh "$DATA/net.sh" apply || true
    else
        sh "$DATA/net.sh" up || true
    fi
    sh "$DATA/net.sh" watch || true

    if [ -n "$APP_PID" ] && ! kill -0 "$APP_PID" 2>/dev/null; then
        log "статус-сервер упал, перезапуск"
        start_app
    fi
    trim "$DATA/app.log"; trim "$DATA/dnsmasq.log"
    sleep 45
done
