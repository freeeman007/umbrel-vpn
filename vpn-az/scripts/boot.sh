#!/bin/sh
# boot.sh — супервизор приложения vpn-az v3: пакеты, копия скриптов из образа, статус-сервер.
# Код берётся из /scripts (смонтирован из каталога приложения), сеть не нужна.
set -u
DATA=${DATA:-/data}
SRC=${SRC:-/scripts}
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

# скрипты из каталога приложения -> рабочий каталог; старые версии остаются как резерв
for f in net.sh app.py; do
    if [ -f "$SRC/$f" ]; then
        if ! cmp -s "$SRC/$f" "$DATA/$f"; then
            cp "$SRC/$f" "$DATA/$f.new" && mv "$DATA/$f.new" "$DATA/$f" && log "обновлён $f"
        fi
    elif [ ! -f "$DATA/$f" ]; then
        log "нет $f ни в $SRC, ни в $DATA — работа невозможна"
    else
        log "использую сохранённый $f"
    fi
done
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
