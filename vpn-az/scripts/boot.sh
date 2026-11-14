#!/bin/sh
# boot.sh — супервизор приложения vpn-az v3: пакеты, доставка скриптов, статус-сервер.
# Скрипты тянутся с двух зеркал; в /data всегда лежит последняя рабочая копия.
set -u
DATA=${DATA:-/data}
log() { echo "$(date -u +%FT%TZ) boot: $*" ; }

# зеркала: сначала тег релиза в jsDelivr (кэш тегов иммутабельный, поэтому не бывает
# устаревших скриптов), затем raw.githubusercontent как запас. @main не использовать:
# jsDelivr держит кэш ветки часами и app.py приезжает старый.
MIRRORS="https://cdn.jsdelivr.net/gh/freeeman007/umbrel-vpn@v3.4.1/vpn-az/scripts
https://raw.githubusercontent.com/freeeman007/umbrel-vpn/main/vpn-az/scripts"

mkdir -p "$DATA" "$DATA/profiles" "$DATA/state"

trap 'log "остановка — снимаю туннель и перехват DNS (намерение включения сохраняю)"; sh "$DATA/net.sh" stop 2>/dev/null; sh "$DATA/net.sh" dns off 2>/dev/null; exit 0' TERM INT

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
# 3.2.0: ретраи + диагностика. Если проверка TLS не проходит (нет CA-бандла в образе),
# повторяем с -k — код берётся из нашего же репозитория, но факт фиксируем в логе.
fetch() {
    _name=$1; _min=$2
    _try=0
    while [ "$_try" -lt 6 ]; do
        _try=$((_try+1))
        for _m in $MIRRORS; do
            for _opt in "" "-k"; do
                if curl -fsS $_opt --max-time 25 --retry 2 --retry-delay 2 \
                        "$_m/$_name" -o "$DATA/$_name.new" 2>/tmp/curlerr; then
                    _sz=$(wc -c <"$DATA/$_name.new" 2>/dev/null || echo 0)
                    if [ "$_sz" -ge "$_min" ]; then
                        mv "$DATA/$_name.new" "$DATA/$_name"
                        log "обновлён $_name ($_sz байт${_opt:+, без проверки TLS})"
                        return 0
                    fi
                    log "битая копия $_name ($_sz байт, ожидалось >= $_min)"
                    rm -f "$DATA/$_name.new"
                else
                    log "curl $_name [$_m${_opt}] не удался: $(head -c 200 /tmp/curlerr 2>/dev/null | tr '\n' ' ')"
                fi
            done
        done
        sleep 10
    done
    [ -f "$DATA/$_name" ] && log "не скачал $_name за $_try попыток, использую сохранённый"
    return 1
}

# --- доставка из смонтированного каталога (надёжнее любого CDN) ---
# /code монтируется в compose с хоста (~/vpn-code): Hermes кладёт туда свежие
# скрипты по SSH, приложение забирает их без интернета и без обновления из стора.
SRC=${SRC:-/code}

# sync_src — забрать net.sh/app.py из $SRC, если там другая версия. 0 = что-то обновили.
# ВАЖНО: 0 — это успех для `if sync_src`, поэтому «ничего не меняли» = 1. Раньше было
# наоборот, и статус-сервер убивался каждую минуту, даже когда файлы те же.
sync_src() {
    _ch=1
    for _f in net.sh app.py; do
        [ -s "$SRC/$_f" ] || continue
        if ! cmp -s "$SRC/$_f" "$DATA/$_f"; then
            if cp "$SRC/$_f" "$DATA/$_f"; then
                log "скрипт $_f обновлён из $SRC ($(wc -c <"$DATA/$_f") байт)"
                _ch=0
            fi
        fi
    done
    return $_ch
}

if [ -s "$SRC/app.py" ]; then
    sync_src
else
    log "в $SRC нет скриптов — тяну с зеркал"
    fetch net.sh 8000
    fetch app.py 20000
fi
chmod +x "$DATA/net.sh" 2>/dev/null

# саморемонт: контейнер мог умереть в момент пробы, когда DNS хоста был уведён в туннель.
# Такие правила живут в netns хоста и переживают падение контейнера — снимаем их сразу.
sh "$DATA/net.sh" guard 2>&1 | tee -a "$DATA/net.log"

# автоподъём после включения/перезагрузки сервера делает app.py (boot() -> net.sh resume):
# он знает про state/want_on и state/autostart, здесь второй драйвер не нужен.

trim() {
    [ -f "$1" ] || return 0
    _sz=$(wc -c <"$1" 2>/dev/null || echo 0)
    [ "$_sz" -gt "${2:-500000}" ] && tail -c "${2:-500000}" "$1" > "$1.tmp" && mv "$1.tmp" "$1"
}

log "старт статус-сервера"

# раз в минуту сверяем $SRC: если скрипты обновились — перезапускаем статус-сервер
(
    while :; do
        sleep 60
        if sync_src; then
            log "перезапуск статус-сервера после обновления из $SRC"
            pkill -f "python3 .*app\.py" 2>/dev/null
        fi
    done
) &

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
