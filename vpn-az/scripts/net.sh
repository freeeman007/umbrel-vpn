#!/bin/sh
# net.sh — сеть приложения vpn-az: WG-клиент к AZ-узлу, DNS-подмена, WG-сервер для телефонов.
# Идемпотентен: любой вызов приводит систему к целевому состоянию.
set -u

DATA=${DATA:-/data}
CONF="$DATA/wg0.conf"
WG0=wg0
WGP=wgphone
DNS_PORT=${DNS_PORT:-5399}
DNS_UPSTREAM=${AZ_DNS_UPSTREAM:-10.29.8.1}
CHAIN=AZVPN_DNS

log() { echo "$(date -u +%FT%TZ) net: $*" ; }

lan_info() {
    # LAN_IP LAN_GW LAN_IF по маршруту по умолчанию
    _r=$(ip -4 route get 1.1.1.1 2>/dev/null | head -1)
    LAN_IP=$(echo "$_r" | sed -n 's/.* src \([0-9.]*\).*/\1/p' | head -1)
    LAN_GW=$(echo "$_r" | sed -n 's/.* via \([0-9.]*\).*/\1/p' | head -1)
    LAN_IF=$(echo "$_r" | sed -n 's/.* dev \([^ ]*\).*/\1/p' | head -1)
}

strip_conf() { grep -vE '^[[:space:]]*(Address|DNS|MTU)[[:space:]]*=' "$1" > "$2" ; }
conf_get() { sed -n "s/^[[:space:]]*$1[[:space:]]*=[[:space:]]*//p" "$2" | head -1 | tr -d ' ' ; }

rule_ensure() { # rule_ensure <table> <chain> <args...>
    _t=$1; _c=$2; shift 2
    iptables -t "$_t" -C "$_c" "$@" 2>/dev/null || iptables -t "$_t" -A "$_c" "$@"
}
rule_del() { # rule_del <table> <chain> <args...>
    _t=$1; _c=$2; shift 2
    iptables -t "$_t" -D "$_c" "$@" 2>/dev/null || true
}

wg0_up() {
    [ -f "$CONF" ] || { log "wg0: нет $CONF — туннель не поднимаю"; return 1; }
    lan_info

    ip link show "$WG0" >/dev/null 2>&1 || ip link add dev "$WG0" type wireguard || return 1

    _addr=$(conf_get Address "$CONF")
    _mtu=$(conf_get MTU "$CONF"); [ -n "$_mtu" ] || _mtu=1420
    _ep=$(conf_get Endpoint "$CONF")
    _ep_host=${_ep%:*}; _ep_port=${_ep##*:}
    _ep_ip=$(getent ahostsv4 "$_ep_host" 2>/dev/null | awk 'NR==1{print $1}')
    [ -n "$_ep_ip" ] || { log "wg0: не резолвится $_ep_host"; return 1; }

    strip_conf "$CONF" /run/wg0.strip
    wg setconf "$WG0" /run/wg0.strip 2>/dev/null || { log "wg0: setconf не удался"; return 1; }

    echo "$_addr" | grep -q '/' || _addr="$_addr/32"
    ip -4 addr show dev "$WG0" | grep -q " ${_addr%/*}/" || ip -4 addr add "$_addr" dev "$WG0"
    ip link set mtu "$_mtu" up dev "$WG0" || return 1

    # сплит-маршруты из AllowedIPs
    _allowed=$(conf_get AllowedIPs "$CONF")
    if [ -n "$_allowed" ]; then
        echo "$_allowed" | tr ',' '\n' | sed 's/^[[:space:]]*//; s/[[:space:]]*$//' | grep -v '^$' \
            | sed "s|^|replace |; s|\$| dev $WG0|" > /run/routes.batch
        ip -4 -batch /run/routes.batch >/dev/null 2>&1 || log "wg0: часть маршрутов не применилась"
    fi

    # эндпоинт всегда через LAN, даже если попал в AllowedIPs
    [ -n "$LAN_GW" ] && ip route replace "$_ep_ip/32" via "$LAN_GW" dev "$LAN_IF" >/dev/null 2>&1

    # MSS, чтобы не вешать TCP на MTU туннеля
    rule_ensure mangle POSTROUTING -o "$WG0" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
    rule_ensure mangle OUTPUT -o "$WG0" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
    return 0
}

dns_up() {
    if [ -f /run/dnsmasq.pid ] && kill -0 "$(cat /run/dnsmasq.pid)" 2>/dev/null; then
        # процесс жив, но мог не забиндить порт в прошлый раз
        ss -lnuH 2>/dev/null | grep -q ":$DNS_PORT " && return 0
    fi
    pkill -f "dnsmasq.*--port=$DNS_PORT" 2>/dev/null || true
    rm -f /run/dnsmasq.pid
    dnsmasq --port="$DNS_PORT" --no-resolv --no-hosts --domain-needed --bogus-priv \
            --server="$DNS_UPSTREAM" --cache-size=4000 --min-cache-ttl=60 \
            --pid-file=/run/dnsmasq.pid --log-facility="$DATA/dnsmasq.log" \
            --conf-file=/dev/null 2>>"$DATA/dnsmasq.log"
    sleep 1
    if ss -lnuH 2>/dev/null | grep -q ":$DNS_PORT "; then
        log "dns: слушаю :$DNS_PORT -> $DNS_UPSTREAM"
        return 0
    fi
    log "dns: не удалось занять порт $DNS_PORT"
    return 1
}

dnat_on() {
    lan_info
    [ -n "$LAN_IP" ] || { log "dnat: нет LAN IP"; return 1; }
    iptables -t nat -N "$CHAIN" 2>/dev/null || true
    iptables -t nat -F "$CHAIN"
    # не перехватывать собственные запросы резолвера и служебные адреса
    iptables -t nat -A "$CHAIN" -d 127.0.0.0/8 -p udp --dport 53 -j RETURN
    iptables -t nat -A "$CHAIN" -d 127.0.0.0/8 -p tcp --dport 53 -j RETURN
    iptables -t nat -A "$CHAIN" -d 10.29.0.0/16 -p udp --dport 53 -j RETURN
    iptables -t nat -A "$CHAIN" -d 10.29.0.0/16 -p tcp --dport 53 -j RETURN
    iptables -t nat -A "$CHAIN" -d 10.77.0.0/24 -p udp --dport 53 -j RETURN
    iptables -t nat -A "$CHAIN" -p udp --dport 53 -j DNAT --to-destination "$LAN_IP:$DNS_PORT"
    iptables -t nat -A "$CHAIN" -p tcp --dport 53 -j DNAT --to-destination "$LAN_IP:$DNS_PORT"
    for hook in PREROUTING OUTPUT; do
        iptables -t nat -C "$hook" -j "$CHAIN" 2>/dev/null || iptables -t nat -I "$hook" 1 -j "$CHAIN"
    done
    log "dnat: DNS всех контейнеров -> $LAN_IP:$DNS_PORT"
}

dnat_off() {
    for hook in PREROUTING OUTPUT; do
        while iptables -t nat -C "$hook" -j "$CHAIN" 2>/dev/null; do iptables -t nat -D "$hook" -j "$CHAIN"; done
    done
    iptables -t nat -F "$CHAIN" 2>/dev/null || true
    iptables -t nat -X "$CHAIN" 2>/dev/null || true
    log "dnat: снят"
}

dns_down() {
    [ -f /run/dnsmasq.pid ] && kill "$(cat /run/dnsmasq.pid)" 2>/dev/null || true
    rm -f /run/dnsmasq.pid
}

wgphone_up() {
    _conf="$DATA/wgphone/server.conf"
    [ -f "$_conf" ] || return 0
    lan_info
    ip link show "$WGP" >/dev/null 2>&1 || ip link add dev "$WGP" type wireguard || return 1
    strip_conf "$_conf" /run/wgphone.strip
    wg setconf "$WGP" /run/wgphone.strip 2>/dev/null || { log "wgphone: setconf не удался"; return 1; }
    _addr=$(conf_get Address "$_conf"); echo "$_addr" | grep -q '/' || _addr="$_addr/32"
    ip -4 addr show dev "$WGP" | grep -q " ${_addr%/*}/" || ip -4 addr add "$_addr" dev "$WGP"
    ip link set mtu 1280 up dev "$WGP" || return 1
    echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null || true

    rule_ensure nat POSTROUTING -s 10.77.0.0/24 -o "$LAN_IF" -j MASQUERADE
    _az_addr=$(conf_get Address "$CONF" 2>/dev/null | cut -d/ -f1)
    if [ -n "${_az_addr:-}" ]; then
        rule_ensure nat POSTROUTING -s 10.77.0.0/24 -o "$WG0" -j SNAT --to-source "$_az_addr"
    fi
    rule_ensure nat POSTROUTING -s 10.77.0.0/24 -o "$WGP" -j MASQUERADE
    rule_ensure filter FORWARD -i "$WGP" -j ACCEPT
    rule_ensure filter FORWARD -o "$WGP" -j ACCEPT
    rule_ensure nat PREROUTING -i "$WGP" -p udp --dport 53 -j REDIRECT --to-ports "$DNS_PORT"
    rule_ensure nat PREROUTING -i "$WGP" -p tcp --dport 53 -j REDIRECT --to-ports "$DNS_PORT"
    log "wgphone: сервер поднят (10.77.0.1, 51820/udp, mtu 1280)"
}

wgphone_down() {
    rule_del nat PREROUTING -i "$WGP" -p udp --dport 53 -j REDIRECT --to-ports "$DNS_PORT"
    rule_del nat PREROUTING -i "$WGP" -p tcp --dport 53 -j REDIRECT --to-ports "$DNS_PORT"
    rule_del filter FORWARD -i "$WGP" -j ACCEPT
    rule_del filter FORWARD -o "$WGP" -j ACCEPT
    rule_del nat POSTROUTING -s 10.77.0.0/24 -o "$WGP" -j MASQUERADE
    ip link del "$WGP" 2>/dev/null || true
}

wg0_down() {
    rule_del mangle POSTROUTING -o "$WG0" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
    rule_del mangle OUTPUT -o "$WG0" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
    ip route flush dev "$WG0" 2>/dev/null || true
    ip link del "$WG0" 2>/dev/null || true
}

watch() {
    [ -f "$CONF" ] || return 0
    ip link show "$WG0" >/dev/null 2>&1 || { wg0_up; return 0; }
    _hs=$(wg show "$WG0" latest-handshakes 2>/dev/null | awk 'NR==1{print $2}')
    _now=$(date +%s)
    if [ -n "${_hs:-}" ] && [ "$_hs" != "0" ]; then
        _age=$(( _now - _hs ))
        if [ "$_age" -gt 900 ]; then
            log "wg0: рукопожатия нет ${_age}s — перезапускаю интерфейс"
            wg0_down; sleep 2; wg0_up
        elif [ "$_age" -gt 180 ]; then
            log "wg0: рукопожатие ${_age}s назад — обновляю эндпоинт"
            _ep=$(conf_get Endpoint "$CONF"); _host=${_ep%:*}; _port=${_ep##*:}
            _ip=$(getent ahostsv4 "$_host" 2>/dev/null | awk 'NR==1{print $1}')
            _pub=$(wg show "$WG0" peers | head -1)
            [ -n "$_ip" ] && [ -n "$_pub" ] && wg set "$WG0" peer "$_pub" endpoint "$_ip:$_port" persistent-keepalive 15
        fi
    fi
}

case "${1:-up}" in
    up)
        if wg0_up; then
            if dns_up; then dnat_on; else dnat_off; fi
        else
            dnat_off; dns_down
        fi
        wgphone_up
        ;;
    down)   dnat_off; wgphone_down; dns_down; wg0_down ;;
    watch)  watch ;;
    apply)  dnat_off; wg0_down; wg0_up && dns_up && dnat_on; wgphone_up ;;
    status)
        echo "wg0: $(wg show $WG0 2>/dev/null | head -3 | tr '\n' ' ')"
        echo "routes: $(ip -4 route show dev $WG0 2>/dev/null | wc -l)"
        echo "dns: $(ss -lnuH 2>/dev/null | grep -c ":$DNS_PORT ")"
        echo "lan: $(lan_info; echo "$LAN_IP/$LAN_IF/$LAN_GW")"
        ;;
    *) echo "usage: net.sh up|down|apply|watch|status"; exit 2 ;;
esac
