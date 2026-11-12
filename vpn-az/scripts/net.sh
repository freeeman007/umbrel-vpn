#!/bin/sh
# net.sh — сеть приложения vpn-az: туннель к своему AZ-узлу (OpenVPN или WireGuard),
# локальный резолвер и опциональный NAT в домашнюю сеть.
# Идемпотентен: любой вызов приводит систему к целевому состоянию.
set -u

DATA=${DATA:-/data}
OVPN_CONF="$DATA/client.ovpn"
OVPN_DEV=azvpn
OVPN_PID="$DATA/ovpn.pid"
WG_CONF="$DATA/wg0.conf"
WG0=wg0
DNS_PORT=${DNS_PORT:-5399}
DNS_UPSTREAM=${AZ_DNS_UPSTREAM:-1.1.1.1}
VPN_SUBNET=${AZ_VPN_SUBNET:-10.28.0.0/22}
CHAIN=AZVPN_DNS

log() { echo "$(date -u +%FT%TZ) net: $*" ; }

mode() {
    if [ -f "$OVPN_CONF" ]; then echo ovpn
    elif [ -f "$WG_CONF" ]; then echo wg
    else echo none ; fi
}

resolve4() { # resolve4 <host> -> первый IPv4 или пусто
    _r=$(getent ahostsv4 "$1" 2>/dev/null | awk 'NR==1{print $1}')
    [ -n "$_r" ] || _r=$(busybox nslookup "$1" 2>/dev/null | awk '/^Address: /{print $2; exit}')
    [ -n "$_r" ] || _r=$(nslookup "$1" 2>/dev/null | awk '/^Address: /{print $2; exit}')
    printf '%s' "$_r"
}

lan_info() {
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
    while iptables -t "$_t" -D "$_c" "$@" 2>/dev/null; do :; done
}

tun_ip() { ip -4 -o addr show dev "$OVPN_DEV" 2>/dev/null | sed -n 's/.* inet \([0-9.]*\)\/.*/\1/p' | head -1 ; }

ovpn_alive() {
    [ -f "$OVPN_PID" ] && kill -0 "$(cat "$OVPN_PID" 2>/dev/null)" 2>/dev/null && return 0
    pgrep -f "openvpn --config $OVPN_CONF" >/dev/null 2>&1
}

lan_access_wanted() { [ -f "$DATA/lan_access" ]; }

lan_access_on() {
    lan_info
    echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null || true
    rule_ensure filter FORWARD -i "$OVPN_DEV" -j ACCEPT
    rule_ensure filter FORWARD -o "$OVPN_DEV" -j ACCEPT
    [ -n "$LAN_IF" ] && rule_ensure nat POSTROUTING -s "$VPN_SUBNET" -o "$LAN_IF" -j MASQUERADE
    log "lan: NAT $VPN_SUBNET -> $LAN_IF (доступ к домашней сети по tunnel-IP)"
}

lan_access_off() {
    rule_del filter FORWARD -i "$OVPN_DEV" -j ACCEPT
    rule_del filter FORWARD -o "$OVPN_DEV" -j ACCEPT
    lan_info
    [ -n "$LAN_IF" ] && rule_del nat POSTROUTING -s "$VPN_SUBNET" -o "$LAN_IF" -j MASQUERADE
    log "lan: NAT снят"
}

ovpn_up() {
    [ -f "$OVPN_CONF" ] || { log "ovpn: нет $OVPN_CONF"; return 1; }
    ovpn_down_soft
    lan_info
    # эндпоинт сервера всегда через LAN, а не через туннель
    _ep=$(sed -n 's/^[[:space:]]*remote[[:space:]]\+\([^[:space:]]\+\)[[:space:]]\+\([0-9]\+\).*/\1 \2/p' "$OVPN_CONF" | head -1)
    _ep_host=${_ep%% *}
    _ep_ip=$(resolve4 "$_ep_host")
    [ -n "$_ep_ip" ] && [ -n "${LAN_GW:-}" ] && ip route replace "$_ep_ip/32" via "$LAN_GW" dev "$LAN_IF" 2>/dev/null

    openvpn --config "$OVPN_CONF" --dev "$OVPN_DEV" --dev-type tun \
            --log "$DATA/ovpn.log" --writepid "$OVPN_PID" --daemon \
            --script-security 2 --ping 10 --ping-restart 120 2>>"$DATA/ovpn.log" \
        || { log "ovpn: запуск не удался (см. ovpn.log)"; return 1; }

    _i=0
    while [ "$_i" -lt 40 ]; do
        [ -n "$(tun_ip)" ] && break
        ovpn_alive || break
        sleep 1; _i=$((_i+1))
    done
    [ -n "$(tun_ip)" ] || { log "ovpn: интерфейс не получил адрес"; return 1; }

    rule_ensure mangle POSTROUTING -o "$OVPN_DEV" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
    rule_ensure mangle OUTPUT -o "$OVPN_DEV" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
    lan_access_wanted && lan_access_on
    log "ovpn: up $(tun_ip) маршрутов $(ip -4 route show dev $OVPN_DEV | wc -l)"
    return 0
}

ovpn_down_soft() {
    [ -f "$OVPN_PID" ] && kill "$(cat "$OVPN_PID" 2>/dev/null)" 2>/dev/null
    pkill -f "openvpn --config $OVPN_CONF" 2>/dev/null || true
    rm -f "$OVPN_PID"
    _i=0; while [ "$_i" -lt 10 ] && ip link show "$OVPN_DEV" >/dev/null 2>&1; do sleep 1; _i=$((_i+1)); done
}

ovpn_down() {
    lan_access_off
    rule_del mangle POSTROUTING -o "$OVPN_DEV" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
    rule_del mangle OUTPUT -o "$OVPN_DEV" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
    ovpn_down_soft
    ip link del "$OVPN_DEV" 2>/dev/null || true
}

wg0_up() {
    [ -f "$WG_CONF" ] || { log "wg0: нет $WG_CONF"; return 1; }
    lan_info
    ip link show "$WG0" >/dev/null 2>&1 || ip link add dev "$WG0" type wireguard || return 1
    _addr=$(conf_get Address "$WG_CONF")
    _mtu=$(conf_get MTU "$WG_CONF"); [ -n "$_mtu" ] || _mtu=1420
    _ep=$(conf_get Endpoint "$WG_CONF")
    _ep_host=${_ep%:*}; _ep_port=${_ep##*:}
    _ep_ip=$(resolve4 "$_ep_host")
    [ -n "$_ep_ip" ] || { log "wg0: не резолвится $_ep_host"; return 1; }
    strip_conf "$WG_CONF" /run/wg0.strip
    wg setconf "$WG0" /run/wg0.strip 2>/dev/null || { log "wg0: setconf не удался"; return 1; }
    echo "$_addr" | grep -q '/' || _addr="$_addr/32"
    ip -4 addr show dev "$WG0" | grep -q " ${_addr%/*}/" || ip -4 addr add "$_addr" dev "$WG0"
    ip link set mtu "$_mtu" up dev "$WG0" || return 1
    _allowed=$(conf_get AllowedIPs "$WG_CONF")
    if [ -n "$_allowed" ]; then
        echo "$_allowed" | tr ',' '\n' | sed 's/^[[:space:]]*//; s/[[:space:]]*$//' | grep -v '^$' \
            | sed "s|^|route replace |; s|\$| dev $WG0|" > /run/routes.batch
        ip -4 -batch /run/routes.batch >/dev/null 2>&1 || log "wg0: часть маршрутов не применилась"
    fi
    [ -n "${LAN_GW:-}" ] && ip route replace "$_ep_ip/32" via "$LAN_GW" dev "$LAN_IF" >/dev/null 2>&1
    rule_ensure mangle POSTROUTING -o "$WG0" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
    rule_ensure mangle OUTPUT -o "$WG0" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
    return 0
}

wg0_down() {
    rule_del mangle POSTROUTING -o "$WG0" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
    rule_del mangle OUTPUT -o "$WG0" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
    ip route flush dev "$WG0" 2>/dev/null || true
    ip link del "$WG0" 2>/dev/null || true
}

dnat_wanted() { [ -f "$DATA/dns_on" ]; }

dns_up() {
    if [ -f /run/dnsmasq.pid ] && kill -0 "$(cat /run/dnsmasq.pid)" 2>/dev/null; then
        ss -lnuH 2>/dev/null | grep -q ":$DNS_PORT " && return 0
    fi
    pkill -f "dnsmasq.*--port=$DNS_PORT" 2>/dev/null || true
    rm -f /run/dnsmasq.pid
    dnsmasq --port="$DNS_PORT" --no-resolv --no-hosts --domain-needed --bogus-priv \
            --server="$DNS_UPSTREAM" \
            --cache-size=4000 --min-cache-ttl=60 \
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
    [ -n "${LAN_IP:-}" ] || { log "dnat: нет LAN IP"; return 1; }
    iptables -t nat -N "$CHAIN" 2>/dev/null || true
    iptables -t nat -F "$CHAIN"
    for net in 127.0.0.0/8 10.28.0.0/15 "$VPN_SUBNET"; do
        iptables -t nat -A "$CHAIN" -d "$net" -p udp --dport 53 -j RETURN
        iptables -t nat -A "$CHAIN" -d "$net" -p tcp --dport 53 -j RETURN
    done
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

# проверка живости туннеля по факту трафика через интерфейс
ovpn_probe() {
    before=$(cat "/sys/class/net/$OVPN_DEV/statistics/tx_packets" 2>/dev/null || echo 0)
    curl -s -o /dev/null --max-time 8 --interface "$OVPN_DEV" https://ifconfig.me 2>/dev/null \
        || curl -s -o /dev/null --max-time 8 --interface "$OVPN_DEV" http://1.1.1.1 2>/dev/null
    after=$(cat "/sys/class/net/$OVPN_DEV/statistics/tx_packets" 2>/dev/null || echo 0)
    [ "$after" -gt "$before" ] 2>/dev/null
}

watch() {
    _mode=$(mode)
    case "$_mode" in
        ovpn)
            if ! ip link show "$OVPN_DEV" >/dev/null 2>&1; then
                [ -n "$(iptables -t nat -S "$CHAIN" 2>/dev/null)" ] && dnat_off
                log "watch: туннеля нет — поднимаю"
                ovpn_up || true
                return 0
            fi
            if ovpn_probe; then
                rm -f "$DATA/probe_fail"
            else
                _f=$(cat "$DATA/probe_fail" 2>/dev/null || echo 0)
                _f=$((_f+1)); echo "$_f" > "$DATA/probe_fail"
                log "watch: проба через туннель не прошла ($_f)"
                if [ "$_f" -ge 3 ]; then
                    log "watch: перезапускаю openvpn"
                    ovpn_up || true
                    rm -f "$DATA/probe_fail"
                fi
            fi
            ;;
        wg)
            if ! ip link show "$WG0" >/dev/null 2>&1; then
                [ -n "$(iptables -t nat -S "$CHAIN" 2>/dev/null)" ] && dnat_off
                wg0_up || true
                return 0
            fi
            _hs=$(wg show "$WG0" latest-handshakes 2>/dev/null | awk 'NR==1{print $2}')
            _now=$(date +%s)
            if [ -n "${_hs:-}" ] && [ "$_hs" != "0" ] && [ $(( _now - _hs )) -gt 900 ]; then
                log "wg0: рукопожатий нет — перезапуск"
                wg0_down; sleep 2; wg0_up || true
            fi
            ;;
        none)
            [ -n "$(iptables -t nat -S "$CHAIN" 2>/dev/null)" ] && dnat_off
            ;;
    esac
    if ! ss -lnuH 2>/dev/null | grep -q ":$DNS_PORT "; then
        if [ "$_mode" = "none" ] && dnat_wanted; then
            log "watch: резолвера нет — снимаю перехват DNS"
            dnat_off
        else
            dns_up || true
        fi
    fi
}

case "${1:-up}" in
    up)
        _m=$(mode)
        case "$_m" in
            ovpn) ok=1; ovpn_up && ok=0 ;;
            wg)   ok=1; wg0_up && ok=0 ;;
            *)    ok=0 ;;
        esac
        if [ "$ok" = "0" ] && [ "$_m" != "none" ]; then
            if dns_up && dnat_wanted; then dnat_on; else dnat_off; fi
        else
            dnat_off
        fi
        ;;
    down)   dnat_off; dns_down; ovpn_down; wg0_down ;;
    apply)  dnat_off; ovpn_down; wg0_down; ovpn_up || wg0_up; dns_up && dnat_on ;;
    watch)  watch ;;
    lan)    if lan_access_wanted; then lan_access_on; else lan_access_off; fi ;;
    status)
        _m=$(mode)
        echo "mode: $_m"
        if [ "$_m" = "ovpn" ]; then
            echo "ovpn: alive=$(ovpn_alive && echo yes || echo no) ip=$(tun_ip) pid=$(cat "$OVPN_PID" 2>/dev/null)"
            echo "routes: $(ip -4 route show dev $OVPN_DEV 2>/dev/null | wc -l)"
            echo "default: $(ip -4 route show default | head -2 | tr '\n' ' ')"
        else
            echo "wg0: $(wg show $WG0 2>/dev/null | head -3 | tr '\n' ' ')"
            echo "routes: $(ip -4 route show dev $WG0 2>/dev/null | wc -l)"
        fi
        echo "dns: $(ss -lnuH 2>/dev/null | grep -c ":$DNS_PORT ") -> $DNS_UPSTREAM (перехват: $(dnat_wanted && echo yes || echo no))"
        echo "lan_access: $(lan_access_wanted && echo yes || echo no)"
        echo "lan: $(lan_info; echo "$LAN_IP/$LAN_IF/$LAN_GW")"
        ;;
    *) echo "usage: net.sh up|down|apply|watch|lan|status"; exit 2 ;;
esac
