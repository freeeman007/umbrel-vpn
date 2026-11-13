#!/bin/sh
# net.sh — сеть приложения vpn-az v3: библиотека профилей, connect/disconnect с автооткатом,
# локальный резолвер, NAT в домашнюю сеть.
# Идемпотентен: любой вызов приводит систему к целевому состоянию.
# Команды: connect <id> | disconnect | up | watch | dns on|off | lan on|off | status | down
set -u

DATA=${DATA:-/data}
STATE="$DATA/state"
PROFILES="$DATA/profiles"
DNS_PORT=${DNS_PORT:-5399}
DNS_UPSTREAM=${AZ_DNS_UPSTREAM:-1.1.1.1}
VPN_SUBNET=${AZ_VPN_SUBNET:-10.28.0.0/22}
OVPN_DEV=azvpn
WG0=wg0
CHAIN=AZVPN_DNS
CHAIN_OUT=AZVPN_DNS_OUT
DNS_UID=1001
PROBE_TIMEOUT=${AZ_PROBE_TIMEOUT:-90}

log() { echo "$(date -u +%FT%TZ) net: $*" ; }

mkdir -p "$STATE" "$PROFILES"

# ---------------------------------------------------------------- состояние
phase()      { cat "$STATE/phase" 2>/dev/null | tr -d ' \n' ; }
set_phase()  { mkdir -p "$STATE"; printf '%s\n' "$1" > "$STATE/phase" ; }
error()      { cat "$STATE/error" 2>/dev/null ; }
set_error()  { mkdir -p "$STATE"; printf '%s\n' "$1" > "$STATE/error" ; }
clear_error(){ rm -f "$STATE/error" ; }
active_id()  { cat "$STATE/active" 2>/dev/null | tr -d ' \n' ; }
set_active() { mkdir -p "$STATE"; printf '%s\n' "$1" > "$STATE/active" ; }
clear_active(){ rm -f "$STATE/active" ; }
since()      { cat "$STATE/since" 2>/dev/null ; }
set_since()  { mkdir -p "$STATE"; printf '%s\n' "$1" > "$STATE/since" ; }

# ---------------------------------------------------------------- профили
prof_dir()  { echo "$PROFILES/$1" ; }
prof_conf() { ls "$PROFILES/$1"/*.ovpn "$PROFILES/$1"/*.conf 2>/dev/null | head -1 ; }
prof_type() {
    case "$(prof_conf "$1")" in
        *.ovpn) echo ovpn ;;
        *.conf) echo wg ;;
        *)      echo none ;;
    esac
}
full_tunnel() { # full_tunnel <id>
    _c=$(prof_conf "$1"); [ -n "$_c" ] || return 1
    case "$(prof_type "$1")" in
        ovpn) grep -qiE '^[[:space:]]*(redirect-gateway|route[[:space:]]+0\.0\.0\.0[[:space:]]+0\.0\.0\.0)' "$_c" ;;
        wg)   grep -qiE '^[[:space:]]*AllowedIPs[[:space:]]*=[[:space:]]*.*0\.0\.0\.0/0' "$_c" ;;
        *)    return 1 ;;
    esac
}

# ---------------------------------------------------------------- утилиты
resolve4() {
    _r=$(getent ahostsv4 "$1" 2>/dev/null | awk 'NR==1{print $1}')
    [ -n "$_r" ] || _r=$(busybox nslookup "$1" 2>/dev/null | awk '/^Address: /{print $2; exit}')
    [ -n "$_r" ] || _r=$(nslookup "$1" 2>/dev/null | awk '/^Address: /{print $2; exit}')
    printf '%s' "$_r"
}

lan_info() {
    # домашний интерфейс ищем по адресу, а не по default: при полном туннеле
    # default уже смотрит в azvpn/wg0 и даёт неверный интерфейс
    LAN_IP=""; LAN_IF=""; LAN_GW=""; LAN_PREFIX=24; LAN_NET=""
    for _n in /sys/class/net/*; do
        _i=$(basename "$_n")
        case "$_i" in lo|azvpn|wg0|tun*|tap*|docker*|veth*|br-*|virbr*) continue ;;
        esac
        _a=$(ip -4 -o addr show dev "$_i" 2>/dev/null | sed -n 's/.* inet \([0-9.]*\)\/\([0-9]*\).*/\1 \2/p' | head -1)
        [ -n "$_a" ] || continue
        _ip=${_a%% *}; _pf=${_a##* }
        case "$_ip" in 10.28.*|10.29.*|172.17.*|172.18.*) continue ;; esac
        LAN_IP=$_ip; LAN_IF=$_i; LAN_PREFIX=${_pf:-24}; break
    done
    [ -n "$LAN_IF" ] && LAN_GW=$(ip -4 route show dev "$LAN_IF" 2>/dev/null \
        | sed -n 's/^default via \([0-9.]*\).*/\1/p' | head -1)
    if [ -n "$LAN_IP" ]; then
        # сеть из IP и префикса
        LAN_NET=$(python3 - "$LAN_IP" "$LAN_PREFIX" <<'PY' 2>/dev/null
import ipaddress, sys
print(ipaddress.ip_network("%s/%s" % (sys.argv[1], sys.argv[2]), strict=False).with_prefixlen)
PY
)
        [ -n "$LAN_NET" ] || LAN_NET=$(echo "$LAN_IP" | awk -F. '{printf "%s.%s.%s.0/%d", $1,$2,$3,24}')
    fi
}

rule_ensure() { _t=$1; _c=$2; shift 2; iptables -t "$_t" -C "$_c" "$@" 2>/dev/null || iptables -t "$_t" -A "$_c" "$@" ; }
rule_del()    { _t=$1; _c=$2; shift 2; while iptables -t "$_t" -D "$_c" "$@" 2>/dev/null; do :; done ; }

# LAN-маршрут ставится ПОСЛЕ маршрутов туннеля, иначе сервер его перезапишет.
protect_lan() {
    lan_info
    [ -n "${LAN_NET:-}" ] && [ -n "${LAN_GW:-}" ] || return 0
    ip route replace "$LAN_NET" via "$LAN_GW" dev "$LAN_IF" 2>/dev/null \
        && log "lan: $LAN_NET оставлен напрямую через $LAN_GW (доступ к серверу не теряется)"
}

# ---------------------------------------------------------------- openvpn
ovpn_pid_file() { echo "$STATE/ovpn.$1.pid" ; }
ovpn_alive() {
    _pf=$(ovpn_pid_file "$1")
    [ -f "$_pf" ] && kill -0 "$(cat "$_pf" 2>/dev/null)" 2>/dev/null && return 0
    pgrep -f "openvpn --config $(prof_conf "$1")" >/dev/null 2>&1
}
tun_ip() { ip -4 -o addr show dev "$OVPN_DEV" 2>/dev/null | sed -n 's/.* inet \([0-9.]*\)\/.*/\1/p' | head -1 ; }

ovpn_stop() {
    _id=${1:-$(active_id)}
    [ -n "$_id" ] && pkill -f "openvpn --config $(prof_conf "$_id")" 2>/dev/null
    pkill -f "openvpn.*--dev $OVPN_DEV" 2>/dev/null || true
    rm -f "$STATE"/ovpn.*.pid
    _i=0; while [ "$_i" -lt 10 ] && ip link show "$OVPN_DEV" >/dev/null 2>&1; do sleep 1; _i=$((_i+1)); done
    ip link del "$OVPN_DEV" 2>/dev/null || true
    rule_del mangle POSTROUTING -o "$OVPN_DEV" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
    rule_del mangle OUTPUT -o "$OVPN_DEV" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
}

ovpn_start() { # ovpn_start <id>
    _id=$1; _dir=$(prof_dir "$_id"); _conf=$(prof_conf "$_id")
    [ -f "$_conf" ] || { set_error "нет конфига в профиле"; return 1; }
    lan_info
    # эндпоинт сервера всегда через LAN, а не через туннель
    _ep=$(sed -n 's/^[[:space:]]*remote[[:space:]]\+\([^[:space:]]\+\)[[:space:]]\+\([0-9]\+\).*/\1 \2/p' "$_conf" | head -1)
    _ep_host=$(echo "$_ep" | cut -d' ' -f1)
    _ep_ip=$(resolve4 "$_ep_host")
    [ -n "$_ep_ip" ] || _ep_ip=$_ep_host
    [ -n "$_ep_ip" ] && [ -n "${LAN_GW:-}" ] && ip route replace "$_ep_ip/32" via "$LAN_GW" dev "$LAN_IF" 2>/dev/null

    _extra=""
    [ -f "$_dir/cred.txt" ] && _extra="--auth-user-pass $_dir/cred.txt"

    # --cd важен: сторонние провайдеры ссылаются на ca.crt/key из той же папки
    openvpn --cd "$_dir" --config "$_conf" --dev "$OVPN_DEV" --dev-type tun \
            $_extra --log "$DATA/ovpn.log" --writepid "$(ovpn_pid_file "$_id")" --daemon \
            --script-security 2 --ping 10 --ping-restart 120 2>>"$DATA/ovpn.log" \
        || { set_error "openvpn не запустился (см. журнал)"; return 1; }

    _i=0
    while [ "$_i" -lt 45 ]; do
        [ -n "$(tun_ip)" ] && break
        ovpn_alive "$_id" || break
        sleep 1; _i=$((_i+1))
    done
    if [ -z "$(tun_ip)" ]; then
        set_error "туннель не получил адрес (ошибка в профиле или сервер недоступен)"
        return 1
    fi
    rule_ensure mangle POSTROUTING -o "$OVPN_DEV" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
    rule_ensure mangle OUTPUT -o "$OVPN_DEV" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
    protect_lan
    log "ovpn[$_id]: up $(tun_ip) маршрутов $(ip -4 route show dev $OVPN_DEV | wc -l)"
    return 0
}

# ---------------------------------------------------------------- wireguard
wg_stop() {
    rule_del mangle POSTROUTING -o "$WG0" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
    rule_del mangle OUTPUT -o "$WG0" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
    ip route flush dev "$WG0" 2>/dev/null || true
    ip link del "$WG0" 2>/dev/null || true
}

conf_get() { sed -n "s/^[[:space:]]*$1[[:space:]]*=[[:space:]]*//p" "$2" | head -1 | sed 's/[[:space:]]*$//' ; }

wg_start() { # wg_start <id>
    _id=$1; _conf=$(prof_conf "$_id")
    [ -f "$_conf" ] || { set_error "нет конфига в профиле"; return 1; }
    lan_info
    ip link show "$WG0" >/dev/null 2>&1 || ip link add dev "$WG0" type wireguard || { set_error "не создаётся wg0"; return 1; }
    _addr=$(conf_get Address "$_conf")
    _mtu=$(conf_get MTU "$_conf"); [ -n "$_mtu" ] || _mtu=1420
    _ep=$(conf_get Endpoint "$_conf")
    _ep_host=${_ep%:*}; 
    _ep_ip=$(resolve4 "$_ep_host"); [ -n "$_ep_ip" ] || _ep_ip=$_ep_host
    [ -n "$_ep_ip" ] && [ -n "${LAN_GW:-}" ] && ip route replace "$_ep_ip/32" via "$LAN_GW" dev "$LAN_IF" 2>/dev/null
    grep -vE '^[[:space:]]*(Address|DNS|MTU)[[:space:]]*=' "$_conf" > /run/wg0.strip
    wg setconf "$WG0" /run/wg0.strip 2>/dev/null || { set_error "wg setconf: ошибка в конфиге"; return 1; }
    echo "$_addr" | grep -q '/' || _addr="$_addr/32"
    ip -4 addr show dev "$WG0" | grep -q " ${_addr%/*}/" || ip -4 addr add "$_addr" dev "$WG0"
    ip link set mtu "$_mtu" up dev "$WG0" || { set_error "wg0 не поднимается"; return 1; }
    _allowed=$(conf_get AllowedIPs "$_conf")
    if [ -n "$_allowed" ]; then
        echo "$_allowed" | tr ',' '\n' | sed 's/^[[:space:]]*//; s/[[:space:]]*$//' | grep -v '^$' \
            | sed "s|^|route replace |; s|\$| dev $WG0|" > /run/routes.batch
        ip -4 -batch /run/routes.batch >/dev/null 2>&1 || log "wg0: часть маршрутов не применилась"
    fi
    rule_ensure mangle POSTROUTING -o "$WG0" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
    rule_ensure mangle OUTPUT -o "$WG0" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
    protect_lan
    log "wg[$_id]: up $(conf_get Address "$_conf")"
    return 0
}

# ---------------------------------------------------------------- DNS
dns_user() { id -u dnsres >/dev/null 2>&1 || adduser -D -H -u "$DNS_UID" dnsres 2>/dev/null ; }

dns_up() {
    if [ -f /run/dnsmasq.pid ] && kill -0 "$(cat /run/dnsmasq.pid)" 2>/dev/null \
       && ss -lnuH 2>/dev/null | grep -q ":$DNS_PORT "; then
        return 0
    fi
    pkill -f "dnsmasq.*--port=$DNS_PORT" 2>/dev/null || true
    rm -f /run/dnsmasq.pid
    dns_user
    dnsmasq --port="$DNS_PORT" --no-resolv --no-hosts --domain-needed --bogus-priv \
            --server="$DNS_UPSTREAM" --user=dnsres \
            --cache-size=4000 --min-cache-ttl=60 \
            --pid-file=/run/dnsmasq.pid --log-facility="$DATA/dnsmasq.log" \
            --conf-file=/dev/null 2>>"$DATA/dnsmasq.log"
    sleep 1
    ss -lnuH 2>/dev/null | grep -q ":$DNS_PORT " && { log "dns: слушаю :$DNS_PORT -> $DNS_UPSTREAM"; return 0 ; }
    set_error "DNS-резолвер не занял порт $DNS_PORT"
    return 1
}

dns_down() { [ -f /run/dnsmasq.pid ] && kill "$(cat /run/dnsmasq.pid)" 2>/dev/null; rm -f /run/dnsmasq.pid ; }

dnat_wanted() { [ -f "$STATE/dns_on" ] ; }

dnat_on() {
    lan_info
    [ -n "${LAN_IP:-}" ] || { log "dnat: нет LAN IP"; return 1 ; }
    iptables -t nat -N "$CHAIN" 2>/dev/null || true
    iptables -t nat -F "$CHAIN"
    for net in 127.0.0.0/8 10.28.0.0/15 "$VPN_SUBNET"; do
        iptables -t nat -A "$CHAIN" -d "$net" -p udp --dport 53 -j RETURN
        iptables -t nat -A "$CHAIN" -d "$net" -p tcp --dport 53 -j RETURN
    done
    iptables -t nat -A "$CHAIN" -p udp --dport 53 -j DNAT --to-destination "$LAN_IP:$DNS_PORT"
    iptables -t nat -A "$CHAIN" -p tcp --dport 53 -j DNAT --to-destination "$LAN_IP:$DNS_PORT"
    iptables -t nat -N "$CHAIN_OUT" 2>/dev/null || true
    iptables -t nat -F "$CHAIN_OUT"
    iptables -t nat -A "$CHAIN_OUT" -m owner --uid-owner "$DNS_UID" -j RETURN
    iptables -t nat -A "$CHAIN_OUT" -j "$CHAIN"
    iptables -t nat -C PREROUTING -j "$CHAIN" 2>/dev/null || iptables -t nat -I PREROUTING 1 -j "$CHAIN"
    iptables -t nat -C OUTPUT -j "$CHAIN_OUT" 2>/dev/null || iptables -t nat -I OUTPUT 1 -j "$CHAIN_OUT"
    log "dnat: DNS всех контейнеров -> $LAN_IP:$DNS_PORT"
}

dnat_off() {
    for hook in PREROUTING OUTPUT; do
        for ch in "$CHAIN" "$CHAIN_OUT"; do
            while iptables -t nat -C "$hook" -j "$ch" 2>/dev/null; do iptables -t nat -D "$hook" -j "$ch"; done
        done
    done
    for ch in "$CHAIN" "$CHAIN_OUT"; do
        iptables -t nat -F "$ch" 2>/dev/null || true
        iptables -t nat -X "$ch" 2>/dev/null || true
    done
}

# ---------------------------------------------------------------- NAT в LAN
lan_access_wanted() { [ -f "$STATE/lan_access" ] ; }

lan_access_on() {
    lan_info
    echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null || true
    for _d in "$OVPN_DEV" "$WG0"; do
        rule_ensure filter FORWARD -i "$_d" -j ACCEPT
        rule_ensure filter FORWARD -o "$_d" -j ACCEPT
    done
    [ -n "${LAN_IF:-}" ] && rule_ensure nat POSTROUTING -s "$VPN_SUBNET" -o "$LAN_IF" -j MASQUERADE
    log "lan: NAT $VPN_SUBNET -> $LAN_IF"
}

lan_access_off() {
    for _d in "$OVPN_DEV" "$WG0"; do
        rule_del filter FORWARD -i "$_d" -j ACCEPT
        rule_del filter FORWARD -o "$_d" -j ACCEPT
    done
    lan_info
    [ -n "${LAN_IF:-}" ] && rule_del nat POSTROUTING -s "$VPN_SUBNET" -o "$LAN_IF" -j MASQUERADE
}

# ---------------------------------------------------------------- проба и откат
tun_dev() { if ip link show "$OVPN_DEV" >/dev/null 2>&1; then echo "$OVPN_DEV"; \
            elif ip link show "$WG0" >/dev/null 2>&1; then echo "$WG0"; fi ; }

# связь через туннель по IP, без DNS (DNS может идти по туннелю и врать)
probe_tunnel() {
    _dev=$(tun_dev); [ -n "$_dev" ] || return 1
    for _u in http://1.1.1.1/ https://1.1.1.1/; do
        _code=$(curl -s -o /dev/null -m 8 --interface "$_dev" -w '%{http_code}' "$_u" 2>/dev/null)
        case "$_code" in 200|301|302|403|404) return 0 ;; esac
    done
    ping -I "$_dev" -c1 -W3 1.1.1.1 >/dev/null 2>&1 && return 0
    return 1
}

# есть ли вообще выход в интернет напрямую (страховка: туннель мог убить сеть)
probe_direct() {
    _code=$(curl -s -o /dev/null -m 6 -w '%{http_code}' http://1.1.1.1/ 2>/dev/null)
    case "$_code" in 200|301|302|403|404) return 0 ;; esac
    ping -c1 -W3 1.1.1.1 >/dev/null 2>&1
}

stop_tunnel() { # снять всё, что относится к туннелю, не трогая выбор профиля
    _id=$(active_id)
    ovpn_stop "$_id"
    wg_stop
    dnat_off
}

# connect <id> — поднять профиль с автооткатом
connect() {
    _id=$1
    [ -n "$_id" ] || { set_error "профиль не выбран"; set_phase failed; return 1 ; }
    _type=$(prof_type "$_id")
    [ "$_type" = none ] && { set_error "в профиле нет .ovpn или .conf"; set_phase failed; return 1 ; }

    set_active "$_id"; clear_error; set_phase connecting
    stop_tunnel
    sleep 1

    case "$_type" in
        ovpn) ovpn_start "$_id" || { stop_tunnel; set_phase failed; return 1 ;} ;;
        wg)   wg_start   "$_id" || { stop_tunnel; set_phase failed; return 1 ;} ;;
    esac

    if dns_up; then dnat_wanted && dnat_on; else dnat_off; fi
    lan_access_wanted && lan_access_on

    # ждём, пока трафик реально пойдёт через туннель; иначе откат
    if full_tunnel "$_id"; then
        _i=0
        while [ "$_i" -lt "$PROBE_TIMEOUT" ]; do
            probe_tunnel && break
            ovpn_alive "$_id" >/dev/null 2>&1 || { [ "$_type" = wg ] && ip link show "$WG0" >/dev/null 2>&1 ; } || true
            sleep 5; _i=$((_i+5))
        done
        if [ "$_i" -ge "$PROBE_TIMEOUT" ]; then
            log "connect[$_id]: через туннель связи нет за ${PROBE_TIMEOUT}с — откат"
            stop_tunnel
            set_error "через туннель нет связи за ${PROBE_TIMEOUT} с — туннель выключен автоматически"
            set_phase failed
            probe_direct || log "откат: прямой сети тоже нет!"
            return 1
        fi
    fi

    set_since "$(date +%s)"
    set_phase on
    log "connect[$_id]: подключено ($_type)"
    return 0
}

disconnect() {
    stop_tunnel
    clear_active
    set_phase off
    log "disconnect: туннель выключен"
}

# ---------------------------------------------------------------- супервизор
watch() {
    _ph=$(phase)
    _id=$(active_id)
    case "$_ph" in
        on)
            if [ -n "$_id" ]; then
                case "$(prof_type "$_id")" in
                    ovpn)
                        if ! ovpn_alive "$_id"; then
                            log "watch: openvpn умер — переподключаю"
                            connect "$_id" || true
                        elif full_tunnel "$_id" && ! probe_tunnel; then
                            _f=$(cat "$STATE/probe_fail" 2>/dev/null || echo 0)
                            _f=$((_f+1)); echo "$_f" > "$STATE/probe_fail"
                            log "watch: проба через туннель не прошла ($_f)"
                            if [ "$_f" -ge 3 ]; then
                                log "watch: три провала подряд — переподключаю"
                                echo 0 > "$STATE/probe_fail"
                                connect "$_id" || true
                            fi
                        else
                            rm -f "$STATE/probe_fail"
                        fi
                        ;;
                    wg)
                        if ! ip link show "$WG0" >/dev/null 2>&1; then
                            log "watch: wg0 нет — переподключаю"; connect "$_id" || true
                        fi
                        ;;
                esac
            fi
            ;;
        connecting)
            # незавершённое подключение (упал контейнер в процессе) — снимаем
            _age=$(( $(date +%s) - $(stat -c %Y "$STATE/phase" 2>/dev/null || date +%s) ))
            [ "$_age" -gt 180 ] && { log "watch: зависшее connecting — откат"; stop_tunnel; set_phase failed; \
                                     set_error "подключение прервано" ; }
            ;;
    esac

    if [ "$_ph" = on ]; then
        ss -lnuH 2>/dev/null | grep -q ":$DNS_PORT " || dns_up || true
    fi
}

# ---------------------------------------------------------------- статус
status() {
    _ph=$(phase); _id=$(active_id); _type=$(prof_type "$_id")
    echo "phase: $_ph"
    echo "active: $_id ($_type)"
    echo "error: $(error)"
    echo "since: $(since)"
    case "$_type" in
        ovpn) echo "ovpn: alive=$(ovpn_alive "$_id" && echo yes || echo no) ip=$(tun_ip) pid=$(cat "$(ovpn_pid_file "$_id")" 2>/dev/null)" ;;
        wg)   echo "wg0: $(wg show "$WG0" 2>/dev/null | head -3 | tr '\n' ' ')" ;;
    esac
    echo "routes: $(ip -4 route show dev "$(tun_dev)" 2>/dev/null | wc -l)"
    echo "dns: $(ss -lnuH 2>/dev/null | grep -c ":$DNS_PORT ") -> $DNS_UPSTREAM (перехват: $(dnat_wanted && echo yes || echo no))"
    echo "lan_access: $(lan_access_wanted && echo yes || echo no)"
    lan_info; echo "lan: $LAN_IP/$LAN_IF/$LAN_GW net=$LAN_NET"
    echo "tunnel_ok: $(probe_tunnel && echo yes || echo no)"
    echo "direct_ok: $(probe_direct && echo yes || echo no)"
}

case "${1:-up}" in
    connect)     connect "${2:-}" ;;
    disconnect)  disconnect ;;
    up)          # совместимость: поднять активный профиль, если он был включён
                 if [ "$(phase)" = on ] && [ -n "$(active_id)" ]; then
                     [ -n "$(tun_dev)" ] || connect "$(active_id)" || true
                 fi ;;
    down)        stop_tunnel; dns_down; set_phase off ;;
    watch)       watch ;;
    dns)         _on=${2:-}; if [ "$_on" = off ]; then rm -f "$STATE/dns_on"; dnat_off; else \
                     mkdir -p "$STATE"; echo 1 > "$STATE/dns_on"; dns_up && dnat_on; fi ;;
    lan)         _on=${2:-}; if [ "$_on" = off ]; then rm -f "$STATE/lan_access"; lan_access_off; \
                     else mkdir -p "$STATE"; echo 1 > "$STATE/lan_access"; lan_access_on; fi ;;
    status)      status ;;
    *)           echo "usage: net.sh connect <id>|disconnect|up|down|watch|dns on|off|lan on|off|status"; exit 2 ;;
esac
