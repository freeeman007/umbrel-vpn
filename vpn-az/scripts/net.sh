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
# предупреждение (не ошибка): подключение состоялось, но что-то пришлось поправить
warn()       { cat "$STATE/warn" 2>/dev/null ; }
set_warn()   { mkdir -p "$STATE"; printf '%s\n' "$1" > "$STATE/warn" ; }
clear_warn() { rm -f "$STATE/warn" ; }
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
        case "$_i" in lo|azvpn|azp*|wg*|tun*|tap*|docker*|veth*|br-*|virbr*) continue ;;
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

# Резолверы выводятся мимо туннеля отдельными /32 — это надёжнее, чем метка в OUTPUT:
# маршрут /32 сильнее 0.0.0.0/1+128.0.0.0/1 и работает сразу, без ожидания проб.
# Зачем: сервер AZ на полном туннеле делает DNAT :53 клиентов в 127.2.2.2, который
# не отвечает, — и хост (вместе с агентом) остаётся без имён, хотя IP-связность есть.
protect_resolvers() {
    lan_info
    [ -n "${LAN_GW:-}" ] && [ -n "${LAN_IF:-}" ] || return 0
    _n=0
    for _ns in $(awk '/^nameserver[ \t]+[0-9.]+/{print $2}' /etc/resolv.conf 2>/dev/null) \
               "$DNS_UPSTREAM" 1.1.1.1 9.9.9.9 8.8.8.8; do
        case "$_ns" in 127.*|0.0.0.0|"") continue ;; esac
        ip route replace "$_ns/32" via "$LAN_GW" dev "$LAN_IF" 2>/dev/null && _n=$((_n+1))
    done
    [ "$_n" -gt 0 ] && log "dns: резолверы ($_n) выведены мимо туннеля через $LAN_GW"
    return 0
}

unprotect_resolvers() {
    for _ns in $(awk '/^nameserver[ \t]+[0-9.]+/{print $2}' /etc/resolv.conf 2>/dev/null) \
               "$DNS_UPSTREAM" 1.1.1.1 9.9.9.9 8.8.8.8; do
        case "$_ns" in 127.*|0.0.0.0|"") continue ;; esac
        ip route del "$_ns/32" 2>/dev/null
    done
    return 0
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
    # резолверы тоже мимо туннеля — иначе на полном туннеле сервер AZ уводит :53
    # в свой 127.2.2.2, и хост остаётся без имён (модель «не отвечает»)
    protect_resolvers

    _extra=""
    [ -f "$_dir/cred.txt" ] && _extra="--auth-user-pass $_dir/cred.txt"
    # ключ может быть зашифрован: пароль лежит в pass.txt (0600), задаётся из панели
    [ -f "$_dir/pass.txt" ] && _extra="$_extra --askpass $_dir/pass.txt"

    # --cd важен: сторонние провайдеры ссылаются на ca.crt/key из той же папки
    # --ping 5/--ping-restart 12 + игнор серверных ping-опций: первая сессия к этому
    # серверу иногда не проводит данные и висит до серверного ping-restart (30 с) —
    # на полном туннеле это 30 с без интернета у всего хоста. Свои таймауты дают ~12 с.
    # --explicit-exit-notify 1: при выключении честно сообщаем серверу, чтобы не
    # оставалась мёртвая сессия с тем же CN (duplicate-cn на сервере включён).
    openvpn --cd "$_dir" --config "$_conf" --dev "$OVPN_DEV" --dev-type tun \
            $_extra --log "$DATA/ovpn.log" --writepid "$(ovpn_pid_file "$_id")" --daemon \
            --script-security 2 --ping 5 --ping-restart 12 --explicit-exit-notify 1 \
            --pull-filter ignore "ping-restart" --pull-filter ignore "ping" 2>>"$DATA/ovpn.log" \
        || { set_error "openvpn не запустился (см. журнал)"; return 1; }

    _i=0
    while [ "$_i" -lt 45 ]; do
        [ -n "$(tun_ip)" ] && break
        ovpn_alive "$_id" || break
        sleep 1; _i=$((_i+1))
    done
    if [ -z "$(tun_ip)" ]; then
        case "$(tail -3 "$DATA/ovpn.log" 2>/dev/null)" in
            *"Private Key Password"*|*"neither stdin nor stderr are a tty"*)
                set_error "ключ профиля защищён паролем — задай его кнопкой с ключом на карточке профиля" ;;
            *) set_error "туннель не получил адрес (ошибка в профиле или сервер недоступен)" ;;
        esac
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

# AmneziaWG-параметры (Jc/Jmin/Jmax/S1..S4/H1..H4/I1..I5) понимает только awg.
# Обычный wg падает на всём файле из-за первой же такой строки («wg setconf:
# ошибка в конфиге»), хотя остальное — валидный WireGuard. Поэтому такие строки
# отбрасываем и предупреждаем в панели; если серверу действительно нужен AWG,
# рукопожатия не будет и это будет видно отдельной ошибкой ниже.
AWG_RE='^[[:space:]]*(Jc|Jmin|Jmax|S[1-4]|H[1-4]|I[1-5])[[:space:]]*='

wg_start() { # wg_start <id>
    _id=$1; _conf=$(prof_conf "$_id")
    [ -f "$_conf" ] || { set_error "нет конфига в профиле"; return 1; }
    lan_info
    ip link show "$WG0" >/dev/null 2>&1 || ip link add dev "$WG0" type wireguard || { set_error "не создаётся wg0"; return 1; }
    _addr=$(conf_get Address "$_conf")
    _mtu=$(conf_get MTU "$_conf"); [ -n "$_mtu" ] || _mtu=1420
    _ep=$(conf_get Endpoint "$_conf")
    _ep_host=${_ep%:*}
    _ep_ip=$(resolve4 "$_ep_host"); [ -n "$_ep_ip" ] || _ep_ip=$_ep_host
    [ -n "$_ep_ip" ] && [ -n "${LAN_GW:-}" ] && ip route replace "$_ep_ip/32" via "$LAN_GW" dev "$LAN_IF" 2>/dev/null
    _def0=$(ip -4 route show default | head -1)
    _awg=0
    grep -qE "$AWG_RE" "$_conf" 2>/dev/null && _awg=1
    grep -vE '^[[:space:]]*(Address|DNS|MTU)[[:space:]]*=' "$_conf" | grep -vE "$AWG_RE" > /run/wg0.strip
    if ! _werr=$(wg setconf "$WG0" /run/wg0.strip 2>&1); then
        set_error "wg setconf: $(printf '%s' "$_werr" | head -2 | tr '\n' ' ')"
        return 1
    fi
    if [ "$_awg" = 1 ]; then
        set_warn "в профиле были параметры AmneziaWG (Jc/S1/H1…) — обычный WireGuard их не понимает, они отброшены; туннель поднят как обычный WireGuard"
        log "wg[$_id]: строки AmneziaWG из конфига убраны"
    fi
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
    protect_resolvers

    # Подтверждение рукопожатия: при неверном порту, ключе или мёртвом сервере wg
    # не ругается — интерфейс просто молчит, а панель показывала «подключено».
    _i=0; _hs=0
    while [ "$_i" -lt 15 ]; do
        _hs=$(wg show "$WG0" latest-handshakes 2>/dev/null | awk 'NR==1{print $2+0}')
        [ "${_hs:-0}" -gt 0 ] && break
        sleep 1; _i=$((_i+1))
    done
    if [ "${_hs:-0}" -le 0 ]; then
        set_error "WireGuard не получил рукопожатие за 15 с: $_ep не отвечает или ключи не подходят"
        return 1
    fi
    log "wg[$_id]: up $(conf_get Address "$_conf"), рукопожатие есть"
    return 0
}

# ---------------------------------------------------------------- доп. туннели
# Второй и следующие профили нужны только ради маршрутов к своим сетям
# (корпоративная, домашняя и т.п.). Интернет всегда идёт через основной профиль:
# здесь default не ставится, DNS хоста не трогается, NAT и kill-switch относятся
# только к основному туннелю.
dev_aux() { # dev_aux <id> <type>
    _s=$(printf '%s' "$1" | tr 'A-Z' 'a-z' | tr -cd 'a-z0-9' | cut -c1-10)
    [ -n "$_s" ] || _s="x"
    if [ "$2" = wg ]; then printf 'wg%s' "$_s" ; else printf 'azp%s' "$_s" ; fi
}
aux_list()  { [ -f "$STATE/aux" ] && grep -v '^[[:space:]]*$' "$STATE/aux" ; }
aux_has()   { aux_list 2>/dev/null | grep -Fqx "$1" ; }
aux_add()   { mkdir -p "$STATE"; aux_has "$1" || printf '%s\n' "$1" >> "$STATE/aux" ; }
aux_del()   { mkdir -p "$STATE"; aux_list 2>/dev/null | grep -Fvx "$1" > "$STATE/aux.tmp"; \
              mv "$STATE/aux.tmp" "$STATE/aux" 2>/dev/null ; }
aux_clear() { rm -f "$STATE/aux" ; }
aux_ip()    { ip -4 -o addr show dev "$1" 2>/dev/null | sed -n 's/.* inet \([0-9.]*\)\/.*/\1/p' | head -1 ; }

# Сервер может прислать redirect-gateway или маршруты 0.0.0.0/1+128.0.0.0/1 даже
# в «сплит»-профиле. У доп. туннеля default быть не должно: интернет идёт через
# основной. Такие маршруты снимаем и, если default пропал совсем, возвращаем прежний.
aux_strip_default() { # aux_strip_default <dev> <прежний default>
    _d=$1; _prev=$2
    for _r in default 0.0.0.0/1 128.0.0.0/1; do
        ip -4 route show "$_r" dev "$_d" 2>/dev/null | grep -q . || continue
        ip -4 route del "$_r" dev "$_d" 2>/dev/null && log "aux[$_d]: убран $_r (интернет остаётся у основного туннеля)"
    done
    if [ -z "$(ip -4 route show default 2>/dev/null)" ] && [ -n "$_prev" ]; then
        ip -4 route replace $_prev 2>/dev/null && log "aux[$_d]: прежний default возвращён"
    fi
}
aux_routes() { ip -4 route show dev "$1" 2>/dev/null | grep -v '^default' | wc -l ; }

# dev_alive — интерфейс существует и (для ovpn) процесс жив
aux_alive() { # aux_alive <id>
    _t=$(prof_type "$1"); _d=$(dev_aux "$1" "$_t")
    ip link show "$_d" >/dev/null 2>&1 || return 1
    [ -n "$(aux_ip "$_d")" ] || return 1
    return 0
}

aux_ovpn_up() {
    _id=$1; _dir=$(prof_dir "$_id"); _conf=$(prof_conf "$_id"); _dev=$(dev_aux "$_id" ovpn)
    [ -f "$_conf" ] || { set_warn "нет конфига в профиле"; return 1; }
    lan_info
    _ep=$(sed -n 's/^[[:space:]]*remote[[:space:]]\+\([^[:space:]]\+\)[[:space:]]\+\([0-9]\+\).*/\1 \2/p' "$_conf" | head -1)
    _ep_host=$(echo "$_ep" | cut -d' ' -f1)
    _ep_ip=$(resolve4 "$_ep_host"); [ -n "$_ep_ip" ] || _ep_ip=$_ep_host
    [ -n "$_ep_ip" ] && [ -n "${LAN_GW:-}" ] && ip route replace "$_ep_ip/32" via "$LAN_GW" dev "$LAN_IF" 2>/dev/null
    protect_resolvers
    _def0=$(ip -4 route show default | head -1)
    _extra=""
    [ -f "$_dir/cred.txt" ] && _extra="--auth-user-pass $_dir/cred.txt"
    [ -f "$_dir/pass.txt" ] && _extra="$_extra --askpass $_dir/pass.txt"
    # redirect-gateway и dhcp-option от сервера отбрасываем: default и DNS остаются
    # у основного туннеля, а push'и нумерации («route 10.0.0.0/8») применяются как есть
    openvpn --cd "$_dir" --config "$_conf" --dev "$_dev" --dev-type tun \
            $_extra --log "$DATA/ovpn.log" --writepid "$STATE/ovpnx.$_id.pid" --daemon \
            --script-security 2 --ping 5 --ping-restart 12 --explicit-exit-notify 1 \
            --pull-filter ignore "ping-restart" --pull-filter ignore "ping" \
            --pull-filter ignore "redirect-gateway" --pull-filter ignore "dhcp-option" \
            2>>"$DATA/ovpn.log" \
        || { set_warn "openvpn (доп. $_id) не запустился (см. журнал)"; return 1; }
    _i=0
    while [ "$_i" -lt 45 ]; do
        [ -n "$(aux_ip "$_dev")" ] && break
        sleep 1; _i=$((_i+1))
    done
    if [ -z "$(aux_ip "$_dev")" ]; then
        case "$(tail -3 "$DATA/ovpn.log" 2>/dev/null)" in
            *"Private Key Password"*|*"neither stdin nor stderr are a tty"*)
                set_warn "ключ профиля $_id защищён паролем — задай его кнопкой с ключом на карточке профиля" ;;
            *) set_warn "доп. туннель $_id не получил адрес (сервер недоступен или ошибка в профиле)" ;;
        esac
        return 1
    fi
    rule_ensure mangle POSTROUTING -o "$_dev" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
    rule_ensure mangle OUTPUT -o "$_dev" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
    protect_lan
    aux_strip_default "$_dev" "$_def0"
    log "aux[$_id]: up $(aux_ip "$_dev") на $_dev, маршрутов $(aux_routes "$_dev")"
    return 0
}

aux_wg_up() {
    _id=$1; _conf=$(prof_conf "$_id"); _dev=$(dev_aux "$_id" wg)
    [ -f "$_conf" ] || { set_warn "нет конфига в профиле"; return 1; }
    lan_info
    ip link show "$_dev" >/dev/null 2>&1 || ip link add dev "$_dev" type wireguard \
        || { set_warn "не создаётся $_dev"; return 1; }
    _addr=$(conf_get Address "$_conf")
    _mtu=$(conf_get MTU "$_conf"); [ -n "$_mtu" ] || _mtu=1420
    _ep=$(conf_get Endpoint "$_conf"); _ep_host=${_ep%:*}
    _ep_ip=$(resolve4 "$_ep_host"); [ -n "$_ep_ip" ] || _ep_ip=$_ep_host
    [ -n "$_ep_ip" ] && [ -n "${LAN_GW:-}" ] && ip route replace "$_ep_ip/32" via "$LAN_GW" dev "$LAN_IF" 2>/dev/null
    grep -vE '^[[:space:]]*(Address|DNS|MTU)[[:space:]]*=' "$_conf" | grep -vE "$AWG_RE" > "/run/$_dev.strip"
    if ! _werr=$(wg setconf "$_dev" "/run/$_dev.strip" 2>&1); then
        set_warn "wg setconf ($_id): $(printf '%s' "$_werr" | head -2 | tr '\n' ' ')"
        ip link del "$_dev" 2>/dev/null; return 1
    fi
    echo "$_addr" | grep -q '/' || _addr="$_addr/32"
    ip -4 addr show dev "$_dev" | grep -q " ${_addr%/*}/" || ip -4 addr add "$_addr" dev "$_dev"
    # маршруты — только конкретные сети: 0.0.0.0/0 здесь означал бы «интернет-профиль»
    conf_get AllowedIPs "$_conf" | tr ',' '\n' | sed 's/^[[:space:]]*//; s/[[:space:]]*$//' | grep -v '^$' \
        | grep -vE '^(0\.0\.0\.0/0|0\.0\.0\.0/1|128\.0\.0\.0/1|::/0)$' \
        | sed "s|^|route replace |; s|\$| dev $_dev|" > "/run/$_dev.routes"
    if [ ! -s "/run/$_dev.routes" ]; then
        ip link del "$_dev" 2>/dev/null
        set_warn "в профиле $_id нет сетей кроме 0.0.0.0/0 — это интернет-профиль, его подключают кнопкой питания, а не как дополнительный"
        return 1
    fi
    ip link set mtu "$_mtu" up dev "$_dev" || { set_warn "$_dev не поднимается"; return 1; }
    ip -4 -batch "/run/$_dev.routes" >/dev/null 2>&1 || log "aux[$_id]: часть маршрутов не применилась"
    rule_ensure mangle POSTROUTING -o "$_dev" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
    rule_ensure mangle OUTPUT -o "$_dev" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
    protect_lan
    _i=0; _hs=0
    while [ "$_i" -lt 15 ]; do
        _hs=$(wg show "$_dev" latest-handshakes 2>/dev/null | awk 'NR==1{print $2+0}')
        [ "${_hs:-0}" -gt 0 ] && break
        sleep 1; _i=$((_i+1))
    done
    if [ "${_hs:-0}" -le 0 ]; then
        set_warn "WireGuard ($_id) не получил рукопожатие за 15 с: $_ep не отвечает или ключи не подходят"
        ip -4 route flush dev "$_dev" 2>/dev/null; ip link del "$_dev" 2>/dev/null
        return 1
    fi
    aux_strip_default "$_dev" "$_def0"
    log "aux[$_id]: up $_addr на $_dev, маршрутов $(aux_routes "$_dev")"
    return 0
}

aux_up() { # aux_up <id> — поднять профиль как дополнительный (только маршруты)
    _id=$1
    [ -n "$_id" ] || { set_warn "профиль не выбран"; return 1; }
    _t=$(prof_type "$_id")
    [ "$_t" = none ] && { set_warn "в профиле нет .ovpn или .conf"; return 1; }
    if [ "$_id" = "$(active_id)" ]; then
        set_warn "этот профиль уже подключён как основной — он и так работает"
        return 1
    fi
    if full_tunnel "$_id"; then
        set_warn "это профиль «весь трафик»: дополнительным он забрал бы интернет у основного. Подключай его кнопкой питания"
        return 1
    fi
    aux_alive "$_id" && { aux_add "$_id"; log "aux[$_id]: уже поднят"; return 0; }
    aux_add "$_id"
    case "$_t" in
        ovpn) aux_ovpn_up "$_id" || { aux_forget "$_id"; return 1 ;} ;;
        wg)   aux_wg_up   "$_id" || { aux_forget "$_id"; return 1 ;} ;;
    esac
    return 0
}

aux_down() { # aux_down <id>
    _id=$1; [ -n "$_id" ] || return 0
    _t=$(prof_type "$_id"); _dev=$(dev_aux "$_id" "$_t")
    pkill -f "openvpn.*--dev $_dev" 2>/dev/null || true
    rm -f "$STATE/ovpnx.$_id.pid"
    rule_del mangle POSTROUTING -o "$_dev" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
    rule_del mangle OUTPUT -o "$_dev" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
    ip -4 route flush dev "$_dev" 2>/dev/null || true
    ip -4 addr flush dev "$_dev" 2>/dev/null || true
    ip link del "$_dev" 2>/dev/null || true
    log "aux[$_id]: снят"
}

aux_forget() { aux_down "$1"; aux_del "$1" ; }

aux_all_down() { for _a in $(aux_list 2>/dev/null); do aux_down "$_a"; done ; }
aux_forget_all() { for _a in $(aux_list 2>/dev/null); do aux_forget "$_a"; done ; }

# reup — поднять все дополнительные профили, которые были включены (после основного)
aux_reup() {
    aux_list 2>/dev/null | while read -r _a; do
        [ -n "$_a" ] || continue
        aux_alive "$_a" && continue
        log "aux: возвращаю $_a"
        aux_up "$_a" || log "aux: $_a не поднялся"
    done
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

# Подсети активного туннеля. Пул клиентов задаёт сервер и он не всегда равен
# AZ_VPN_SUBNET (KZ выдаёт 10.29.0.0/22, AZ-шный WG — 10.29.8.0/24), поэтому
# берём реальную сеть с интерфейса: иначе MASQUERADE не покрывает клиентов
# и ответы из домашней сети уходят в никуда.
tunnel_nets() {
    _nets="$VPN_SUBNET"
    _d=$(tun_dev)
    [ -n "$_d" ] || { echo "$_nets"; return 0 ; }
    for _n in $(ip -4 route show dev "$_d" scope link 2>/dev/null | awk '$1 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\/[0-9]+$/ {print $1}'); do
        case " $_nets " in *" $_n "*) ;; *) _nets="$_nets $_n" ;; esac
    done
    echo "$_nets"
}

lan_access_on() {
    lan_info
    echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null || true
    for _d in "$OVPN_DEV" "$WG0"; do
        rule_ensure filter FORWARD -i "$_d" -j ACCEPT
        rule_ensure filter FORWARD -o "$_d" -j ACCEPT
    done
    : > "$STATE/lan_nets"
    for _n in $(tunnel_nets); do
        echo "$_n" >> "$STATE/lan_nets"
        [ -n "${LAN_IF:-}" ] && rule_ensure nat POSTROUTING -s "$_n" -o "$LAN_IF" -j MASQUERADE
    done
    log "lan: NAT $(tr '\n' ' ' < "$STATE/lan_nets" | sed 's/ $//') -> $LAN_IF"
}

lan_access_off() {
    for _d in "$OVPN_DEV" "$WG0"; do
        rule_del filter FORWARD -i "$_d" -j ACCEPT
        rule_del filter FORWARD -o "$_d" -j ACCEPT
    done
    lan_info
    # снимаем по записанному списку: после отключения туннеля подсеть с интерфейса уже не прочитать
    _list=$(cat "$STATE/lan_nets" 2>/dev/null)
    [ -n "$_list" ] || _list="$VPN_SUBNET"
    for _n in $_list; do
        [ -n "${LAN_IF:-}" ] && rule_del nat POSTROUTING -s "$_n" -o "$LAN_IF" -j MASQUERADE
    done
    rm -f "$STATE/lan_nets"
}

# ---------------------------------------------------------------- проба и откат
tun_dev() { if ip link show "$OVPN_DEV" >/dev/null 2>&1; then echo "$OVPN_DEV"; \
            elif ip link show "$WG0" >/dev/null 2>&1; then echo "$WG0"; fi ; }

# шлюз туннеля (via-адрес любого маршрута в tun)
tun_gw() {
    _d=$(tun_dev); [ -n "$_d" ] || return 1
    ip -4 route show dev "$_d" 2>/dev/null | awk '/ via /{print $3; exit}'
}

# связь через туннель по IP, без DNS (DNS может идти по туннелю и врать).
# Сначала пинг шлюза туннеля — он отвечает и в сплит-режиме, где 1.1.1.1 в туннель не маршрутизируется.
probe_tunnel() {
    _dev=$(tun_dev); [ -n "$_dev" ] || return 1
    _gw=$(tun_gw)
    [ -n "$_gw" ] && ping -I "$_dev" -c1 -W3 "$_gw" >/dev/null 2>&1 && return 0
    for _u in http://1.1.1.1/ https://1.1.1.1/; do
        _code=$(curl -s -o /dev/null -m 8 --interface "$_dev" -w '%{http_code}' "$_u" 2>/dev/null)
        case "$_code" in 200|301|302|403|404) return 0 ;; esac
    done
    ping -I "$_dev" -c1 -W3 1.1.1.1 >/dev/null 2>&1 && return 0
    return 1
}

# полный туннель определяем по факту (default ушёл в tun), а не только по конфигу:
# сервер может пушить redirect-gateway, которого в .ovpn нет
tunnel_is_default() {
    _d=$(tun_dev); [ -n "$_d" ] || return 1
    ip -4 route show dev "$_d" 2>/dev/null | grep -qE '^(default|0\.0\.0\.0/1|128\.0\.0\.0/1)( |$)'
}

# есть ли вообще выход в интернет напрямую (страховка: туннель мог убить сеть)
probe_direct() {
    _code=$(curl -s -o /dev/null -m 6 -w '%{http_code}' http://1.1.1.1/ 2>/dev/null)
    case "$_code" in 200|301|302|403|404) return 0 ;; esac
    ping -c1 -W3 1.1.1.1 >/dev/null 2>&1
}

# --- DNS при полном туннеле -------------------------------------------------
# Сервер в туннеле перехватывает DNS и отвечает своими адресами, по которым снаружи
# ничего не открывается: сервер остаётся без имён (по IP всё работает, curl — нет).
# Поэтому DNS-трафик хоста выводим мимо туннеля прямо в локальный шлюз: имена
# получают настоящие адреса, а сам трафик идёт через туннель.
DNS_MARK=0x53
DNS_RT=53

tunnel_dns_on() {
    lan_info
    if [ -z "${LAN_GW:-}" ] || [ -z "${LAN_IF:-}" ]; then
        log "dns: нет локального шлюза — DNS оставляю как есть"
        return 1
    fi
    ip route replace default via "$LAN_GW" dev "$LAN_IF" table "$DNS_RT" 2>/dev/null
    ip rule add fwmark "$DNS_MARK" lookup "$DNS_RT" priority 999 2>/dev/null || true
    for _p in udp tcp; do
        iptables -t mangle -C OUTPUT -p "$_p" --dport 53 -j MARK --set-mark "$DNS_MARK" 2>/dev/null || \
            iptables -t mangle -A OUTPUT -p "$_p" --dport 53 -j MARK --set-mark "$DNS_MARK" 2>/dev/null
    done
    mkdir -p "$STATE"; echo "$LAN_GW" >"$STATE/dns_bypass"
    log "dns: DNS хоста идёт мимо туннеля через $LAN_GW (имена — настоящие)"
}

tunnel_dns_off() {
    for _p in udp tcp; do
        while iptables -t mangle -D OUTPUT -p "$_p" --dport 53 -j MARK --set-mark "$DNS_MARK" 2>/dev/null; do :; done
    done
    while ip rule del fwmark "$DNS_MARK" lookup "$DNS_RT" priority 999 2>/dev/null; do :; done
    ip route flush table "$DNS_RT" 2>/dev/null
    # подчистить правила от прежней схемы (DNAT в резолвер туннеля), если остались
    for _p in udp tcp; do
        while iptables -t nat -D OUTPUT -p "$_p" --dport 53 -j VPN_DNS 2>/dev/null; do :; done
    done
    iptables -t nat -F VPN_DNS 2>/dev/null
    iptables -t nat -X VPN_DNS 2>/dev/null
    rm -f "$STATE/dns_bypass" "$STATE/tunnel_dns"
}

# dns_probe — резолвится ли имя обычным путём (через локальный шлюз), 3 попытки по 5 с
dns_probe() {
    _i=0
    while [ "$_i" -lt 3 ]; do
        nslookup example.com "${LAN_GW:-192.168.11.1}" >/dev/null 2>&1 && return 0
        sleep 5; _i=$((_i+1))
    done
    return 1
}

# снять мусор прошлых попыток: живой openvpn, адрес/маршруты/устройство туннеля.
# Без этого следующая попытка упирается в "ip addr add ... File exists" и
# "ERROR: Linux route add command failed" — и туннель формально поднят, но без трафика.
tunnel_clean() {
    pkill -f "openvpn.*--dev $OVPN_DEV" 2>/dev/null || true
    rm -f "$STATE"/ovpn.*.pid
    _i=0
    while [ "$_i" -lt 10 ] && pgrep -f "openvpn.*--dev $OVPN_DEV" >/dev/null 2>&1; do
        sleep 1; _i=$((_i+1))
    done
    for _d in "$OVPN_DEV" "$WG0"; do
        ip link show "$_d" >/dev/null 2>&1 || continue
        ip -4 route flush dev "$_d" 2>/dev/null || true
        ip -4 addr flush dev "$_d" 2>/dev/null || true
        ip link del "$_d" 2>/dev/null || true
    done
}

stop_tunnel() { # снять всё, что относится к туннелю, не трогая выбор профиля
    _id=$(active_id)
    ovpn_stop "$_id"
    wg_stop
    tunnel_clean
    dnat_off
    tunnel_dns_off
    unprotect_resolvers
    clear_warn
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

    # DNS хоста НЕ трогаем, пока трафик через туннель не подтверждён: если туннель
    # окажется мёртвым, хост и все host-network приложения (включая агента) остаются
    # без имён на все 90 с пробы — именно это роняло сервер в цикле переподключений.

    # ждём, пока трафик реально пойдёт через туннель; иначе откат
    if tunnel_is_default; then
        _i=0
        while [ "$_i" -lt "$PROBE_TIMEOUT" ]; do
            probe_tunnel && break
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
        # трафик через туннель подтверждён — только теперь уводим DNS хоста в туннель
        tunnel_dns_on
        if ! dns_probe; then
            log "connect[$_id]: через туннель не резолвятся имена — откат"
            stop_tunnel
            set_error "через туннель не работают имена (DNS) — туннель выключен автоматически"
            set_phase failed
            return 1
        fi
    else
        log "connect[$_id]: сплит-режим (default не через туннель), автооткат по пробе не нужен"
    fi

    # даже в сплит-режиме: если сеть пропала совсем — откат
    if ! probe_direct && ! probe_tunnel; then
        log "connect[$_id]: после поднятия нет ни прямого выхода, ни туннеля — откат"
        stop_tunnel
        set_error "после подключения пропала связь — туннель выключен автоматически"
        set_phase failed
        return 1
    fi

    set_since "$(date +%s)"
    set_phase on
    log "connect[$_id]: подключено ($_type)"
    # дополнительные туннели (корпоративные сети и т.п.) возвращаем после основного
    aux_reup 2>/dev/null || true
    return 0
}

disconnect() {
    aux_all_down
    stop_tunnel
    clear_active
    set_phase off
    log "disconnect: туннель выключен"
}

# --- автоподъём после перезагрузки -------------------------------------------
# want_on ставится, когда пользователь включает туннель, и снимается при выключении:
# именно он отличает «сервер перезагрузился» от «пользователь сам выключил VPN».
want_on_set()   { mkdir -p "$STATE"; : > "$STATE/want_on" ; }
want_on_clear() { rm -f "$STATE/want_on" "$STATE/autostart" ; }

# net_ready — есть default-маршрут и резолвятся имена (после ребута сеть поднимается не сразу)
net_ready() {
    [ -n "$(ip route show default 2>/dev/null)" ] || return 1
    [ -n "$(resolve4 "api.deepseek.com" 2>/dev/null)" ] && return 0
    [ -n "$(resolve4 "example.com" 2>/dev/null)" ] && return 0
    return 1
}

resume() { # resume [id] — id передаёт app.py при автостарте, иначе берём активный профиль
    if [ -n "${1:-}" ]; then
        _id=$1
    else
        [ -f "$STATE/want_on" ] || { log "resume: автоподъём не нужен (туннель был выключен)"; return 0 ; }
        _id=$(active_id)
    fi
    [ -n "$_id" ] || { log "resume: профиль не выбран — поднимать нечего"; return 0 ; }
    [ "$(phase)" = on ] && [ -n "$(tun_dev)" ] && { log "resume: уже поднят"; return 0 ; }

    _i=0
    while [ "$_i" -lt 60 ]; do
        net_ready && break
        sleep 2; _i=$((_i+1))
    done
    [ "$_i" -lt 60 ] || { log "resume: сети нет за 120 с — автоподъём пропущен"; return 1 ; }

    _t=0
    while [ "$_t" -lt 3 ]; do
        _t=$((_t+1))
        log "resume: подъём профиля $_id (попытка $_t)"
        connect "$_id" && { log "resume: туннель поднят автоматически"; return 0 ; }
        sleep 15
    done
    log "resume: поднять $_id не удалось за 3 попытки"
    return 1
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
                        elif tunnel_is_default && ! probe_tunnel; then
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

    # страховка: перехват DNS хоста живёт только вместе с туннелем. Если туннель не
    # поднят (упал контейнер в момент пробы, ovpn умер, откат) — правила снимаем,
    # иначе хост остаётся без имён и «висит» весь сервер вместе с агентами.
    if [ "$_ph" != connecting ] && [ -f "$STATE/tunnel_dns" ] && ! tunnel_is_default; then
        tunnel_dns_off
        log "watch: туннель не поднят — перехват DNS снят"
    fi

    if [ "$_ph" = on ]; then
        ss -lnuH 2>/dev/null | grep -q ":$DNS_PORT " || dns_up || true
        # доп. туннели: устройство пропало — поднимаем заново (не чаще раза в цикл)
        for _a in $(aux_list 2>/dev/null); do
            [ -n "$_a" ] || continue
            aux_alive "$_a" || { log "watch: доп. туннель $_a пропал — поднимаю"; aux_up "$_a" || true; }
        done
    fi
}

# ---------------------------------------------------------------- статус
status() {
    _ph=$(phase); _id=$(active_id); _type=$(prof_type "$_id")
    echo "phase: $_ph"
    echo "active: $_id ($_type)"
    echo "error: $(error)"
    echo "warn: $(warn)"
    echo "since: $(since)"
    case "$_type" in
        ovpn) echo "ovpn: alive=$(ovpn_alive "$_id" && echo yes || echo no) ip=$(tun_ip) pid=$(cat "$(ovpn_pid_file "$_id")" 2>/dev/null)" ;;
        wg)   echo "wg0: $(wg show "$WG0" 2>/dev/null | head -3 | tr '\n' ' ')" ;;
    esac
    echo "routes: $(ip -4 route show dev "$(tun_dev)" 2>/dev/null | wc -l)"
    echo "dns: $(ss -lnuH 2>/dev/null | grep -c ":$DNS_PORT ") -> $DNS_UPSTREAM (перехват: $(dnat_wanted && echo yes || echo no))"
    echo "tunnel_dns: $(cat "$STATE/tunnel_dns" 2>/dev/null || echo none) -> правило $(iptables -t nat -S OUTPUT 2>/dev/null | grep -c VPN_DNS)"
    echo "lan_access: $(lan_access_wanted && echo yes || echo no)"
    lan_info; echo "lan: $LAN_IP/$LAN_IF/$LAN_GW net=$LAN_NET"
    for _a in $(aux_list 2>/dev/null); do
        _at=$(prof_type "$_a"); _ad=$(dev_aux "$_a" "$_at")
        echo "aux: $_a|$_at|$_ad|$(aux_ip "$_ad")|$(aux_routes "$_ad")|$(aux_alive "$_a" && echo up || echo down)"
    done
    echo "tunnel_ok: $(probe_tunnel && echo yes || echo no)"
    echo "direct_ok: $(probe_direct && echo yes || echo no)"
}

case "${1:-up}" in
    connect)     want_on_set; connect "${2:-}" ;;
    disconnect)  disconnect ;;
    forget)      want_on_clear; log "resume: намерение включения снято" ;;
    resume)      resume "${2:-}" ;;
    stop)        # снять туннель, но СОХРАНИТЬ намерение: для trap при остановке контейнера,
                 # чтобы после старта resume поднял профиль обратно
                 stop_tunnel; dns_down; set_phase off ;;
    up)          # совместимость: поднять активный профиль, если он был включён
                 if [ "$(phase)" = on ] && [ -n "$(active_id)" ]; then
                     [ -n "$(tun_dev)" ] || connect "$(active_id)" || true
                 fi ;;
    down)        want_on_clear; stop_tunnel; dns_down; set_phase off ;;
    watch)       watch ;;
    guard)       # саморемонт при старте контейнера/по вызову: перехват DNS без живого туннеля не нужен
                 if ! tunnel_is_default || [ "$(phase)" != on ]; then
                     if [ -f "$STATE/tunnel_dns" ]; then
                         tunnel_dns_off; echo "guard: перехват DNS снят (туннель не поднят)"
                     else
                         echo "guard: перехвата DNS нет — чисто"
                     fi
                 else
                     echo "guard: туннель поднят — перехват оставлен"
                 fi ;;
    dns)         _on=${2:-}; if [ "$_on" = off ]; then rm -f "$STATE/dns_on"; dnat_off; else \
                     mkdir -p "$STATE"; echo 1 > "$STATE/dns_on"; dns_up && dnat_on; fi ;;
    lan)         _on=${2:-}; if [ "$_on" = off ]; then rm -f "$STATE/lan_access"; lan_access_off; \
                     else mkdir -p "$STATE"; echo 1 > "$STATE/lan_access"; lan_access_on; fi ;;
    aux)         # aux up <id> | aux off <id> | aux list
                 _cmd=${2:-list}
                 case "$_cmd" in
                     up)   aux_up "${3:-}" ;;
                     off)  aux_forget "${3:-}" ;;
                     list) for _a in $(aux_list 2>/dev/null); do
                               _at=$(prof_type "$_a"); _ad=$(dev_aux "$_a" "$_at")
                               echo "$_a|$_at|$_ad|$(aux_ip "$_ad")|$(aux_routes "$_ad")"
                           done ;;
                     *)    echo "usage: net.sh aux up <id>|off <id>|list"; exit 2 ;;
                 esac ;;
    status)      status ;;
    *)           echo "usage: net.sh connect <id>|disconnect|resume|up|down|watch|aux up|off <id>|aux list|dns on|off|lan on|off|status"; exit 2 ;;
esac
