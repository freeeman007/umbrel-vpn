#!/bin/sh
# Проверка net.sh guard: два сценария, stateful-заглушки ip/iptables.
# В сценарии 1 заранее кладём правила перехвата DNS (в т.ч. дубликат), чтобы
# убедиться, что цикл "удаляй, пока удаляется" завершается и снимает их все.
# ВАЖНО: путь LOG должен быть экспортирован — заглушки пишут в него.
cd "$(dirname "$0")" || exit 1
_sd=$PWD
_root="$(cd "$_sd/../.." && pwd)"
NET="$_root/scripts/net.sh"
[ -f "$NET" ] || NET="$_root/store/vpn-az/scripts/net.sh"
cp "$NET" net_up.sh
export PATH=$PWD/bin:$PATH

UDP='OUTPUT -p udp --dport 53 -j MARK --set-mark 0x53'
TCP='OUTPUT -p tcp --dport 53 -j MARK --set-mark 0x53'

seed() {
    mkdir -p "$1/log/ipt" "$1/state"
    printf '%s\n%s\n%s\n' "$UDP" "$UDP" "$TCP" > "$1/log/ipt/mangle"
}

echo "=== сценарий 1: перехват есть, туннеля нет (phase=failed)"
rm -rf d1; seed d1
echo 10.29.0.1 > d1/state/tunnel_dns; echo failed > d1/state/phase
echo "правил mangle до: $(wc -l < d1/log/ipt/mangle)"
: > log1.txt; export LOG=$PWD/log1.txt
IPT_STATE=$PWD/d1/log/ipt DATA=$PWD/d1 FAKE_TUN=0 timeout 30 sh "$NET" guard
echo "rc=$?"
echo "файл tunnel_dns: $([ -f d1/state/tunnel_dns ] && echo ОСТАЛСЯ || echo снят)"
echo "правил mangle после: $(wc -l < d1/log/ipt/mangle)"
echo "вызовов iptables -D: $(grep -c -- '-D OUTPUT' log1.txt)"

echo "=== сценарий 2: туннель поднят и phase=on"
rm -rf d2; seed d2
echo 10.29.0.1 > d2/state/tunnel_dns; echo on > d2/state/phase
echo "правил mangle до: $(wc -l < d2/log/ipt/mangle)"
: > log2.txt; export LOG=$PWD/log2.txt
IPT_STATE=$PWD/d2/log/ipt DATA=$PWD/d2 FAKE_TUN=1 FAKE_ROUTES='default via 10.28.0.1 dev azvpn' timeout 30 sh "$NET" guard
echo "rc=$?"
echo "файл tunnel_dns: $([ -f d2/state/tunnel_dns ] && echo ОСТАЛСЯ || echo снят)"
echo "правил mangle после: $(wc -l < d2/log/ipt/mangle)"
echo "вызовов iptables -D: $(grep -c -- '-D OUTPUT' log2.txt)"
