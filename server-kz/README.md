# Серверная часть (KZ, 5.39.253.63)

Что должно быть на OpenVPN-сервере, чтобы клиенты VPN видели Umbrel (10.29.0.2)
и домашнюю сеть за ним (192.168.11.0/24).

## Куда кладутся файлы

| файл репозитория | путь на сервере |
|---|---|
| `client-connect.sh`, `client-disconnect.sh` | `/etc/openvpn/server/scripts/` |
| `custom-up.sh`, `custom-down.sh` | `/root/antizapret/` (хуки AntiZapret, вызываются из up.sh/down.sh) |
| `umbrel-lan-route.sh` | `/root/antizapret/` |
| `umbrel-lan-route.service`, `.timer` | `/etc/systemd/system/` (`systemctl enable --now umbrel-lan-route.timer`) |

## Почему так

1. **Клиент ↔ клиент.** При `--data-channel-offload` (DCO 2.7) пакеты клиентов уходят
   в ядро, и `--client-to-client` ничего не делает. Но в FORWARD у AntiZapret стоит
   `DROP` по connmark для адресов вне ipset `antizapret-forward`, поэтому трафик
   между клиентами (в том числе к 10.29.0.2) режется. `custom-up.sh` добавляет
   ACCEPT-правила для 10.29.0.0/16 и 10.28.0.0/15 (внутри себя и в 192.168.11.0/24).
2. **Маршрут в домашнюю сеть.** `ccd/umbrel` c `ifconfig-push`/`iroute` ломает
   выдачу маршрутов клиенту (в связке с `duplicate-cn`), поэтому адрес выдаётся
   пулом, а маршрут `192.168.11.0/24 via <адрес umbrel>` держит root-таймер
   `umbrel-lan-route.timer` (openvpn работает под nobody и не может менять маршруты
   из client-connect — `RTNETLINK answers: Operation not permitted`).
3. **Push маршрута клиентам.** Строка `push "route 192.168.11.0 255.255.255.0"`
   должна быть **последней** — в конце `ccd/DEFAULT`, а не в основном конфиге:
   в начале PUSH_REPLY клиент ещё не создал tun и первый маршрут теряется
   (`net_route_v4_add ... dev [NULL]`).

## Проверено

Клиент в отдельном netns на сервере: `http://10.29.0.2/` → 200, `http://10.29.0.2:8666/` → 200,
`http://192.168.11.126/` → 200, `http://192.168.11.1/` → 307 (роутер).
