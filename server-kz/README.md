# Серверная часть (KZ, `<VPN_SERVER_IP>`)

Что должно быть на OpenVPN-сервере, чтобы клиенты VPN видели Umbrel (`<UMBREL_TUNNEL_IP>`)
и домашнюю сеть за ним (`<HOME_LAN>`).

Конкретные адреса в репозитории не хранятся: скрипты читают их из
`/root/antizapret/local.env` (образец — `local.env.example`, путь переопределяется
переменной `AZ_LOCAL_CONF`). Если файла нет, правила «в домашнюю сеть» просто не ставятся —
интернет через туннель и доступ клиент↔клиент работают как обычно.

## Куда кладутся файлы

| файл репозитория | путь на сервере |
|---|---|
| `client-connect.sh`, `client-disconnect.sh` | `/etc/openvpn/server/scripts/` |
| `custom-up.sh`, `custom-down.sh` | `/root/antizapret/` (хуки AntiZapret, вызываются из up.sh/down.sh) |
| `umbrel-lan-route.sh` | `/root/antizapret/` |
| `umbrel-lan-route.service`, `.timer` | `/etc/systemd/system/` (`systemctl enable --now umbrel-lan-route.timer`) |
| `local.env.example` | скопировать в `/root/antizapret/local.env`, права `600` |

## Почему так

1. **Клиент ↔ клиент.** При `--data-channel-offload` (DCO 2.7) пакеты клиентов уходят
   в ядро, и `--client-to-client` ничего не делает. Но в FORWARD у AntiZapret стоит
   `DROP` по connmark для адресов вне ipset `antizapret-forward`, поэтому трафик
   между клиентами (в том числе к адресу Umbrel в туннеле) режется. `custom-up.sh`
   добавляет ACCEPT-правила для подсетей пула — внутри себя и, если задан `HOME_LAN`,
   в домашнюю сеть.
2. **Маршрут в домашнюю сеть.** `ccd/umbrel` c `ifconfig-push`/`iroute` ломает
   выдачу маршрутов клиенту (в связке с `duplicate-cn`), поэтому адрес выдаётся
   пулом, а маршрут `<HOME_LAN> via <адрес umbrel>` держит root-таймер
   `umbrel-lan-route.timer` (openvpn работает под nobody и не может менять маршруты
   из client-connect — `RTNETLINK answers: Operation not permitted`).
3. **Push маршрута клиентам.** Строка `push "route <HOME_NET> <HOME_MASK>"`
   должна быть **последней** — в конце `ccd/DEFAULT`, а не в основном конфиге:
   в начале PUSH_REPLY клиент ещё не создал tun и первый маршрут теряется
   (`net_route_v4_add ... dev [NULL]`).

## Проверено

Клиент в отдельном netns на сервере: `http://<UMBREL_TUNNEL_IP>/` → 200,
`http://<UMBREL_TUNNEL_IP>:8666/` → 200, `http://<HOME_HOST>/` → 200,
`http://<HOME_GW>/` → 307 (роутер).
