# pia-gluetun

`ghcr.io/tekgnosis-net/pia-gluetun` is [gluetun](https://github.com/qdm12/gluetun)
(pinned to **v3.41.3**) plus everything needed to run **Private Internet
Access WireGuard with port forwarding unattended**: keys are registered inside
the container seconds before connecting, `SERVER_NAMES` is computed rather than
maintained by hand, and when the tunnel breaks the container re-registers and
reconnects **without restarting itself**, so containers attached with
`network_mode: service:gluetun` (qBittorrent, mousehole) are never orphaned.

It exists because the obvious alternatives all fail for this use case; the
reasons are recorded in [`../CLAUDE.md`](../CLAUDE.md) and the design in
[`../docs/superpowers/specs/2026-09-16-pia-gluetun-design.md`](../docs/superpowers/specs/2026-09-16-pia-gluetun-design.md).

Target: Synology DSM 7 Container Manager (compose project, no `.env`),
userspace WireGuard. Also works with plain `docker compose`.

## Quick start

1. Create the host folders (see the header of
   [`compose.example.yaml`](compose.example.yaml)).
2. Copy `compose.example.yaml` into a Container Manager project, set
   `PIA_USER`, `PIA_PASS`, `PIA_REGION`, `PUID`/`PGID`, `TZ`, the mousehole
   password and `MOUSEHOLE_ALLOWED_HOSTS`.
3. In qBittorrent → Options → Web UI, enable **Bypass authentication for
   clients on localhost** so the forwarded port can be pushed in. The compose
   sets both `VPN_PORT_FORWARDING_UP_COMMAND` and `_DOWN_COMMAND`; keep the
   down command, because qBittorrent only re-binds when the port value
   changes and a same-server recovery reuses the same port.
4. Start the project. Logs to look for:

```
[pia-entrypoint] gluetun will connect to zurich412 at 156.146.62.x:1337 (region swiss)
INFO [port forwarding] port forwarded is 45123
[pia-recover] started: interval=60s threshold=3 ...
```

The image is published for `linux/amd64`, `linux/arm64` and `linux/arm/v7`.

## How it works

```
pia-entrypoint.sh (PID 1)
 ├─ pia-wg register ──► PIA token → pick server → addKey ──► /gluetun/pia/state.json
 ├─ export WIREGUARD_* / VPN_ENDPOINT_* / SERVER_NAMES / port-forward creds
 ├─ /gluetun-entrypoint   (child; gluetun as usual)
 └─ pia-recover.sh        (child; polls 127.0.0.1:<control port>)
        └─ on failure: pia-wg register (same server first) → pia-wg apply
           (PUT /v1/vpn/settings, gluetun restarts only its VPN loop)
           └─ if the PUT is rejected: SIGUSR1 → entrypoint restarts the
              gluetun child in place (same container, same netns)
```

- **Keys as env vars, never a conf file.** gluetun derives the port-forward
  gateway from the routing table, not from the file, and only parses five keys
  from a file anyway. Env vars are the known-good path.
- **Server pinning.** `state.json` remembers the server. Cold starts and
  recoveries reconnect to it first (re-registering a fresh key), which keeps the
  exit IP and the 60-day port signature. A different server is chosen only after
  `PIA_SAME_SERVER_ATTEMPTS` failed rounds *and* once
  `PIA_MIN_SERVER_CHANGE_INTERVAL` has elapsed, or immediately if PIA no longer
  lists the server. Every change is logged as
  `server change: <old cn> (<old ip>, exit ip <ip>) -> <new cn> (<new ip>)` and
  the old `piaportforward.json` is deleted.
- **Control server auth.** `GET /v1/vpn/status`, `/v1/publicip/ip` and
  `/v1/portforward` are open (role `lan-readonly`) so LAN tools and mousehole
  can read them. `PUT /v1/vpn/settings` is only reachable with an API key
  generated at boot and kept in `/run/pia/apikey` (mode 600). Mount your own
  `/gluetun/auth/config.toml` to change the open routes; the recovery role is
  always appended.
- **Zero host coupling.** No Docker socket, no compose editing, no `.env`,
  no second container in the recovery path.

## Dials

Every threshold is an env var read at start with a default and a clamp.

| Variable | Default | Clamp | Meaning |
| --- | --- | --- | --- |
| `PIA_USER` / `PIA_PASS` | required | | PIA credentials. `PIA_USER_FILE` / `PIA_PASS_FILE` read from a file instead. Also used by gluetun for port forwarding. |
| `PIA_REGION` | required | | PIA region id (`swiss`, `ca_toronto`, `de_berlin`…). List: `curl -s https://serverlist.piaservers.net/vpninfo/servers/v6 \| head -1 \| jq -r '.regions[] \| select(.port_forward) \| .id'`. |
| `PIA_PORT_FORWARD_ONLY` | `on` | on/off | Refuse regions that do not offer port forwarding. |
| `PIA_REQUIRE_PORT_FORWARD` | `on` | on/off | Treat "no forwarded port" as unhealthy. Turn off if you only need the tunnel. |
| `PIA_CHECK_INTERVAL` | `60` | 1–3600 s | How often the loop probes the control server. |
| `PIA_FAIL_THRESHOLD` | `3` | 1–100 | Consecutive unhealthy probes before recovery starts. |
| `PIA_SAME_SERVER_ATTEMPTS` | `2` | 0–10 | Recovery rounds on the current server before a different one is considered. |
| `PIA_MIN_SERVER_CHANGE_INTERVAL` | `3600` | 0–604800 s | Minimum time between server changes (MAM rate-limits IP changes). Ignored when PIA delists the server. |
| `PIA_STARTUP_GRACE` | `120` | 0–3600 s | Quiet period after boot and after each recovery before probing resumes. |
| `PIA_RECOVERY_MODE` | `api` | api/restart | `api` = `PUT /v1/vpn/settings`; `restart` = always restart the gluetun child in place. `api` falls back to `restart` if the PUT fails. |
| `PIA_REGISTER_ATTEMPTS` | `5` | 1–20 | Boot-time key registration retries (5 s × attempt backoff). |
| `PIA_REGISTER_TIMEOUT` | `30` | 5–120 s | Per-request timeout talking to PIA. |
| `PIA_STATE_DIR` | `/gluetun/pia` | | Where `state.json` and the 24 h token cache live (persist it with the `/gluetun` volume). |
| `HTTP_CONTROL_SERVER_ADDRESS` | `:8000` | | gluetun's; the loop derives its port from it. The compose example uses `:8009`. |

All other gluetun variables work unchanged. Do **not** set
`VPN_SERVICE_PROVIDER`, `VPN_TYPE`, `WIREGUARD_*`, `VPN_ENDPOINT_*`,
`SERVER_NAMES`, `VPN_PORT_FORWARDING_PROVIDER` or the port-forward credentials;
the entrypoint owns them.

## Files inside the container

| Path | Purpose |
| --- | --- |
| `/gluetun/pia/state.json` | Last registration (server, keys, timestamps), mode 600. Delete it to force a new server. |
| `/gluetun/pia/token.json` | Cached PIA token (24 h), mode 600. |
| `/gluetun/piaportforward.json` | gluetun's port signature, bound to the server. Deleted automatically on server change. |
| `/run/pia/register.env` | Current registration as shell assignments (what gluetun is running with). |
| `/run/pia/apikey`, `/run/pia/auth.toml` | Boot-time control-server credentials. |

## Development

```
sh pia-gluetun/tests/run.sh          # shellcheck, go vet/test, sh tests (dash + busybox)
docker build -t pia-gluetun:local pia-gluetun
PIA_USER=… PIA_PASS=… sh pia-gluetun/tests/integration.sh pia-gluetun:local
```

`pia-wg` (Go, standard library only) has subcommands `register`,
`gluetun-settings`, `state`, `probe`, `apply`, `version`; run any with `-h`.
The PIA protocol follows [pia-foss/manual-connections](https://github.com/pia-foss/manual-connections).

Releases: push a tag `pia-gluetun-vX.Y.Z`, which publishes `:X.Y.Z`, `:X.Y`
and `:latest`. Pushes to `master` that touch `pia-gluetun/` publish `:edge`.
`:latest` does not exist until the first tag has been pushed; the compose
example pins `:X.Y` so a NAS on auto-pull only picks up patch releases.

## Open question carried from the investigation

gluetun probes the port-forward API at `x.y.128.1` then `x.y.0.1` (derived
from the tunnel address). PIA's own scripts instead call the server's public
IP on port 19999, and the addKey response carries a `server_vip`. `state.json`
records `server_vip` so the integration test can compare which gateway
answers on current PIA infrastructure. If `.128.1` proves dead, the fix
belongs upstream in gluetun's `findAPIIP`; nothing in this image can change
the gateway.
