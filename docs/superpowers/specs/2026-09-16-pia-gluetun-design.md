# pia-gluetun design

Date: 2026-09-16. Status: implemented.

## Goal

A Docker image wrapping `qmcgaw/gluetun` so that Private Internet Access (PIA)
WireGuard with port forwarding runs unattended on Synology DSM 7 Container
Manager, recovering from key expiry or server failure **without ever restarting
the container**, so services using `network_mode: service:gluetun` are never
orphaned. Published to `ghcr.io/tekgnosis-net/pia-gluetun`.

The full rationale for why earlier approaches were rejected is in `CLAUDE.md`.

## Verified facts the design rests on (gluetun v3.41.3 source)

- `PUT /v1/vpn/settings` exists (`internal/server/vpn.go`, `patchSettings`).
  It JSON-decodes a `settings.VPN` override, merges it into the live settings,
  validates, then `state.SetSettings` stops and restarts the VPN loop
  in-process. No container restart.
- Accepted JSON fields used here: `provider.server_selection.names[]`,
  `provider.server_selection.wireguard.{endpoint_ip,endpoint_port,public_key}`,
  `wireguard.{private_key,addresses[]}`.
- The PIA port-forward gateway is derived from the routing table
  (`routing.VPNLocalGatewayIP`) then probed as `x.y.128.1` and `x.y.0.1`
  (`findAPIIP`). It is **not** read from a WireGuard conf file. gluetun's conf
  parser only reads PrivateKey, Address, PreSharedKey, PublicKey, Endpoint.
  Therefore keys are passed as **env vars**, never as a file.
- Port-forward credentials come from `VPN_PORT_FORWARDING_USERNAME` and
  `VPN_PORT_FORWARDING_PASSWORD` (fallbacks `OPENVPN_USER`/`OPENVPN_PASSWORD`).
- Control-server auth file: `HTTP_CONTROL_SERVER_AUTH_CONFIG_FILEPATH`
  (default `/gluetun/auth/config.toml`), TOML `[[roles]]` with `name`, `auth`
  (`none|basic|apikey`), `apikey`, `routes = ["METHOD /path"]`. API key is
  sent as the `X-API-Key` header.
- Control-server responses: `/v1/vpn/status` → `{"status":"running"}`,
  `/v1/publicip/ip` → `{"public_ip":"..."}`, `/v1/portforward` →
  `{"port":N,"ports":[N]}`, PUT settings → `{"outcome":"..."}`.
- `ccarpinteri/pia-wg-config` v1.4.0 has no server-pinning flag and no binary
  releases. It is therefore **not used**; a stdlib-only Go helper replaces it.
- PIA protocol (from `pia-foss/manual-connections`): token via
  `POST https://www.privateinternetaccess.com/api/client/v2/token` (form
  `username`, `password`), server list `https://serverlist.piaservers.net/vpninfo/servers/v6`
  (first line is JSON), key registration `GET https://<cn>:1337/addKey?pt=<token>&pubkey=<pub>`
  dialled to the server IP with TLS verified against PIA's CA and the CN.
- gluetun image: busybox `sh`, `wget` (GET/POST only, no PUT), no jq/curl/openssl.

## Components (all under `pia-gluetun/`)

### `pia-wg` (Go, stdlib only)

- `register`: choose a server (pinned CN/IP, else random port-forward-capable
  server in `--region`, optionally excluding CNs), fetch/cached token, generate
  X25519 keypair (`crypto/ecdh`), call addKey, write `state.json` (0600),
  print `KEY='value'` lines (`--format env`) or JSON.
- `gluetun-settings`: state → JSON body for `PUT /v1/vpn/settings`.
- `state`: state → the same `KEY='value'` lines as `register` (used at boot to
  decide the pin without parsing JSON in sh).
- `probe`: GET the three control-server routes, print `STATUS=… PUBLIC_IP=… PORT=…`.
- `apply`: PUT the settings body with `X-API-Key`.
- Credentials only from env `PIA_USER`/`PIA_PASS`. Keys and tokens never logged.

### `pia-entrypoint.sh` (PID 1 supervisor, POSIX sh)

1. Validate env, clamp knobs.
2. If `state.json` exists for the same region, pin to its CN/IP.
3. `pia-wg register` → source env → export `WIREGUARD_PRIVATE_KEY`,
   `WIREGUARD_ADDRESSES=<peer_ip>/32`, `WIREGUARD_PUBLIC_KEY`,
   `VPN_ENDPOINT_IP`, `VPN_ENDPOINT_PORT`, `SERVER_NAMES`,
   `VPN_SERVICE_PROVIDER=custom`, `VPN_TYPE=wireguard`,
   `VPN_PORT_FORWARDING=on`, `VPN_PORT_FORWARDING_PROVIDER="private internet access"`,
   `VPN_PORT_FORWARDING_USERNAME/PASSWORD`.
4. If the CN changed, delete `/gluetun/piaportforward.json`.
5. Generate a boot API key, write a merged auth TOML (user file + our role),
   point `HTTP_CONTROL_SERVER_AUTH_CONFIG_FILEPATH` at it.
6. Start `/gluetun-entrypoint` and `pia-recover.sh` as children; forward
   TERM/INT; on USR1 restart the gluetun child in place (netns preserved).

### `pia-recover.sh`

Every `PIA_CHECK_INTERVAL` seconds run `probe`. After `PIA_FAIL_THRESHOLD`
consecutive failures: re-register pinned to the current server; after
`PIA_SAME_SERVER_ATTEMPTS` same-server rounds, or if the server vanished from
the list, roll within the region, but only if the last change is older than
`PIA_MIN_SERVER_CHANGE_INTERVAL`. Apply via `apply` (mode `api`) or USR1 to
the supervisor (mode `restart`, also the fallback when the PUT is rejected).
Every server change logs old/new CN and exit IP.

### Image, CI, compose

- `Dockerfile`: `golang:1.25-alpine` cross-build → `FROM qmcgaw/gluetun:v3.41.3`.
- `.github/workflows/pia-gluetun-image.yaml`: shellcheck + go test; build and
  push `linux/amd64,linux/arm64,linux/arm/v7` to GHCR on master pushes touching
  `pia-gluetun/**` (`edge`) and on tags `pia-gluetun-vX.Y.Z` (`X.Y.Z`, `X.Y`,
  `latest`). PRs build without pushing.
- `compose.example.yaml`: control server `:8009` on LAN, qBittorrent `8099`,
  mousehole `5010`, config under `/volume1/docker/mousehole-qbit/mam/`.

## Env knobs

See `pia-gluetun/README.md` "Dials". Every knob has a default and a clamp.

## Testing

- Go unit tests with `httptest` (token, server list, addKey, probe, apply,
  state serialisation, env quoting).
- `shellcheck -s sh` on every script; sh unit and supervisor tests run under
  `dash` and `busybox sh` against fake `pia-wg`/`gluetun-entrypoint` binaries
  in `tests/fakes/`.
- `tests/integration.sh`: needs real PIA creds; asserts tunnel IP, forwarded
  port, qBittorrent port, then blocks the endpoint with iptables inside the
  container and asserts recovery with unchanged container IDs and at most one
  server change.

## Open item carried forward

Which of `x.y.128.1` / `x.y.0.1` answers on current PIA infrastructure, and
whether PIA's `server_vip` should be preferred, is to be measured in the
integration run. It does not affect this design because the gateway is not
configurable from outside gluetun.
