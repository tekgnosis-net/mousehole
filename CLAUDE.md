# CLAUDE.md — pia-gluetun

Guidance for Claude Code working in this repository. Read fully before making changes.

## What this project is

A Docker image that wraps [gluetun](https://github.com/qdm12/gluetun) so that
Private Internet Access (PIA) WireGuard **with port forwarding** works unattended,
with no host-side scripts, no `.env` files, and no external supervisor container.

The repository is forked from [t-mart/mousehole](https://github.com/t-mart/mousehole)
because the end-to-end target is a MyAnonamouse seedbox stack
(gluetun + qBittorrent + mousehole). **Do not modify mousehole's own code** unless a
task explicitly says so — it works. New work lives under `pia-gluetun/`.

Target deployment: Synology DSM 7.x, Container Manager "project" (compose file, no
`.env` support in the UI), userspace WireGuard (no kernel module), Docker socket is
root-owned.

## Why the obvious approaches failed (do not repeat these)

These were all tried and are documented here so they are not proposed again.

1. **Keys in compose env vars.** Works, but PIA key registration (`addKey`) lapses if
   the client doesn't connect within minutes, and each generated config is bound to
   one server. Manual regeneration is required after any outage.
2. **Gluetun's native PIA provider.** OpenVPN only. WireGuard requires
   `VPN_SERVICE_PROVIDER=custom` + `VPN_PORT_FORWARDING_PROVIDER=private internet access`.
3. **Upstream `kylegrantlucas/pia-wg-config`.** Broken on Go ≥ 1.17: PIA's regional
   API certs have CN only (no SAN) → `x509: certificate relies on legacy Common Name`.
   The maintained fork `ccarpinteri/pia-wg-config` (v1.4.0) works but **cannot pin a
   server** (it takes the first server PIA lists for the region) and ships no binary
   releases. It is therefore not used; `pia-gluetun/pia-wg` (Go, stdlib only)
   implements the PIA token/serverlist/addKey protocol from
   `pia-foss/manual-connections` with explicit server pinning.
4. **`ccarpinteri/pia-wg-refresh` as a sidecar.** Regenerates `wg0.conf` and does
   `docker restart gluetun`. Three problems:
   - `SERVER_NAMES` is a gluetun env var bound to the chosen server's TLS CN. A
     `docker restart` cannot change env, and pia-wg-refresh's fix requires `.env`.
   - Its failure hook fires *before* the new config exists; its recovery hook needs
     port forwarding to be up, which is the thing that's broken → infinite regen loop,
     new server each time, new exit IP each time.
   - Every gluetun restart/recreate orphans containers using
     `network_mode: service:gluetun` (they hold the old netns / container ID).
5. **A `docker events` supervisor that edits compose and force-recreates.** Works
   mechanically but is host-coupled (socket, compose path, bind-mount rename
   semantics) and still causes exit-IP churn. MAM rate-limits IP changes
   (`429 Last change too recent`) and repeated churn risks a ban. Rejected.

## Design goals for the new image

Ordered by priority:

1. **Never change the container's network namespace to recover.** Key regeneration and
   VPN reconnection must happen *inside* the running gluetun process/container so
   `network_mode: service:` dependents are never orphaned.
2. **Compute `SERVER_NAMES` in-process** from the generated config. It must never be
   a value a human maintains in compose.
3. **Generate keys immediately before connecting** (seconds, not minutes) on first
   start and on every recovery.
4. **Bound exit-IP churn.** Prefer reconnecting to the *same* server (re-register key,
   keep the 60-day port signature) before selecting a new one. Expose a minimum
   interval between server changes.
5. **Zero host coupling.** No Docker socket, no compose editing, no `.env`. All
   configuration via env vars on one container.

## Implemented architecture (2026-09-16)

`pia-gluetun/` is built. Read `pia-gluetun/README.md` and
`docs/superpowers/specs/2026-09-16-pia-gluetun-design.md` before changing it.
Summary: `pia-entrypoint.sh` (PID 1) runs `pia-wg register`, exports gluetun's
WireGuard settings as **env vars** (never a conf file), starts `/gluetun-entrypoint`
and `pia-recover.sh` as children. The loop uses `pia-wg probe` and, on failure,
`pia-wg register` (same server first) + `pia-wg apply` (`PUT /v1/vpn/settings`,
verified to exist in v3.41.3 source and to restart only the VPN loop), falling back
to `SIGUSR1` → in-place restart of the gluetun child. Tests: `sh pia-gluetun/tests/run.sh`.
Image: `ghcr.io/tekgnosis-net/pia-gluetun`, built by
`.github/workflows/pia-gluetun-image.yaml`.

The section below is the original plan kept for history; where it differs
(pia-wg-config, conf file), the implementation above wins.

## Original recommended architecture (superseded)

`FROM qmcgaw/gluetun:<pinned tag>` with an added entrypoint shim and a small
in-container loop:

- **Entrypoint shim** (`/pia-entrypoint.sh`): runs `pia-wg-config` (fork, static
  binary, `--json -s -p`), writes `/gluetun/wireguard/wg0.conf`, exports
  `SERVER_NAMES=<cn>` and `WIREGUARD_*` from the JSON, then `exec`s gluetun's
  original entrypoint. This alone fixes stale keys + SERVER_NAMES for cold start.
- **Runtime recovery**: gluetun's control server has `PUT /v1/vpn/settings` (verify
  exact schema for the pinned tag in
  https://github.com/qdm12/gluetun-wiki/blob/main/setup/advanced/control-server.md)
  which applies new provider/WireGuard settings and restarts the VPN loop *without*
  restarting the container. A loop inside the container (started by the shim,
  `wait`ed alongside gluetun) should:
  1. Poll `/v1/publicip/ip` and `/v1/portforward` on `127.0.0.1:8000`.
  2. On N consecutive failures: regenerate against the **same** server first
     (pia-wg-config with an explicit server if the fork supports it; otherwise same
     region and accept the roll), then `PUT /v1/vpn/settings` with new keys,
     endpoint and `server_names`.
  3. If the same server fails M times, allow a region roll, subject to the min
     server-change interval.
- If `PUT /v1/vpn/settings` cannot carry `server_names`/port-forward settings on the
  pinned tag, fall back to `exec`-restarting gluetun *inside* the container (PID 1
  re-exec keeps the netns). Document which path is used.
- `auth/config.toml` must open the routes the loop uses; ship a default and merge
  with any user-provided file.

Pin gluetun to a release tag. `latest` tracks HEAD and logs "bleeding edge".

## Open investigation — PIA port-forward gateway

Unresolved and must be understood before the image is declared done:

- With keys in **env vars**, gluetun probed gateway candidates
  (`10.x.y.1` → `10.x.128.1` → `10.x.0.1`), `.128.1` timed out, `.0.1` answered
  (cert = server CN), port forwarding succeeded.
- With keys in **`wg0.conf` written by pia-wg-config**, gluetun skipped probing and
  went straight to `10.x.128.1:19999/getSignature`, which times out. Same server,
  same credentials. Gluetun also reported a fixed `MTU: 1320` instead of running
  discovery, so it is honouring extra lines in the file.
- ~~Hypothesis: a `DNS =` / gateway line in the generated conf is used as the PF
  gateway.~~ **Disproved 2026-09-16 against gluetun v3.41.3 source**: the gateway
  comes from the routing table (`routing.VPNLocalGatewayIP`) and `findAPIIP` then
  probes `x.y.128.1` followed by `x.y.0.1`; the conf-file parser reads only
  PrivateKey, Address, PreSharedKey, PublicKey and Endpoint. `.128.1` may still be
  dead on current PIA infrastructure (qdm12/gluetun#3295, April 2026), which would
  only cost a 5 s timeout before `.0.1` is tried. pia-gluetun avoids the file path
  entirely (env vars) and records PIA's `server_vip` in `state.json` for comparison.
- Still to measure in `tests/integration.sh`: which of `.128.1` / `.0.1` answers, and
  whether PIA's own approach (public server IP on :19999, as in
  `pia-foss/manual-connections`) would be more reliable. Any fix belongs upstream in
  gluetun; the image cannot change the gateway.
- Related upstream reports: ccarpinteri/pia-wg-refresh#9 (June 2026, identical
  symptom, open).

## Facts about the environment that constrain the code

- Alpine/busybox `sh` only. No bash, no GNU sed extensions, no `sudo`.
- `sed -i` on a bind-mounted **file** fails (`Resource busy`): rename over a mount
  point. Write via `cat > file` (same inode) or mount directories.
- Gluetun runs as UID/GID 1000 by default; generated files must be readable by it.
- Gluetun lowercases `SERVER_NAMES` in logs but compares case-insensitively.
- PIA port signature (`/gluetun/piaportforward.json`) is bound to the server that
  issued it. Delete it whenever the server changes or `bindPort` hangs.
- `VPN_PORT_FORWARDING_UP_COMMAND` uses `{{PORTS}}` (not `{{PORT}}`; substitution of
  the latter was unreliable in 3.40.x).
- Port-forward credentials: `VPN_PORT_FORWARDING_USERNAME`/`_PASSWORD` (fallbacks
  `OPENVPN_USER`/`OPENVPN_PASSWORD`). Control-server auth file env:
  `HTTP_CONTROL_SERVER_AUTH_CONFIG_FILEPATH`; API key header `X-API-Key`; a route may
  appear in several roles. Busybox `wget` cannot send PUT, hence `pia-wg apply`.
- wget's `-nv` summary goes to stderr and gluetun logs it at ERROR even on HTTP 200;
  use `-q`.
- qBittorrent: WebUI port must equal the published host port (Host-header validation)
  and "Bypass authentication for clients on localhost" must be on for the up command.
- Mousehole only needs the tunnel; it does not need the port. Keep
  `MOUSEHOLE_UPDATE_INTERVAL_SECONDS` high (≥ 3600) and start it last in tests.

## Repository layout

```
pia-gluetun/
  Dockerfile            # golang:1.25-alpine build stage → FROM qmcgaw/gluetun:v3.41.3
  pia-wg/               # Go helper: register | gluetun-settings | state | probe | apply
  pia-lib.sh            # shared sh helpers (clamp, bool, auth merge, env export)
  pia-entrypoint.sh     # PID 1: register → export env → supervise gluetun + loop
  pia-recover.sh        # in-container health/recovery loop
  auth/config.toml      # default control-server roles (LAN read-only)
  compose.example.yaml  # full MAM stack for Synology (no .env)
  README.md             # dials table, files, development
  tests/                # run.sh, sh/ (dash + busybox), fakes/, integration.sh
.github/workflows/pia-gluetun-image.yaml   # GHCR build/push
docs/superpowers/specs/2026-09-16-pia-gluetun-design.md
```

## Testing

- **Offline** (`sh pia-gluetun/tests/run.sh`, also run in CI): shellcheck (`-s sh`)
  on every script; `go vet` + `go test` for `pia-wg` (httptest fakes of PIA and the
  gluetun control server, serverlist fixture in `pia-wg/testdata/`);
  `tests/sh/test_lib.sh` and `tests/sh/test_supervisor.sh` run under both `dash` and
  `busybox sh` using the fake `pia-wg`/`gluetun-entrypoint` in `tests/fakes/`.
- **Integration** (needs real PIA creds via env, never committed): bring up the
  compose example, assert in order: tunnel public IP is PIA, `port forwarded is` in
  logs, qBittorrent listening port equals gluetun's, then simulate failure by
  `docker exec gluetun kill -STOP` on the wireguard process or by blocking the
  endpoint with iptables inside the container, and assert recovery **without** the
  container ID or dependents' health changing.
- Log every server change with old/new CN and exit IP; the integration test asserts
  at most one change per test run.

## Conventions

- Shell: POSIX sh, `set -eu`, quote everything, no `[[`, no arrays.
- Log lines: `<ISO8601Z> [component] message`. Redact keys and tokens always.
- Every env var documented in README with default and rationale.
- Do not add a Docker-socket dependency. Do not add a second container to the
  recovery path. If a proposed change needs either, stop and explain why in the PR.
- Pricing/costs in AUD if ever mentioned. Verify current gluetun control-server API
  against the wiki for the pinned tag rather than from memory.

## Session history that produced this file

Sydney, 2026-09-15. Stack: gluetun v3.41.1, lscr.io/linuxserver/qbittorrent 5.2.3,
tmmrtn/mousehole 0.5.0, ccarpinteri/pia-wg-config 1.4.0, ccarpinteri/pia-wg-refresh
latest. Region `swiss`. Servers seen: Server-10837-2a (195.177.93.76),
Server-10835-3a (.164, PF worked once via env vars, gateway 10.111.0.1),
Server-12620-0a (.123). gluetun v3.41.3 was available but not yet evaluated.

2026-09-16: pia-gluetun implemented against gluetun v3.41.3 (see "Implemented
architecture"). Local Go toolchain is /usr/local/go (1.26), symlinked into
/usr/local/bin.
