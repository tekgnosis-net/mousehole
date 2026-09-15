# syntax=docker/dockerfile:1
# pia-gluetun: qmcgaw/gluetun + in-container PIA WireGuard key registration
# and recovery. See README.md.

ARG GLUETUN_VERSION=v3.41.3

FROM --platform=$BUILDPLATFORM golang:1.25-alpine AS build
ARG TARGETOS
ARG TARGETARCH
ARG TARGETVARIANT
ARG VERSION=dev
WORKDIR /src
COPY pia-wg/ ./
RUN --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH GOARM=${TARGETVARIANT#v} \
    go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/pia-wg .

FROM qmcgaw/gluetun:${GLUETUN_VERSION}
ARG GLUETUN_VERSION
ARG VERSION=dev
LABEL org.opencontainers.image.title="pia-gluetun" \
      org.opencontainers.image.description="gluetun ${GLUETUN_VERSION} with unattended PIA WireGuard port forwarding" \
      org.opencontainers.image.source="https://github.com/tekgnosis-net/mousehole" \
      org.opencontainers.image.version="${VERSION}" \
      pia-gluetun.gluetun-version="${GLUETUN_VERSION}"

COPY --from=build /out/pia-wg /usr/local/bin/pia-wg
COPY pia-lib.sh pia-entrypoint.sh pia-recover.sh /
COPY auth/config.toml /pia/auth/config.toml
RUN chmod 755 /pia-entrypoint.sh /pia-recover.sh /pia-lib.sh /usr/local/bin/pia-wg

# Defaults for the dials (all overridable in compose; see README "Dials").
ENV PIA_STATE_DIR=/gluetun/pia \
    PIA_CHECK_INTERVAL=60 \
    PIA_FAIL_THRESHOLD=3 \
    PIA_SAME_SERVER_ATTEMPTS=2 \
    PIA_MIN_SERVER_CHANGE_INTERVAL=3600 \
    PIA_STARTUP_GRACE=120 \
    PIA_RECOVERY_MODE=api \
    PIA_REQUIRE_PORT_FORWARD=on \
    PIA_PORT_FORWARD_ONLY=on \
    PIA_REGISTER_ATTEMPTS=5 \
    PIA_REGISTER_TIMEOUT=30 \
    PIA_PORT_FORWARDING=on \
    PIA_BYPASS_MARK=51820 \
    PIA_BYPASS_DNS=1.1.1.1:53,8.8.8.8:53

# gluetun's own HEALTHCHECK (/gluetun-entrypoint healthcheck) is inherited.
ENTRYPOINT ["/pia-entrypoint.sh"]
