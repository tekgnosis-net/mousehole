#!/bin/sh
# Runs every offline check for pia-gluetun: shellcheck, Go vet/tests, and the
# sh test-suites under each available POSIX shell (dash, busybox sh, sh).
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"

echo "== shellcheck"
shellcheck -s sh -x pia-lib.sh pia-entrypoint.sh pia-recover.sh tests/sh/*.sh tests/run.sh tests/integration.sh tests/fakes/*

echo "== go"
(cd pia-wg && test -z "$(gofmt -l .)" && go vet ./... && go test ./...)

for shell in dash "busybox sh" sh; do
	if command -v "${shell%% *}" >/dev/null 2>&1; then
		echo "== sh tests under: $shell"
		$shell tests/sh/test_lib.sh
		TEST_SH="$shell" $shell tests/sh/test_supervisor.sh
	fi
done
echo "all checks passed"
