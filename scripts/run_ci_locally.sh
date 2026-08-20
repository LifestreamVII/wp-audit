#!/usr/bin/env bash
# run_ci_locally.sh — run the wp-audit CI pipeline WITHOUT triggering GitHub
# Actions. This is the single source of truth for CI orchestration: the
# GitHub Actions e2e job calls this script (--e2e-only), so what you run
# locally is exactly what CI runs.
#
# Pipeline:
#   1. unit tests   — pytest (no Docker needed)
#   2. e2e audit    — build a throwaway vulnerable WordPress container, audit
#                     it over SSH with the real CLI, assert the expected
#                     finding types (plugin/theme/core vuln, outdated, log,
#                     unreachable host).
#
# Usage:
#   bash scripts/run_ci_locally.sh               # unit + e2e
#   bash scripts/run_ci_locally.sh --unit-only   # just unit tests
#   bash scripts/run_ci_locally.sh --e2e-only    # just the docker e2e audit
#   bash scripts/run_ci_locally.sh --seed 42     # reproducible scenario
#   bash scripts/run_ci_locally.sh --keep-up     # leave the container running
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

UNIT_ONLY=0
E2E_ONLY=0
KEEP_UP=0
SEED=""
EXTRA_PYTEST=()

for arg in "$@"; do
    case "$arg" in
        --unit-only) UNIT_ONLY=1 ;;
        --e2e-only)  E2E_ONLY=1 ;;
        --keep-up)   KEEP_UP=1 ;;
        --seed=*)    SEED="${arg#*=}" ;;
        *)           EXTRA_PYTEST+=("$arg") ;;
    esac
done

# ---------------------------------------------------------------------------
# Python environment
# ---------------------------------------------------------------------------
PY=python3
if [ ! -x "$ROOT/venv/bin/python" ] && command -v python3 >/dev/null 2>&1 \
    && python3 -m venv "$ROOT/venv" >/dev/null 2>&1; then
    echo "[ci] created venv/ (python3)"
fi
if [ -x "$ROOT/venv/bin/python" ]; then
    PY="$ROOT/venv/bin/python"
fi

echo "[ci] python: $($PY --version)"
$PY -m pip install -q --upgrade pip
$PY -m pip install -q -r "$ROOT/requirements.txt" -r "$ROOT/requirements-dev.txt"

# ---------------------------------------------------------------------------
# 1. Unit tests (no Docker)
# ---------------------------------------------------------------------------
if [ "$E2E_ONLY" -ne 1 ]; then
    echo
    echo "══════════ 1/2 unit tests ══════════"
    $PY -m pytest -m "not e2e" -q "${EXTRA_PYTEST[@]}"
fi

# ---------------------------------------------------------------------------
# 2. E2E audit against a dockerized vulnerable WordPress
# ---------------------------------------------------------------------------
E2E_PORT="${WP_SSH_PORT:-3222}"
HTTP_PORT="${WP_HTTP_PORT:-8080}"
RUN_DIR="$ROOT/ci/run"

cleanup() {
    if [ "$KEEP_UP" -ne 1 ]; then
        echo "[ci] tearing down fixture containers…"
        docker compose -f "$ROOT/ci/docker-compose.yml" -p wp-audit-ci down -v --remove-orphans >/dev/null 2>&1 || true
    fi
    # Remove the ephemeral known_hosts entry regardless of --keep-up: it is
    # only valid for this container run, and it should never accumulate in the
    # developer's workspace between runs.
    rm -f "$RUN_DIR/known_hosts"
}
trap cleanup EXIT

if [ "$UNIT_ONLY" -ne 1 ]; then
    for bin in docker ssh-keyscan; do
        command -v "$bin" >/dev/null 2>&1 || {
            echo "[ci] ERROR: '$bin' is required for the e2e audit and was not found." >&2
            exit 1
        }
    done

    echo
    echo "══════════ 2/2 e2e audit (vulnerable WordPress fixture) ══════════"

    # pick a random scenario (or a seeded, reproducible one)
    SCEN=""
    if [ -n "$SEED" ]; then
        SCEN="--seed $SEED"
    fi
    $PY "$ROOT/ci/generate_scenario.py" --ssh-port "$E2E_PORT" --http-port "$HTTP_PORT" $SCEN

    # build + start the fixture (throwaway WP + MariaDB on tmpfs)
    echo "[ci] building vulnerable WordPress fixture…"
    WP_SSH_PORT="$E2E_PORT" WP_HTTP_PORT="$HTTP_PORT" \
        docker compose -f "$ROOT/ci/docker-compose.yml" -p wp-audit-ci up -d --build

    # wait for the container's SSH to come up — the entrypoint provisions WP
    # BEFORE starting sshd, so this doubles as the "provisioning done" wait.
    echo "[ci] waiting for SSH on 127.0.0.1:$E2E_PORT …"
    UP=0
    for _ in $(seq 1 100); do
        if ssh-keyscan -p "$E2E_PORT" 127.0.0.1 >/dev/null 2>&1; then UP=1; break; fi
        sleep 3
    done
    if [ "$UP" -ne 1 ]; then
        echo "[ci] ERROR: fixture SSH never became reachable." >&2
        docker compose -f "$ROOT/ci/docker-compose.yml" -p wp-audit-ci logs --tail=50 wp >&2 || true
        exit 1
    fi
    echo "[ci] fixture SSH is up."

    # Populate a temporary known_hosts file with the fixture's actual host key.
    # This lets the audit client keep RejectPolicy (hard deny) while still
    # accepting the ephemeral container — without touching ~/.ssh/known_hosts.
    # The file lives under ci/run/ (gitignored) and is deleted by cleanup().
    echo "[ci] writing known_hosts for fixture…"
    mkdir -p "$RUN_DIR"
    ssh-keyscan -p "$E2E_PORT" 127.0.0.1 2>/dev/null > "$RUN_DIR/known_hosts"

    # run the real audit CLI against both the fixture and an unreachable host
    echo "[ci] running wp_audit.py …"
    $PY "$ROOT/wp_audit.py" \
        --config "$RUN_DIR/sites.generated.yaml" \
        --output-dir "$RUN_DIR/reports" \
        --known-hosts-file "$RUN_DIR/known_hosts" \
        --no-email --no-logs

    # assert the expected finding types against the produced state/report
    echo "[ci] running e2e assertions…"
    E2E_ROOT="$RUN_DIR" $PY -m pytest -m e2e -q

    echo
    echo "✅ CI passed — audit report: $RUN_DIR/reports/"
fi