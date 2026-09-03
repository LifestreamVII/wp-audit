# Testing & CI

wp-audit ships with a two-layer test pipeline:

| layer | what it does | needs |
|-------|--------------|-------|
| **unit tests** (`tests/`, marked `not e2e`) | version-comparison logic, vulnerability-filtering, state/diff engine, issue-ID generation, severity aggregation, WP detection helpers (with a fake SSH client) | Python only |
| **e2e audit** (`tests/test_e2e.py`, marked `e2e`) | builds a **throwaway vulnerable WordPress** Docker container, audits it over SSH with the real CLI, and asserts every expected finding type landed in `state.json` | Docker |

The GitHub Actions workflow (`.github/workflows/ci.yml`) runs both. The e2e
job does **not** duplicate the orchestration — it calls
`scripts/run_ci_locally.sh`, so what you run locally is exactly what CI runs.

## Run locally (no GitHub needed)

```bash
bash scripts/run_ci_locally.sh            # unit + e2e (full pipeline)
bash scripts/run_ci_locally.sh --unit-only
bash scripts/run_ci_locally.sh --e2e-only
bash scripts/run_ci_locally.sh --seed 42  # reproducible vulnerable scenario
bash scripts/run_ci_locally.sh --keep-up  # keep the fixture running afterwards
```

or `make unit` / `make e2e` / `make ci`.

### What the e2e audit does, step by step

1. `ci/generate_scenario.py` picks a **random** scenario from
   `ci/vulnerable_catalog.json` (seeded RNG → `--seed N` reproduces a run):
   an old WP core, a couple of known-vulnerable plugins, a vulnerable theme,
   an outdated-but-patched plugin/theme, and an unreachable host. It writes
   `ci/run/scenario.env`, `ci/run/scenario.json` and
   `ci/run/sites.generated.yaml`.
2. `docker compose -f ci/docker-compose.yml up -d --build` builds the fixture
   (`ci/Dockerfile` — PHP+Apache+sshd+wp-cli) and starts it next to a MariaDB
   service. `ci/entrypoint.sh` provisions the scenario *inside* the container:
   `wp core download --version=…`, `wp plugin install <slug> --version=…`,
   `wp theme install … --version=…`, plus a seeded `wp-content/debug.log`.
   WP files and the DB live on `tmpfs` — nothing survives the run.
3. The runner waits for SSH to come up, then seeds `~/.ssh/known_hosts` with a
   **non-ported** entry for `127.0.0.1`.
4. The real CLI audits the fixture:
   `python wp_audit.py --config ci/run/sites.generated.yaml --no-email --no-logs`
5. `pytest -m e2e` asserts the artifacts: every expected finding type
   from the CI harness run (plugin vuln, theme vuln, core vuln, outdated
   version, unreachable host) plus a high/critical severity must appear in
   `ci/run/reports/state.json`, and the digest report must exist.
   Because the harness calls `wp_audit.py` with `--no-logs`, debug.log
   findings are intentionally not expected in e2e.

Artifacts land in `ci/run/` (gitignored): `scenario.json`, `scenario.env`,
`reports/` (markdown digest + `state.json`).

## The vulnerable catalog

`ci/vulnerable_catalog.json` pins concrete versions per expected outcome:

* `vulnerable` — inside a range wpvulnerability.net reports (verified live on
  2026-08-04, e.g. `wp-file-manager 6.8` < 7.1 / CVE-2021-24177,
  `contact-form-7 5.3.1` < 5.3.2 / CVE-2020-35489, `hello-elementor 2.6.0`
  < 3.0.1).
* `outdated` — patched but not latest (exercises the *outdated version* issue
  type without tripping a vulnerability).

If the upstream API changes and a pin stops behaving as labeled, the e2e test
fails on that exact component — adjust the pin, rerun with `--seed` to
reproduce.

## Gotchas worth knowing

* **paramiko + non-standard SSH ports.** The audit tool uses
  `RejectPolicy` + `load_system_host_keys()`. paramiko's `HostKeys.lookup()`
  does **not** match `[host]:port` entries, so a ported `ssh-keyscan` entry
  would be treated as an unknown host and the connection rejected. The runner
  therefore seeds a plain `127.0.0.1` entry (sed strips the `[...]:port`
  prefix).
* **Lazy email import.** `wp_audit.py` imports `email_report` (weasyprint)
  only when an email is actually sent, so audit-only runs (`--no-email`)
  don't require the PDF stack.
* **Randomness is seeded.** A failing e2e prints `seed=N` — rerun with
  `--seed N` to get the exact same scenario.
