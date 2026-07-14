#!/usr/bin/env python3
"""
wp_audit.py — Automated WordPress Security Audit Tool
------------------------------------------------------
Audits multiple WordPress sites using SSH access to the site directory
  - WP core version
  - Installed themes & plugins
  - Vulnerability lookups via wpvulnerability.net API

Generates one Markdown report per site in ./reports/

Usage:
    python wp_audit.py [--config sites.yaml] [--output-dir reports]
"""

import argparse
import logging
import sys
from pathlib import Path
from state import State, Diff

import yaml
import time

from auditor import audit_site
from config import DEFAULT_CONFIG, DEFAULT_OUTPUT_DIR, log
from email_report import send_digest_email
from reporter import generate_report

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def load_config(path: str) -> list[dict]:
    config_path = Path(path)
    if not config_path.exists():
        log.error("Config file not found: %s", path)
        sys.exit(1)
    with config_path.open(encoding="utf-8") as f:
        data = yaml.safe_load(f)
    sites = data.get("sites", [])
    if not sites:
        log.error("No sites defined in %s", path)
        sys.exit(1)
    return sites


def main() -> None:
    start_time = time.time()
    parser = argparse.ArgumentParser(
        description="Automated WordPress Security Audit Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python wp_audit.py
  python wp_audit.py --config my_clients.yaml --output-dir ./results
        """,
    )
    parser.add_argument(
        "--config", default=DEFAULT_CONFIG,
        help=f"Path to YAML config file (default: {DEFAULT_CONFIG})",
    )
    parser.add_argument(
        "--unverified-context", action="store_true",
        help="Allow SMTP without verified context",
    )
    parser.add_argument(
        "--output-dir", default=DEFAULT_OUTPUT_DIR,
        help=f"Output directory for reports (default: {DEFAULT_OUTPUT_DIR})",
    )
    parser.add_argument(
        "--verbose", action="store_true",
        help="Enable debug-level logging",
    )
    parser.add_argument(
        "--no-email", action="store_true",
        help="Skip sending the summary email",
    )
    parser.add_argument(
        "--no-logs", action="store_true",
        help="Skip debug.log analysis and LLM summary (if configured)",
    )
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    sites = load_config(args.config)
    output_dir = Path(args.output_dir)
    state = None
    d = None
    try:
        state = State(output_dir / "state.json").load()
        d = Diff(state)
    except Exception:
        log.warning("Could not load state.json — starting fresh.")

    log.info("WordPress Audit — %d site(s) to audit", len(sites))
    log.info("Reports will be saved to: %s/", output_dir)
    log.info("")

    for site in sites:
        name = site.get("name", site.get("host", "Unknown"))
        host = site.get("host", "")
        username = site.get("username", "")
        password = site.get("password", "")
        directory = site.get("directory", "/var/www/html")
        url = site.get("url", f"https://{host}")
        if not host:
            log.warning("Skipping site with no host: %s", name)
            continue

        try:
            result = audit_site(name, host, username, password, directory, url, skip_logs=args.no_logs)
            if d is not None:
                d.add(result)
        except Exception as exc:
            log.error("  ✗ Unhandled error auditing %s: %s", name, exc)
            log.exception(exc)
            # Create a minimal failed result so the diff still tracks it
            from models import SiteAuditResult
            from datetime import datetime as dt, timezone
            failed_result = SiteAuditResult(
                name=name,
                url=url,
                audited_at=dt.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
                reachable=False,
                error=f"Unhandled exception during audit: {exc}",
                wp_version=None,
                wp_version_source="not-detected",
                logs=None,
                log_analysis=None,
            )
            if d is not None:
                d.add(failed_result)

        log.info("")

    # ── Finalize diff, generate digest report & persist state ─────────────
    report_path: Path | None = None
    if d is not None and state is not None:
        dr = d.finalize()
        state.save()

        report_path = generate_report(
            diff=dr,
            output_dir=output_dir,
            total_sites=len(sites),
            start_time=start_time,
        )

        log.info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        log.info("Audit complete.")
        log.info("  🆕 %d new · ⏸ %d existing · ✅ %d resolved · ⚠ %d errored · 🔘 %d unchanged",
                 len(dr.new), len(dr.existing), len(dr.resolved), len(dr.errored), len(dr.unchanged))
        log.info("  📄 %s", report_path)
    else:
        log.info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        log.info("Audit complete (no state tracking).")

    # ── Summary email ─────────────────────────────────────────────────────
    if not args.no_email and report_path is not None:
        send_digest_email(
            diff=dr,
            total_sites=len(sites),
            start_time=start_time,
            generated_reports=[report_path],
            output_dir=output_dir,
            unverified_context=args.unverified_context,
        )
    else:
        log.info("📧 Email sending skipped (--no-email).")


if __name__ == "__main__":
    main()
