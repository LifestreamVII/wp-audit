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

import yaml

from auditor import audit_site
from config import DEFAULT_CONFIG, DEFAULT_OUTPUT_DIR, log
from email_report import send_summary_email
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
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    sites = load_config(args.config)
    output_dir = Path(args.output_dir)

    log.info("WordPress Audit — %d site(s) to audit", len(sites))
    log.info("Reports will be saved to: %s/", output_dir)
    log.info("")

    generated_reports: list[Path] = []
    errored_sites = 0
    for site in sites:
        name = site.get("name", site.get("host", "Unknown"))
        host = site.get("host", "")
        username = site.get("username", "")
        password = site.get("password", "")
        directory = site.get("directory", "/var/www/html")
        url = site.get("url", f"https://{host}")
        if not host:
            log.warning("Skipping site with no host: %s", name)
            errored_sites += 1
            continue
        result = audit_site(name, host, username, password, directory, url)
        if not result.reachable or result.error:
            errored_sites += 1
        report_path = generate_report(result, output_dir)
        generated_reports.append(report_path)
        log.info("  📄 Report saved: %s", report_path)
        log.info("")

    log.info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    log.info("Audit complete. %d report(s) generated:", len(generated_reports))
    for p in generated_reports:
        log.info("  • %s", p)

    # ── Summary email ─────────────────────────────────────────────────────
    if not args.no_email:
        send_summary_email(
            generated_reports=generated_reports,
            total_sites=len(sites),
            errored_sites=errored_sites,
            output_dir=output_dir,
        )
    else:
        log.info("📧 Email sending skipped (--no-email).")


if __name__ == "__main__":
    main()
