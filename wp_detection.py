"""
wp_detection.py — WordPress core/plugin/theme detection helpers via SSH.
"""

import datetime
from datetime import datetime as dt, timedelta, timezone
import re
from typing import Optional

import paramiko

from config import DEBUG_LOG_CAP, log
from ssh import run_ssh_command
from http_client import http
from config import WP_PLUGIN_API_BASE, WP_THEME_API_BASE
from file import reverse_readline

# ---------------------------------------------------------------------------
# WordPress detection helpers
# ---------------------------------------------------------------------------

def detect_wp_version(client: paramiko.SSHClient, directory: str) -> tuple[Optional[str], str]:
    """
    Detect the WordPress core version from wp-includes/version.php via SSH.
    Returns a (version_string, source_label) tuple.
    """
    # Primary: parse $wp_version from version.php
    version_file = f"{directory.rstrip('/')}/wp-includes/version.php"
    output = run_ssh_command(
        client,
        f"grep -E \"\\$wp_version\\s*=\" {version_file} 2>/dev/null | head -1",
    )
    if output:
        m = re.search(r"\$wp_version\s*=\s*['\"]([^'\"]+)['\"]", output)
        if m:
            return m.group(1), "version.php"

    # Fallback: wp-includes/version.php may use a different variable name on some builds
    output2 = run_ssh_command(
        client,
        f"php -r \"include('{version_file}'); echo \$wp_version;\" 2>/dev/null",
    )
    if output2 and re.match(r"^[\d.]+$", output2.strip()):
        return output2.strip(), "version.php (php eval)"

    return None, "not-detected"


def extract_themes(client: paramiko.SSHClient, directory: str) -> Optional[dict]:
    """List installed themes from wp-content/themes/ via SSH.

    Returns a dict mapping slug -> display name (slug is used as name when
    Style.css cannot be read).
    """
    themes_dir = f"{directory.rstrip('/')}/wp-content/themes"
    output = run_ssh_command(client, f"ls -1 {themes_dir} 2>/dev/null")
    if not output:
        return None
    themes: dict[str, str] = {}
    for slug in output.splitlines():
        slug = slug.strip()
        if not slug:
            continue
        if slug.startswith("."):
            continue  # skip hidden files/directories
        if slug.endswith(".php"):
            continue  # skip single-file plugins
        # Try to get the Theme Name from style.css
        style_css = f"{themes_dir}/{slug}/style.css"
        name_output = run_ssh_command(
            client,
            f"grep -m1 '^Theme Name' {style_css} 2>/dev/null",
        )
        if name_output:
            m = re.match(r"Theme Name\s*:\s*(.+)", name_output)
            name = m.group(1).strip() if m else slug
        else:
            name = slug
        themes[slug] = name
    return themes or None


def probe_content_version(client: paramiko.SSHClient, directory: str, kind: str, slug: str) -> Optional[str]:
    """
    Probe the readme.txt (or the main plugin PHP file header) of a plugin or
    theme to extract its version string via SSH.
    """
    base = f"{directory.rstrip('/')}/wp-content/{kind}s/{slug}"

    # 1. Try readme.txt "Stable tag" line (plugins & themes)
    for readme in ("readme.txt", "README.txt", "README.md"):
        output = run_ssh_command(
            client,
            f"grep -im1 'stable tag' {base}/{readme} 2>/dev/null",
        )
        if output:
            m = re.search(r"stable tag\s*:\s*([\d.]+)", output, re.IGNORECASE)
            if m:
                return m.group(1).strip()

    # 2. Try "Version:" header in the main plugin PHP file
    if kind == "plugin":
        main_php = run_ssh_command(
            client,
            f"grep -rim1 '^[ \t*]*Version:' {base}/*.php 2>/dev/null | head -1",
        )
        if main_php:
            m = re.search(r"Version:\s*([\d.]+)", main_php, re.IGNORECASE)
            if m:
                return m.group(1).strip()

    return None

def get_content_latest_version(slug: str, kind: str) -> Optional[tuple[str, str]]:
    """
    Query the WordPress.org API to get the latest version of a plugin or theme.
    Returns the version string and last updated timestamp, or None if not found.
    """
    if kind == "plugin":
        url = f"{WP_PLUGIN_API_BASE}?action=plugin_information&slug={slug}"
    elif kind == "theme":
        url = f"{WP_THEME_API_BASE}?action=theme_information&slug={slug}"
    else:
        log.warning("Unknown content kind: %s", kind)
        return None

    resp = http.get(url)
    if not resp:
        log.warning("✗ Could not reach content info API for %s/%s", kind, slug)
        return None

    if resp.status_code == 404:
        return None

    try:
        payload = resp.json()
        if not payload:
            return None
        version = payload.get("version")
        last_updated = payload.get("last_updated")
    except (ValueError, KeyError) as e:
        log.warning("  ✗ Failed to parse content version data for %s/%s: %s", kind, slug, e)
        return None

    return version, last_updated

def extract_plugins(client: paramiko.SSHClient, directory: str) -> Optional[dict]:
    """List installed plugins from wp-content/plugins/ via SSH.

    Returns a dict mapping slug -> display name.
    """
    plugins_dir = f"{directory.rstrip('/')}/wp-content/plugins"
    output = run_ssh_command(client, f"ls -1 {plugins_dir} 2>/dev/null")
    if not output:
        return None
    plugins: dict[str, str] = {}
    for slug in output.splitlines():
        slug = slug.strip()
        if not slug:
            continue
        if slug.startswith("."):
            continue  # skip hidden files/directories
        if slug.endswith(".php"):
            continue  # skip single-file plugins
        # Try to get the Plugin Name from the main PHP header
        name_output = run_ssh_command(
            client,
            f"grep -rim1 '^[ \t*]*Plugin Name' {plugins_dir}/{slug}/*.php 2>/dev/null | head -1",
        )
        if name_output:
            m = re.search(r"Plugin Name\s*:\s*(.+)", name_output, re.IGNORECASE)
            name = m.group(1).strip() if m else slug
        else:
            name = slug
        plugins[slug] = name
    return plugins or None

def filter_logs(client: paramiko.SSHClient, path: str, inc_notices: bool = False, td: int = 2) -> list[str]:
    # Regex to extract the date string and the rest of the message.
    # Matches: [01-Jul-2026 02:37:27 UTC] The rest of the log...
    log_pattern = re.compile(r'^\[(.*?) UTC\]\s*(.*)$')

    # Calculate the cutoff date (*timedelta* days ago from right now)
    cutoff_date = dt.now(timezone.utc) - timedelta(days=td)

    seen_messages = set()
    extracted_logs = []

    try:
        sftp = client.open_sftp()

        with sftp.open(path, 'rb') as log_file:
            for line in reverse_readline(fh=log_file, buf_size=8192, limit=DEBUG_LOG_CAP):
                # Exclude lines that don't have "Warning" or "Error"
                if not inc_notices and "Warning" not in line and "Error" not in line:
                    continue

                match = log_pattern.match(line)
                if match:
                    date_str = match.group(1) # e.g., "01-Jul-2026 02:37:27"
                    message_content = match.group(2) # e.g., "PHP Warning: ..."
                    try:
                        log_date = dt.strptime(date_str, '%d-%b-%Y %H:%M:%S')
                        log_date = log_date.replace(tzinfo=timezone.utc)
                        if not isinstance(log_date, dt):
                            continue
                        if log_date < cutoff_date:
                            continue # Exclude results older than *timedelta* days
                    except ValueError as ve:
                        log.warning("  ✗ Failed to parse date in log line: %s", ve)
                        continue
                    if message_content not in seen_messages:
                        seen_messages.add(message_content)
                        extracted_logs.append(line.strip())

    except Exception as e:
        log.warning("  ✗ Error reading log file: %s", e)
    finally:
        if 'sftp' in locals():
            sftp.close()
    return extracted_logs