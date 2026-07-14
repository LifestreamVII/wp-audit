"""
auditor.py — Core site audit orchestration for wp_audit.
"""

from datetime import datetime as dt, timezone
from typing import Optional
from ai import LLMClient
from config import log, LLM_MODEL, LLM_BASE_URL, LLM_API_KEY, LLM_PROMPT
from models import Component, SiteAuditResult
from ssh import client_connect, establish_connection
from vulnerabilities import fetch_vulnerabilities, filter_vulns_for_version
from wp_detection import detect_wp_version, extract_plugins, extract_themes, probe_content_version, get_content_latest_version, filter_logs


# ---------------------------------------------------------------------------
# Site auditor
# ---------------------------------------------------------------------------

def audit_site(name: str, host: str, username: str, password: str, directory: str, url: str, skip_logs: bool = False) -> SiteAuditResult:
    now = dt.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    log.info("━━━━ Auditing: %s (%s)", name, host)

    result = SiteAuditResult(
        name=name,
        url=url,
        audited_at=now,
        reachable=False,
        error=None,
        wp_version=None,
        wp_version_source="not-detected",
        logs=None,
        log_analysis=None,
    )

    # ── 1. Establish SSH connection ──────────────────────────────────────────
    log.info("  🔌 Connecting to %s@%s …", username, host)
    connected = establish_connection(host, username, password)
    if not connected:
        result.error = f"Could not establish SSH connection to {username}@{host}"
        log.error("  ✗ %s", result.error)
        return result

    result.reachable = True
    client = client_connect(host, username, password)

    try:
        # ── 2. Detect WP version ─────────────────────────────────────────────
        log.info("  🔎 Detecting WordPress version…")
        wp_version, wp_version_source = detect_wp_version(client, directory)
        result.wp_version = wp_version
        result.wp_version_source = wp_version_source
        if wp_version:
            log.info("  ✓ WordPress version: %s", wp_version)
        else:
            log.warning("  ✗ Could not detect WordPress version")

        # ── 3. Discover plugins ───────────────────────────────────────────────
        log.info("  🔎 Discovering plugins…")
        plugin_map = extract_plugins(client, directory) or {}
        log.info("  ✓ %d plugin(s) found", len(plugin_map))

        log.info("  🔎 Discovering mu-plugins…")
        mu_plugin_map = extract_plugins(client, directory, mu=True) or {}

        # ── 4. Plugin version probing ─────────────────────────────────────────
        plugin_versions: dict[str, Optional[str]] = {}
        plugin_versions_latest: dict[str, Optional[tuple[str, str]]] = {}
        for slug in plugin_map:
            plugin_versions[slug] = probe_content_version(client, directory, "plugin", slug)
            plugin_versions_latest[slug] = get_content_latest_version(slug, "plugin")
        for slug in mu_plugin_map:
            if slug in plugin_map:
                continue  # skip if already processed in regular plugins
            plugin_versions[slug] = probe_content_version(client, directory, "plugin", slug)
            plugin_versions_latest[slug] = get_content_latest_version(slug, "plugin")

        # ── 5. Discover themes ────────────────────────────────────────────────
        log.info("  🔎 Discovering themes…")
        theme_map = extract_themes(client, directory) or {}
        log.info("  ✓ %d theme(s) found", len(theme_map))

        # Theme version probing
        theme_versions: dict[str, Optional[str]] = {}
        theme_versions_latest: dict[str, Optional[tuple[str, str]]] = {}
        for slug in theme_map:
            theme_versions[slug] = probe_content_version(client, directory, "theme", slug)
            theme_versions_latest[slug] = get_content_latest_version(slug, "theme")

    finally:
        client.close()

    # ── 6. Build component list ────────────────────────────────────────────
    components: list[Component] = []

    # WP Core
    if wp_version:
        components.append(Component(
            kind="core",
            slug=wp_version,
            name="WordPress Core",
            version=wp_version,
            version_source=wp_version_source,
        ))

    # Plugins
    for slug, display_name in plugin_map.items():
        components.append(Component(
            kind="plugin",
            slug=slug,
            name=display_name,
            version=plugin_versions.get(slug),
            version_source="readme.txt" if plugin_versions.get(slug) else "not-detected",
            latest_version=plugin_versions_latest.get(slug),
        ))

    # Themes
    for slug, display_name in theme_map.items():
        components.append(Component(
            kind="theme",
            slug=slug,
            name=display_name,
            version=theme_versions.get(slug),
            version_source="style.css" if theme_versions.get(slug) else "not-detected",
            latest_version=theme_versions_latest.get(slug),
        ))

    # ── 7. Vulnerability lookups ───────────────────────────────────────────
    log.info("  🔍 Looking up vulnerabilities for %d component(s)…", len(components))
    for comp in components:
        if comp.kind == "core":
            all_vulns = fetch_vulnerabilities("core", comp.slug)
        elif comp.kind == "plugin":
            all_vulns = fetch_vulnerabilities("plugin", comp.slug)
        elif comp.kind == "theme":
            all_vulns = fetch_vulnerabilities("theme", comp.slug)
        else:
            all_vulns = []

        if all_vulns is None:
            result.error = f"Could not fetch vulnerabilities for {comp.kind}/{comp.slug}"
        else:
            comp.vulnerabilities = filter_vulns_for_version(all_vulns, comp.version)
            if comp.version:
                if comp.latest_version and comp.version != comp.latest_version[0]:
                    log.info(
                        "  ⚠  %s: Installed version is %s, latest version is %s (last updated: %s)",
                        comp.name, comp.version, comp.latest_version[0], comp.latest_version[1],
                    )
        if comp.vulnerabilities:
            log.info(
                "  ⚠  %s (%s): %d vulnerability/ies found",
                comp.name, comp.version or "?", len(comp.vulnerabilities),
            )

    result.components = components
    log.info(
        "  ✓ Done — %d component(s), %d vulnerable, %d total vulns",
        len(components),
        len(result.vulnerable_components),
        result.total_vulnerabilities,
    )
    
    # ── 8. Logs Collection & Analysis (LLM) ───────────────────────────────
    try:
        log.info("  📝 Reconnecting for log collection…")
        client = client_connect(host, username, password)
        result.logs = filter_logs(client, f"{directory}/wp-content/debug.log", inc_notices=True, td=2)
        
        if result.logs and not skip_logs:
            log.info("  🧠 Analyzing logs with LLM…")
            llm_client = LLMClient(api_key=LLM_API_KEY, base_url=LLM_BASE_URL)
            llm_client.set_model(LLM_MODEL)
            llm_client.set_sysprompt(
                LLM_PROMPT
            )
            try:
                log_summary = llm_client.generate(prompt=result.logs, max_tokens=4096)
                result.log_analysis = log_summary.replace('\n', ' ').replace('\r', '')
                log.info("  ✓ Log analysis completed.")
                
            except Exception as e:
                log.error("  ✗ Error occurred while analyzing logs with LLM: %s", str(e))
        else:
            log.info("  ℹ No logs found for analysis.")
    except Exception as e:
        log.error("  ✗ Error during log collection: %s", str(e))
    finally:
        try:
            client.close()
        except Exception:
            pass

    return result
