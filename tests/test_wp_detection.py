"""Unit tests for wp_detection.py — WP/plugin/theme discovery over SSH.

Uses FakeClient (see conftest.py) so no real SSH connection is involved.
The file-based paths are exercised by forcing has_wp_cli() to return False.
"""

import pytest

import wp_detection
from conftest import FakeClient


@pytest.fixture(autouse=True)
def _no_wp_cli(monkeypatch):
    """Always exercise the file-inspection code paths in these tests."""
    monkeypatch.setattr(wp_detection, "has_wp_cli", lambda client: False)


# ---------------------------------------------------------------------------
# detect_wp_version
# ---------------------------------------------------------------------------
def test_detect_wp_version_from_version_php():
    client = FakeClient({
        "version.php": "$wp_version = '6.4.2';",
    })
    version, source = wp_detection.detect_wp_version(client, "/var/www/html")
    assert version == "6.4.2"
    assert source == "version.php"


def test_detect_wp_version_not_detected():
    client = FakeClient({})  # no matching output anywhere
    version, source = wp_detection.detect_wp_version(client, "/var/www/html")
    assert version is None
    assert source == "not-detected"


# ---------------------------------------------------------------------------
# probe_content_version
# ---------------------------------------------------------------------------
def test_probe_plugin_version_from_readme_stable_tag():
    client = FakeClient({"stable tag": "Stable tag: 6.8"})
    v = wp_detection.probe_content_version(client, "/var/www/html", "plugin", "wp-file-manager")
    assert v == "6.8"


def test_probe_plugin_version_from_php_header():
    # no readme match -> falls back to the Version: header grep
    client = FakeClient({"Version:": " * Version: 5.3.1"})
    v = wp_detection.probe_content_version(client, "/var/www/html", "plugin", "contact-form-7")
    assert v == "5.3.1"


def test_probe_theme_version_from_readme():
    client = FakeClient({"stable tag": "Stable tag: 2.6.0"})
    v = wp_detection.probe_content_version(client, "/var/www/html", "theme", "hello-elementor")
    assert v == "2.6.0"


def test_probe_version_not_found():
    client = FakeClient({})
    v = wp_detection.probe_content_version(client, "/var/www/html", "plugin", "ghost")
    assert v is None


# ---------------------------------------------------------------------------
# extract_plugins
# ---------------------------------------------------------------------------
def test_extract_plugins_lists_and_names():
    client = FakeClient({
        "ls -1 /var/www/html/wp-content/plugins": "akismet\nwp-file-manager\nsingle.php\n.hidden",
        "plugins/akismet/": "",  # no header -> falls back to slug
        "plugins/wp-file-manager/": "Plugin Name: File Manager",
    })
    plugins = wp_detection.extract_plugins(client, "/var/www/html")
    assert plugins == {"akismet": "akismet", "wp-file-manager": "File Manager"}
    # single-file plugin (single.php) and hidden dirs are skipped


def test_extract_plugins_empty_dir_returns_none():
    client = FakeClient({})
    assert wp_detection.extract_plugins(client, "/var/www/html") is None


def test_extract_mu_plugins_uses_mu_dir():
    client = FakeClient({
        "ls -1 /var/www/html/wp-content/mu-plugins": "mustuse-loader",
        "mu-plugins/mustuse-loader/": "Plugin Name: MU Loader",
    })
    plugins = wp_detection.extract_plugins(client, "/var/www/html", mu=True)
    assert plugins == {"mustuse-loader": "MU Loader"}


# ---------------------------------------------------------------------------
# extract_themes
# ---------------------------------------------------------------------------
def test_extract_themes_lists_and_names():
    client = FakeClient({
        "ls -1 /var/www/html/wp-content/themes": "hello-elementor\nastra\nindex.php",
        "themes/hello-elementor/": "Theme Name: Hello Elementor",
        "themes/astra/": "",
    })
    themes = wp_detection.extract_themes(client, "/var/www/html")
    assert themes == {"hello-elementor": "Hello Elementor", "astra": "astra"}


def test_extract_themes_empty_returns_none():
    client = FakeClient({})
    assert wp_detection.extract_themes(client, "/var/www/html") is None