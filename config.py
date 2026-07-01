"""
config.py — Global constants and logging configuration for wp_audit.
"""

import logging

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_CONFIG = "sites.yaml"
DEFAULT_OUTPUT_DIR = "reports"
REQUEST_TIMEOUT = 15          # seconds per HTTP request
CONNECTION_RETRIES = 2        # number of retries for transient errors
RATE_LIMIT_DELAY = 0.5        # seconds between requests to wpvulnerability.net
USER_AGENT = (
    "Mozilla/5.0 (compatible; wp_audit/1.0; +) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36"
)
WPVULN_API_BASE = "https://www.wpvulnerability.net"
WP_PLUGIN_API_BASE = (
    # e.g. : ?action=plugin_information&slug=elementor
    "https://api.wordpress.org/plugins/info/1.2/"
)
WP_THEME_API_BASE = (
    # e.g. : ?action=theme_information&slug=astra
    "https://api.wordpress.org/themes/info/1.2/"
)

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "none": 4, "unknown": 5}
LLM_MODEL = "hf.co/michaelw9999/Qwopus3.6-27B-Coder-MTP-NVFP4-GGUF"  # Model for LLMClient
LLM_BASE_URL = "http://localhost:11434/v1/"  # Base URL for LLMClient
LLM_API_KEY = "ollama"

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("wp_audit")
