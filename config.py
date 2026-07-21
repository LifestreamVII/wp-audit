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
SSH_PORT = 22  # SSH port for connecting to WordPress hosts
DEBUG_LOG_CAP = 800  # Maximum number of log lines to keep in memory for debug output
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
DISABLE_WP_CLI = False # Enforce skipping WP-CLI commands and rely on file inspection only

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4, "none": 5}

# ---------------------------------------------------------------------------
# AI Generation
# ---------------------------------------------------------------------------

LLM_MODEL = "gemma3:4b"  # Model for LLMClient
LLM_BASE_URL = "http://localhost:11434/v1/"  # Base URL for LLMClient
LLM_API_KEY = "ollama"
LLM_PROMPT = (
    "You are a WordPress security expert. Analyze the following logs and provide a short summary (max 2800 chars. if there are a lot of problematic entries) stating potential security issues in the WordPress site. Stay concise and assume the reader is a security professional. If there is a solution, mention it briefly in one or two sentences. Do not provide any other information or commentary."
)

# ---------------------------------------------------------------------------
# Email / SMTP
# ---------------------------------------------------------------------------

SMTP_HOST = ""         # SMTP server hostname
SMTP_PORT = 587                      # SMTP port (587 = STARTTLS)
SMTP_USER = ""   # SMTP login username
SMTP_PASSWORD = ""  # SMTP login password / app-password
EMAIL_SENDER = ""
EMAIL_RECIPIENT = ""
EMAIL_SUBJECT_PREFIX = "[WP-Audit] Security Report"
MAXIMUM_INLINE_TABLE_ROWS = 20  # Maximum number of rows to include inline in the email report

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("wp_audit")
