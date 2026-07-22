# WP-Audit

WP-Audit is a Python CLI tool that audits WordPress sites by connecting over SSH to generate security reports.

It checks:
- WordPress core version
- Installed plugins and themes
- Known vulnerabilities from [wpvulnerability.net](https://www.wpvulnerability.net)
- Available latest versions for plugins/themes (from the official public WordPress API)
- Recent `wp-content/debug.log` entries for unusual errors (if present)

It outputs one Markdown report per site in `reports/`. The reports with considerable severity will be sent through an email with a summary and PDF versions of those reports.

## Requirements

- Python 3.10+
- SSH access to each WordPress host
- Network access to:
  - `https://www.wpvulnerability.net`
  - `https://api.wordpress.org`
- SMTP server to send summary emails (skippable with `--no-email`)
- LLM endpoint compatible with OpenAI client API (skippable with `--no-logs`)

## Install

```bash
cd wp-audit
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Configure

### 1. Define sites in `sites.yaml`

```yaml
sites:
  - name: "WordPress Blog"
    host: "localhost"
    username: "root"
    password: "root" # password or key passphrase
    key: "/path/to/private/key"  # optional, if using key-based auth
    url: "https://localhost"
    directory: "/var/www/html"
```

Fields used per site:
- `name`: display name in reports
- `host`: SSH hostname/IP
- `username`: SSH username
- `password`: SSH password
- `key`: path to private key file (if using key-based authentication)
- `url`: public site URL (only used for report metadata)
- `directory`: WordPress root directory on remote host

### 2. Edit runtime settings in `config.py`

Set the values you need:
- SSH port (`SSH_PORT`)
- SMTP settings (`SMTP_HOST`, `SMTP_USER`, `SMTP_PASSWORD`, `EMAIL_SENDER`, `EMAIL_RECIPIENT`) for email delivery
- LLM settings (`LLM_BASE_URL`, `LLM_MODEL`, `LLM_API_KEY`) for debug.log analysis

If SMTP is not configured, run with `--no-email`.

If LLM is not configured, run with `--no-logs`.

## Run

Default run:

```bash
python wp_audit.py
```

Useful options:

```bash
python wp_audit.py --config sites.yaml --output-dir reports --verbose --no-email --no-logs
```

Arguments:
- `--config`: path to YAML site config (default: `sites.yaml`)
- `--output-dir`: report output folder (default: `reports`)
- `--verbose`: enable verbose logs
- `--no-email`: skip summary email sending
- `--no-logs`: skip debug.log analysis and LLM summary

## Output

For each site, WP-Audit writes:

```text
[severity]_audit_<site_name>_<YYYYMMDD>.md
```

Severity is based on highest vulnerability found (`critical`, `high`, `medium`, `low`, `none`, `unknown`).

The summary email, if enabled, is sent with the following structure:

```
Subject: [WP-Audit] Security Report <DD-MM-YYYY>
Body:
Date of analysis : DD-MM-YYYY HH:MM JST
Sites analysed : <number>
Sites skipped (errored) : <number>
Sites skipped (no severity) : <number>

Reports available for : <list of sites with reports>

Attachments: 
<PDF reports>
```