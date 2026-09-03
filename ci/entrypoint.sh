#!/usr/bin/env bash
# wp-audit CI fixture entrypoint — provision a vulnerable WordPress, then
# start sshd + apache. The provisioning step is what makes each container run
# a (randomly chosen, throwaway) vulnerable scenario.
set -euo pipefail

WP_PATH="${WP_PATH:-/var/www/html}"
mkdir -p "$WP_PATH"

# ---------------------------------------------------------------------------
# SSH: root password auth on port 22 (the surface the audit tool connects to)
# ---------------------------------------------------------------------------
echo "root:${SSH_PASSWORD:-wp-audit}" | chpasswd
{
    echo "Port 22"
    echo "PasswordAuthentication yes"
    echo "PermitRootLogin yes"
} >> /etc/ssh/sshd_config
mkdir -p /run/sshd

# ---------------------------------------------------------------------------
# Provision WordPress if requested (WP_SKIP_PROVISION=1 skips; useful when
# debugging the image itself)
# ---------------------------------------------------------------------------
if [ "${WP_SKIP_PROVISION:-0}" != "1" ]; then
    # wait for the database (compose waits for the healthcheck too, but a
    # second guard makes the container usable standalone)
    for _ in $(seq 1 60); do
        if mysqladmin ping -h"${DB_HOST:-db}" -u"${DB_USER:-wp}" -p"${DB_PASSWORD:-wp}" --silent 2>/dev/null; then
            break
        fi
        sleep 2
    done

    # 1. WordPress core at a pinned (old) version
    wp core download --version="${WP_CORE_VERSION:?WP_CORE_VERSION is required}" \
        --path="$WP_PATH" --force --allow-root
    wp config create --path="$WP_PATH" --allow-root \
        --dbname="${DB_NAME:-wp_audit}" --dbuser="${DB_USER:-wp}" \
        --dbpass="${DB_PASSWORD:-wp}" --dbhost="${DB_HOST:-db}" --skip-check
    wp core install --path="$WP_PATH" --allow-root \
        --url="${WP_URL:-http://127.0.0.1:8080}" --title="wp-audit CI Fixture" \
        --admin_user="${WP_ADMIN_USER:-admin}" --admin_password="${WP_ADMIN_PASSWORD:-admin}" \
        --admin_email="${WP_ADMIN_EMAIL:-admin@example.invalid}" --skip-email
    # enable the debug log so the audit's log-analysis path has something to find
    wp config set WP_DEBUG true --raw --path="$WP_PATH" --allow-root
    wp config set WP_DEBUG_LOG true --raw --path="$WP_PATH" --allow-root

    # 2. Plugins: "slug:version:expectation,slug:version:expectation"
    #    (version "latest" installs without pinning)
    IFS=',' read -ra plugin_specs <<< "${WP_PLUGINS:-}"
    for spec in "${plugin_specs[@]}"; do
        [ -z "$spec" ] && continue
        slug="${spec%%:*}"; rest="${spec#*:}"; ver="${rest%%:*}"
        if [ "$ver" = "latest" ]; then
            wp plugin install "$slug" --path="$WP_PATH" --allow-root --force
        else
            wp plugin install "$slug" --version="$ver" --path="$WP_PATH" --allow-root --force
        fi
    done

    # 3. Themes: same "slug:version" format
    IFS=',' read -ra theme_specs <<< "${WP_THEMES:-}"
    for spec in "${theme_specs[@]}"; do
        [ -z "$spec" ] && continue
        slug="${spec%%:*}"; rest="${spec#*:}"; ver="${rest%%:*}"
        if [ "$ver" = "latest" ]; then
            wp theme install "$slug" --path="$WP_PATH" --allow-root --force
        else
            wp theme install "$slug" --version="$ver" --path="$WP_PATH" --allow-root --force
        fi
    done

    # 4. Seed wp-content/debug.log with entries from the last 2 days so
    #    filter_logs() (which keeps entries newer than 2 days) picks them up.
    LOG="$WP_PATH/wp-content/debug.log"
    mkdir -p "$(dirname "$LOG")"
    : > "$LOG"
    for n in 1 2; do
        TS="$(date -u -d "-$((n - 1)) days" +'%d-%b-%Y %H:%M:%S' 2>/dev/null || date -u +'%d-%b-%Y %H:%M:%S')"
        echo "[$TS UTC] PHP Warning:  Undefined array key \"options\" in /var/www/html/wp-content/plugins/fixture.php on line $((10 + n))" >> "$LOG"
        echo "[$TS UTC] PHP Notice:  Trying to access array offset on value of type null in /var/www/html/wp-includes/functions.php on line $((500 + n))" >> "$LOG"
    done
fi

# ---------------------------------------------------------------------------
# Serve: sshd in the background, apache in the foreground (docker lifecycle)
# ---------------------------------------------------------------------------
/usr/sbin/sshd
exec apache2-foreground