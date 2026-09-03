# wp-audit CI test fixture — a deliberately vulnerable WordPress instance.
#
# This image is NEVER meant for production: it runs an old WP core, installs
# known-vulnerable plugin/theme versions on demand, and exposes SSH so the
# wp_audit CLI can audit it exactly like a real customer host.
#
# The scenario (core version, plugins, themes) is provisioned at CONTAINER
# START by ci/entrypoint.sh from env vars (see ci/generate_scenario.py), so
# every CI run gets a fresh, throwaway vulnerable instance.
#
# Build context: repository root  (docker build -f ci/Dockerfile .)

FROM php:8.1-apache

# system deps: sshd (audit surface), mysql client (db healthchecks), unzip/curl (wp-cli)
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        openssh-server \
        default-mysql-client \
        unzip \
        curl \
    ; \
    docker-php-ext-install mysqli pdo_mysql; \
    a2enmod rewrite headers; \
    rm -rf /var/lib/apt/lists/*

# wp-cli (used by entrypoint.sh to install core/plugins/themes at pinned versions)
RUN curl -sSL https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar \
        -o /usr/local/bin/wp \
    && chmod +x /usr/local/bin/wp

# sshd needs a writable runtime dir
RUN mkdir -p /run/sshd

COPY ci/entrypoint.sh /usr/local/bin/wp-audit-entrypoint.sh
RUN chmod +x /usr/local/bin/wp-audit-entrypoint.sh

EXPOSE 22 80

ENTRYPOINT ["wp-audit-entrypoint.sh"]
CMD ["apache2-foreground"]