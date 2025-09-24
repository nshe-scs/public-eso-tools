# We used the following guides as a basis to build the FreeRADIUS config for eduroam, then customized further:
#  https://wiki.freeradius.org/guide/eduroam and https://wiki.freeradius.org/guide/eduroam-logging
# All config values (IPs, shared secrets, etc.), are set at runtime by the entrypoint script based on env vars
# (see README and custom.env).
#
# We add sqlite, a read-centric, in-memory, "serverless" flatfile database, to the freeradius container image
# for use cases where there is no external secure LDAP identity store. Be sure to persist /db if you want to
# manually inspect/update the local user DB even when the container isn't running.

# See https://hub.docker.com/r/freeradius/freeradius-server/
FROM freeradius/freeradius-server:latest-3.2-alpine

# Add packages:
#  sqlite: for checking or making changes to the local DB from within the container
#  openssl: for issuing a new private CA-signed TLS cert for FreeRADIUS at container startup
#  syslog-ng: for syslog forwarding if chosen at runtime via env vars (recommended); we'd use busybox's own
#   syslogd, but it doesn't support TCP.
RUN apk --no-cache add sqlite openssl syslog-ng

# Add eduroam-US tailored freeradius conf files; values in these files will be set at runtime by entrypoint.sh
COPY customizations/raddb/ /etc/raddb/

# Copy sqlite user data; only applied at runtime if the DB is empty, so it won't be overwritten if persistent
RUN mkdir /db
COPY customizations/users-preload.sql /tmp/

# Copy minimal syslog-ng conf
COPY customizations/syslog-ng.conf /etc/syslog-ng.conf

# Copy custom entrypoint script
COPY customizations/entrypoint.sh /entrypoint.sh
RUN chmod a+x /entrypoint.sh

# Standard radius auth port (re-map as needed via your orchestration tool of choice); no accounting/1813
EXPOSE 1812

# Entrypoint script
CMD ["/entrypoint.sh"]
