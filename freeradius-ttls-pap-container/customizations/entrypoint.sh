#!/bin/sh
# entrypoint.sh
#
# Use env vars to update templated configs and enable/disable things based on the env vars that
# were set for this container.

# If FR_DEBUG is set, we don't want every error to terminate
if [ -z "$FR_DEBUG" ]; then
  echo "Starting normally and with strict error checking..."
  set -e
else
  echo "DBG: FR_DEBUG specified, you'll need to manually crash this container even after radiusd exits."
fi

fr_conf_path=/etc/raddb
fr_cert_path=$fr_conf_path/certs
syslog_conf_path=/etc/syslog-ng.conf

# Narrow down the list of files we'll consider for replacement later.
#conf_files_with_placeholders=$(find "$fr_conf_path/" "$syslog_conf_path" -type f -exec grep -l 'FR_' {} +)

# Helper to do simple substitions of env vars in files, without logging secrets
replace_var_in_conf() {
  var="$1"
  val=$(eval "printf '%s' \"\$$var\"") # safer than plain eval
  # Escape backslashes, ampersands, and pipe
  esc_val=$(printf '%s' "$val" | sed 's/[\/&|]/\\&/g')

  # Only say what we're doing if we're debugging
  if [ -n "$FR_DEBUG" ]; then
    case "$var" in
      *PASS*|*SECRET*) echo "Replacing $var with **REDACTED**...";;
      *)               echo "Replacing $var with $esc_val...";;
    esac
  fi

  # Replace var across all relevant conf files. List may have changed since script start...
  conf_files_with_placeholders=$(find "$fr_conf_path/" "$syslog_conf_path" -type f -exec grep -l 'FR_' {} +)
  for file in $conf_files_with_placeholders; do
    sed -i "s|$var|$esc_val|g" "$file"
  done
}


## General freeradius prep

# Remove mods that we're 100% certain we don't need
echo "Removing pre-packaged mods we don't want..."
cd "$fr_conf_path/mods-enabled"
rm -f ./totp ./chap ./passwd ./ntlm_auth ./mschap ./replicate

# Update our templated configs based on the env vars that were set for this container
echo "Updating config files to use values passed into the environment..."

# Sanity check for general/federation-related env vars
for var in FR_IDP_FQDN FR_IDP_REALM FR_FLR_SECRET FR_FLR_IP_1 FR_FLR_IP_2; do
  eval "val=\$$var"
  if [ -z "$val" ]; then
    echo "ERROR: Mandatory env var '$var' is empty."
    exit 1
  else
    replace_var_in_conf "$var"
  fi
done

# Symlink the appropriate confs for our eduroam config (may already be linked)
cd "$fr_conf_path/sites-enabled"
ln -sf ../sites-available/default default


## TLS cert prep

# Sanity checks for TLS cert generation
if [ -z "$FR_TLS_CA_CERT_BASE64" ] || [ -z "$FR_TLS_CA_KEY_BASE64" ] || [ -z "$FR_TLS_MAXAGE" ]; then
  echo "ERROR: missing TLS-related details (see README), can't generate a server TLS cert."
  exit 1
fi

# Ensure we got a number
case "$FR_TLS_MAXAGE" in
  ''|*[!0-9]*) echo "ERROR: FR_TLS_MAXAGE must be a number."; exit 1;;
esac

# Dump the CA cert and key into a file and sanity check... if blank, everything will fail
echo "Installing provided root CA cert and key to $fr_cert_path..."
echo $FR_TLS_CA_CERT_BASE64 | base64 -d > $fr_cert_path/ca.pem
echo $FR_TLS_CA_KEY_BASE64 | base64 -d > $fr_cert_path/ca.key

echo "Issuing ephemeral server TLS cert for EAP-TTLS using provided root CA..."
openssl ecparam -genkey -name prime256v1 -noout -out "$fr_cert_path/server.key"
openssl req -new -key "$fr_cert_path/server.key" -out "$fr_cert_path/server.csr" -subj "/CN=$FR_IDP_FQDN"
cat > "$fr_cert_path/server.ext" <<EOF
basicConstraints=CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = $FR_IDP_FQDN
EOF

# Sign / "issue" the server cert
openssl x509 -req -in "$fr_cert_path/server.csr" \
 -CA "$fr_cert_path/ca.pem" -CAkey "$fr_cert_path/ca.key" -CAcreateserial \
 -out "$fr_cert_path/server.pem" -days $FR_TLS_MAXAGE -extfile "$fr_cert_path/server.ext"

if [ $? -ne 0 ]; then
  echo "ERROR: failed to issue ephemeral server TLS cert to self with provided root CA cert."
  exit 1
else
  # Show server cert details
  echo "Issued new server TLS cert to self ($FR_IDP_FQDN):"
  openssl x509 -in "$fr_cert_path/server.pem" -noout -subject -serial -enddate -issuer

  # Nobody will hear us scream unless they're watching the container console log, but we can try
  (
  sleep $(( (FR_TLS_MAXAGE - 3) * 24 * 60 * 60)) # 3 days before expiration
  echo "*** entrypoint-cert-watchdog: Server TLS cert expires in 3 days. You MUST restart before then (see README). ***"
  sleep $(( 48 * 60 * 60 )) # 1 day before expiration
  echo "*** entrypoint-cert-watchdog: Server TLS cert expires in 1 day. Restart ASAP or users will fail to auth (see README). ***"
  sleep $(( 23 * 60 * 60 + (55 * 60) )) # 5 minutes before expiration
  echo "*** entrypoint-cert-watchdog: Server TLS cert expires in 5 min. Exiting. Hopefully something auto-restarts this container. ***"
  exit 0 # clean exit to hopefully spur a clean restart by the container host/orchestrator
  ) &
  cert_watchdog_pid=$!
  echo "Spawned entrypoint-cert-watchdog (pid $cert_watchdog_pid). Will automatically stop 5 minutes before $FR_TLS_MAXAGE days elapse (see README)."
fi

# Clean up after ourselves - no need to keep the CA's private key or the CSR sitting around
unset FR_TLS_CA_CERT_BASE64 FR_TLS_CA_KEY_BASE64
rm "$fr_cert_path/ca.key" "$fr_cert_path/server.csr" "$fr_cert_path/server.ext"


## Handle AP-related details
echo "Generating client configurations based on FR_WAP_IP..."

# Figure out WAP/controller info
if [ -z "$FR_WAP_SECRET" ] || [ -z "$FR_WAP_IP" ]; then
  echo "No wireless controller/AP details provided. Assuming you're a rare IdP-only deployment."
  FR_WAP_SECRET="NO_WAP_SECRET_PROVIDED_SO_ASSUMING_IDP_ONLY"
  FR_WAP_IP="127.0.0.1/32"
fi

# Split FR_WAP_IP by comma (ipv4, ipv6, cidr subnets, and hostnames are OK)
# Use lazyish ipv6 checking: if there's a colon, it's ipv6, otherwise it must be ipv4
idx=0
for addr in $(printf %s "$FR_WAP_IP" | tr ',' ' '); do
    [ -n "$addr" ] || continue
    case "$addr" in *:*) addr_type=ipv6addr ;; *) addr_type=ipaddr ;; esac

    this_client_conf="$fr_conf_path/clients.d/wap-$idx.conf"
    echo "Generating $this_client_conf for client '$addr'..."
    cat >"$this_client_conf" <<EOF
# Auto-generated by entrypoint script
client wap-$idx {
    $addr_type = $addr
    secret = '$FR_WAP_SECRET'
    nastype = wireless
    require_message_authenticator = yes
}
EOF
    chmod 0640 "$this_client_conf"
    idx=$((idx+1))
done
echo "Generated $idx clients."

# Figure out VLAN info; if VLANs were specified, use them; else toggle the VLAN config off
if [ -n "$FR_VLAN_VISITORS" ] && [ -n "$FR_VLAN_OWNUSERS" ]; then
  echo "VLAN info provided for visitors and own users; will enable VLAN assignment..."
  FR_VLAN_TOGGLE="true"
else
  echo "No VLAN info provided for visitors or own users; will disable VLAN assignment..."
  FR_VLAN_TOGGLE="false"

  # Dummy values (nulled out in the config) because radiusd conf will fail to parse if blank
  FR_VLAN_VISITORS="1864"
  FR_VLAN_OWNUSERS="1864"
fi

# Figured out WAP/controller and VLAN details, now do it
for var in FR_VLAN_TOGGLE FR_VLAN_VISITORS FR_VLAN_OWNUSERS; do
  replace_var_in_conf "$var"
done


## Identity source setup

# Sanity check for identity source
case "$FR_IDENTITY_SOURCE" in
  ldap|google|sql)
    echo "Configuring identity source '$FR_IDENTITY_SOURCE'..." ;;
  *)
    echo "ERROR: FR_IDENTITY_SOURCE must be 'ldap', 'google', or 'sql'." && exit 1 ;;
esac


# AD/LDAP and/or Google (a more specialized case of LDAP) details
if [ "$FR_IDENTITY_SOURCE" = "google" ] || [ "$FR_IDENTITY_SOURCE" = "ldap" ]; then
  # Use ldap inner-tunnel config file
  cd "$fr_conf_path/sites-enabled"
  ln -sf ../sites-available/inner-tunnel-ldap inner-tunnel

  # If we're using Google, we know a couple defaults and need a couple different values
  if [ "$FR_IDENTITY_SOURCE" = "google" ]; then
    # Google, not AD/LDAP
    rm "$fr_conf_path/mods-available"/ldap-ad-*

    # Instead of worrying about CA certs, we need Google's LDAP Client cert/key
    if [ -n "$FR_LDAP_BIND_GOO_CERT" ] && [ "$FR_LDAP_BIND_GOO_KEY" ]; then
      FR_LDAP_SECURITY="ldaps"
      FR_LDAP_HOST_FQDN="ldap.google.com"
    else
      echo "ERROR: FR_LDAP_BIND_GOO_CERT and FR_LDAP_BIND_GOO_KEY are both required."
      exit 1
    fi

    # Dump Google cert + key pair, remove non-Google ldap confs
    echo "Installing provided Google cert + key to $fr_cert_path..."
    echo $FR_LDAP_BIND_GOO_CERT | base64 -d > "$fr_cert_path/google.pem"
    echo $FR_LDAP_BIND_GOO_KEY | base64 -d > "$fr_cert_path/google.key"
    openssl x509 -in "$fr_cert_path/google.pem" -noout -subject -serial -enddate
    echo "*** You MUST renew your Google LDAP Client cert before it expires; you've set a calendar reminder, right? ***"
  else
    # AD/LDAP, not Google
    rm "$fr_conf_path/mods-available"/ldap-goo-*

    # Dump LDAP CA and/or intermediate certs into a file
    echo "Installing provided LDAP root CA cert(s) to $fr_cert_path..."
    echo $FR_LDAP_HOST_ROOT_CERT_BASE64 | base64 -d > "$fr_cert_path/ldap_cacert.pem"
    # Only append intermediate to CA cert chain if it was supplied
    [ -n "$FR_LDAP_HOST_INTER_CERT_BASE64" ] && echo $FR_LDAP_HOST_INTER_CERT_BASE64 | base64 -d >> "$fr_cert_path/ldap_cacert.pem"
    # Show LDAP CA / intermediate details
    openssl x509 -in "$fr_cert_path/ldap_cacert.pem" -noout -subject -serial -enddate -issuer
  fi

  # Set these regardless of LDAP flavor

  # LDAPS/636 or LDAP+StartTLS/389?
  if [ "$FR_LDAP_SECURITY" = "starttls" ]; then
    echo "Will use LDAP + StartTLS over port 389..."
    FR_LDAP_SEC_PORT=389
    FR_LDAP_SEC_STLS_TOGGLE="yes"
    FR_LDAP_SEC_PREFIX="ldap"
  elif [ "$FR_LDAP_SECURITY" = "ldaps" ]; then
    echo "Will use LDAPS over port 636..."
    FR_LDAP_SEC_PORT=636
    FR_LDAP_SEC_STLS_TOGGLE="no"
    FR_LDAP_SEC_PREFIX="ldaps"
  else
    echo "ERROR: FR_LDAP_SECURITY must be 'starttls' or 'ldaps'."
    exit 1
  fi

  # Handle multiple LDAP servers by splitting FR_LDAP_HOST_FQDN into separate "server = 'hostname'" lines
  echo "Parsing LDAP host(s) from config..."
  hosts_block="$(awk -v hosts="$FR_LDAP_HOST_FQDN" '
    BEGIN {
      n = split(hosts, a, /,/)
      for (i = 1; i <= n; i++) {
        gsub(/^[ \t]+|[ \t]+$/, "", a[i])
        if (a[i] != "") printf "server = '\''%s'\''\n", a[i]
      }
    }'
  )"
  num_ldap_hosts=$(echo "$hosts_block" | wc -l | cut -f1 -d' ')
  if [ "$num_ldap_hosts" -eq 0 ]; then
    echo "ERROR: FR_LDAP_HOST_FQDN must contain at least 1 LDAP server hostname."
    exit 1
  fi

  # Finally write the lines to whichever ldap configs weren't deleted earlier
  for f in $fr_conf_path/mods-available/ldap-*; do
    awk -v blk="$hosts_block" '
      /^[[:space:]]*FR_LDAP_FQDN_BLOCK[[:space:]]*$/ { print blk; next }
      { print }
    ' "$f" > "$f.tmp" && mv "$f.tmp" "$f"
  done
  echo "Added $num_ldap_hosts LDAP host(s)."

  # Set OpenLDAP debug level: 0x0000: none; 0x0108: CONNS+STATS; 0xFFFF: everything
  # If FR_DEBUG is set, crank up the LDAP debug level but not too much
  if [ -n "$FR_DEBUG" ]; then
    echo "DBG: FR_DEBUG specified, will use verbose LDAP logging..."
    FR_LDAP_DEBUG_LVL=0x0108
  else
    FR_LDAP_DEBUG_LVL=0x0000
  fi

  # Sanity check for LDAP-specific env vars
  for var in FR_LDAP_SECURITY FR_LDAP_BASEDN FR_LDAP_BIND_USER FR_LDAP_BIND_PASS FR_LDAP_SEC_PORT FR_LDAP_SEC_STLS_TOGGLE FR_LDAP_SEC_PREFIX FR_LDAP_DEBUG_LVL; do
    eval "val=\$$var"
    if [ -z "$val" ]; then
      echo "ERROR: LDAP requires env var '$var'."
      exit 1
    else
      replace_var_in_conf "$var"
    fi
  done

  # Choose between group and all-users config
  if [ -n "$FR_LDAP_GROUP_DN" ]; then
    echo "Only users in '$FR_LDAP_BASEDN' who are also members of '$FR_LDAP_GROUP_DN' will be authorized..."
    replace_var_in_conf FR_LDAP_GROUP_DN
    cd "$fr_conf_path/mods-enabled"
    ln -sf ../mods-available/ldap-*-group ldap
  else
    echo "All users in '$FR_LDAP_BASEDN' will be authorized..."
    cd "$fr_conf_path/mods-enabled"
    ln -sf ../mods-available/ldap-*-user ldap
  fi
elif [ "$FR_IDENTITY_SOURCE" = "sql" ]; then
  echo "Setting up sqlite identity source..."

  # Use sqlite inner-tunnel config file
  cd "$fr_conf_path/sites-enabled"
  ln -sf ../sites-available/inner-tunnel-sqlite inner-tunnel

  # Create sqlite DB if it doesn't exist.
  # We do it here because prepping at container (re)build time would wipe out the DB if you've been persisting it.
  fr_sql_path=/db/freeradius.sqlite
  echo "Checking for sqlite DB at '$fr_sql_path'..."
  if [ ! -f "$fr_sql_path" ]; then
    echo "Not found; creating and loading schema..."
    sqlite3 $fr_sql_path < "$fr_conf_path/mods-config/sql/main/sqlite/schema.sql"
    echo "Preloading any sqlite users built into the container..."
    sqlite3 $fr_sql_path < /tmp/users-preload.sql
  fi

  # Sanity check: how many users in the sqlite DB?
  rows=$(sqlite3 $fr_sql_path "SELECT COUNT(*) FROM radcheck;")
  if [ "$rows" -eq 0 ]; then
    echo "'$fr_sql_path' radcheck table is empty. This is fine if you're testing or didn't pre-load any users."
  else
    echo "'$fr_sql_path' radcheck table contains $rows rows/users."
  fi
  echo "If you persistently mounted $fr_sql_path, use the sqlite3 command from your container host to make changes."

  # Enable the sql mod
  cd "$fr_conf_path/mods-enabled"
  ln -sf ../mods-available/sql sql
fi
echo "Done setting up identity source."


## Set up logging

# Sanity check for logging method
case "$FR_LOG_DESTINATION" in
  file|syslog)
    echo "Configuring logging method '$FR_LOG_DESTINATION'..." ;;
  *)
    echo "ERROR: FR_LOG_DESTINATION must be 'file' or 'syslog'." && exit 1 ;;
esac

# If FR_DEBUG is set, log more details than usual
if [ -n "$FR_DEBUG" ]; then
  echo "DBG: FR_DEBUG specified, will log every received RADIUS packet..."
  FR_VERBOSE_TOGGLE="true"
else
  FR_VERBOSE_TOGGLE="false"
fi
replace_var_in_conf FR_VERBOSE_TOGGLE

if [ "$FR_LOG_DESTINATION" = "syslog" ]; then
  # Use correct linelog config
  cd "$fr_conf_path/mods-enabled"
  ln -sf ../mods-available/linelog-syslog linelog

  # Sanity check for syslog-specific env vars
  for var in FR_LOG_SYSLOG_HOST FR_LOG_SYSLOG_PORT FR_LOG_SYSLOG_PROTO FR_LOG_SYSLOG_FAC FR_LOG_SYSLOG_SEV; do
    eval "val=\$$var"
    if [ -z "$val" ]; then
      echo "ERROR: syslog requires env var '$var'."
      exit 1
    else
      replace_var_in_conf "$var"
    fi
  done

  # busybox's syslogd only supports UDP, so we're using syslog-ng; fortunately for us, config is easy
  echo "Starting syslog-ng using $syslog_conf_path..."
  case "$FR_LOG_SYSLOG_PROTO" in
    tcp|udp)
      syslog-ng --no-caps -f $syslog_conf_path &
      syslog_pid=$!
      sleep 1 # just in case...
      ;;
    *) echo "ERROR: FR_LOG_SYSLOG_PROTO must be 'tcp' or 'udp'." && exit 1 ;;
  esac
  echo "Spawned syslog-ng (pid $syslog_pid), forwarding to $FR_LOG_SYSLOG_HOST:$FR_LOG_SYSLOG_PORT via $FR_LOG_SYSLOG_PROTO."

elif [ "$FR_LOG_DESTINATION" = "file" ]; then
  echo "Setting up logging: file..."

  # Use correct linelog config
  cd "$fr_conf_path/mods-enabled"
  ln -sf ../mods-available/linelog-file linelog

  # If the log file is empty, this is our first run (OK) or we didn't persist in a previous run (BAD)
  mkdir -p /var/log/freeradius
  logfile_path=/var/log/freeradius/eduroam.log
  if [ ! -s "$logfile_path" ]; then
    echo "*** Log '$logfile_path' is empty. You MUST retain 90 days of logs. Ensure '$(dirname $logfile_path)' is persistently mapped/bound, or logs will disappear when this container exits. ***"
    # Ensure we can tail -f even before any requests are logged
    touch "$logfile_path" && chmod 0600 "$logfile_path"
  fi
  echo "Logs will be appended to '$logfile_path'."
fi


## Enable other important modules
cd "$fr_conf_path/mods-enabled"
ln -sf ../mods-available/proxy_rate_limit proxy_rate_limit
ln -sf ../mods-available/cache cache


## Cleanup traps, to avoid orphaning bg jobs
cleanup() {
  echo "Stopping entrypoint-cert-watchdog and syslog-ng if running..."
  kill "$cert_watchdog_pid" 2>/dev/null
  kill "$syslog_pid" 2>/dev/null
}
term_handler() {
  echo "Got SIGTERM/SIGINT, stopping FreeRADIUS..."
  kill -TERM "$radiusd_pid" 2>/dev/null
  if [ -n "$FR_DEBUG" ]; then
    echo "DBG: Stopping debug loop"
    unset FR_DEBUG
    kill "$dbg_sleep_pid" 2>/dev/null
  fi
}
trap term_handler SIGTERM SIGINT
trap cleanup EXIT # i.e. call cleanup() when script exits


## Finally, start FreeRADIUS
echo "Why are we always preparing? Just go!"

if [ -n "$FR_DEBUG" ]; then
  echo "Starting FreeRADIUS in debug mode..."
  radiusd -X &
  radiusd_pid=$!
else
  echo "Starting FreeRADIUS (to debug, set FR_DEBUG to any value and restart)..."
  radiusd -f -l stdout &
  radiusd_pid=$!
fi

# Capture exit code so we can exit gracefully with the same code (unless debugging)
wait "$radiusd_pid"
ret=$?
echo "FreeRADIUS has stopped with exit code $ret."

# Wait to be forcefully terminated if we're debugging
while [ -n "$FR_DEBUG" ]; do
 echo "DBG: Sleeping so you can inspect the running container..."
 sleep 3600 &
 dbg_sleep_pid=$!
 wait "$dbg_sleep_pid"
done

exit $ret
