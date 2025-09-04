#!/bin/sh
# entrypoint.sh
#
# Use env vars to update templated configs and enable/disable things based on the env vars that
# were set for this container.

# If FR_DEBUG is set, we don't want every error to terminate
if [ -z $FR_DEBUG ]; then
  echo "Starting with strict error checking..."
  set -e
else
  echo "DBG: FR_DEBUG specified, you'll need to manually crash this container even after radiusd exits."
fi

fr_conf_path=/etc/raddb
fr_cert_path=$fr_conf_path/certs
syslog_conf_path=/etc/syslog-ng.conf
mandatory_vars="FR_IDP_FQDN FR_IDP_REALM FR_IDP_SECRET FR_FLR_IP_1 FR_FLR_IP_2"
ldap_vars="FR_LDAP_SECURITY FR_LDAP_HOST_FQDN_1 FR_LDAP_HOST_FQDN_2 FR_LDAP_BASEDN FR_LDAP_BIND_USER FR_LDAP_BIND_PASS"
tls_vars="FR_TLS_CA_CERT_BASE64 FR_TLS_CA_KEY_BASE64 FR_TLS_MAXAGE"
wap_vars="FR_WAP_SECRET FR_WAP_IP"
syslog_vars="FR_LOG_SYSLOG_HOST FR_LOG_SYSLOG_PORT FR_LOG_SYSLOG_PROTO FR_LOG_SYSLOG_FAC FR_LOG_SYSLOG_SEV"

# Helper to do simple substitions of env vars in files, without logging secrets
# But first, let's narrow down the list of files we'll consider for replacement later
conf_files_with_placeholders=$(find "$fr_conf_path/" "$syslog_conf_path" -type f -exec grep -l 'FR_' {} +)
replace_var_in_conf() {
  var="$1"
  val=$(eval "printf '%s' \"\$$var\"") # safer than plain eval
  # Escape backslashes, ampersands, and pipe
  esc_val=$(printf '%s' "$val" | sed 's/[\/&|]/\\&/g')

  case "$var" in
    *PASS*|*SECRET*) echo "Replacing $var with **REDACTED**...";;
    *)               echo "Replacing $var with $esc_val...";;
  esac

  # Replace var across all relevant conf files
  for file in $conf_files_with_placeholders; do
    sed -i "s|$var|$esc_val|g" "$file"
  done
}


## General freeradius prep

# Remove mods that we're 100% certain we don't need
echo "Cleaning up pre-packaged mods we know we don't need/want..."
cd $fr_conf_path/mods-enabled
rm -f ./totp ./chap ./passwd ./ntlm_auth ./mschap

# Update our templated configs based on the env vars that were set for this container
echo "Updating freeradius config files to use values passed into the environment..."

# Sanity check for mandatory env vars and exit early if omitted
for var in $mandatory_vars; do
  eval "val=\$$var"
  if [ -z "$val" ]; then
    echo "ERROR: Mandatory env var $var is empty."
    exit 1
  else
    replace_var_in_conf "$var"
  fi
done

# Symlink the appropriate confs for our basic eduroam config (may already be linked)
cd $fr_conf_path/sites-enabled
ln -sf ../sites-available/default default


## TLS cert prep

# Sanity checks
if [ -z "$FR_TLS_CA_CERT_BASE64" ] || [ -z "$FR_TLS_CA_KEY_BASE64" ] || [ -z "$FR_TLS_MAXAGE" ]; then
  echo "ERROR: missing TLS-related details (see README), can't generate a server cert."
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

echo "Issuing ephemeral server TLS cert for EAP+TTLS using provided root CA..."
openssl ecparam -genkey -name prime256v1 -noout -out $fr_cert_path/server.key
openssl req -new -key $fr_cert_path/server.key -out $fr_cert_path/server.csr -subj "/CN=$FR_IDP_FQDN"
cat > $fr_cert_path/server.ext <<EOF
basicConstraints=CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = $FR_IDP_FQDN
EOF

# Sign / "issue" the server cert
openssl x509 -req -in $fr_cert_path/server.csr \
 -CA $fr_cert_path/ca.pem -CAkey $fr_cert_path/ca.key -CAcreateserial \
 -out $fr_cert_path/server.pem -days $FR_TLS_MAXAGE -extfile $fr_cert_path/server.ext

if [ $? -ne 0 ]; then
  echo "ERROR: failed to issue cert to self with the supplied root CA cert."
  exit 1
else
  # Show server cert details
  echo "New TLS cert generated for $FR_IDP_FQDN:"
  openssl x509 -in $fr_cert_path/server.pem -noout -subject -serial -enddate -issuer

  # Spawn background command to warn to stdout 3 days and 1 day before expiration
  # (hopefully someone's watching the container log...)
  (
  sleep $(( (FR_TLS_MAXAGE - 3) * 24 * 60 * 60)) # first warning, 3 days before expiration
  echo "*** entrypoint-cert-watchdog: FreeRADIUS server certificate expires in 3 days. You MUST restart before then (see README)! ***"
  sleep $(( 48 * 60 * 60 )) # final warning, 1 day before expiration
  echo "*** entrypoint-cert-watchdog: FreeRADIUS server certificate expires in 1 day. Restart ASAP or your eduroam users will fail to auth! ***"
  ) &
  cert_watchdog_pid=$!
  echo "Spawned entrypoint-cert-watchdog (pid $cert_watchdog_pid). You MUST restart before $FR_TLS_MAXAGE days (see README)."
fi

# Clean up after ourselves - no need to keep the CA's private key or the CSR sitting around
unset FR_TLS_CA_CERT_BASE64 FR_TLS_CA_KEY_BASE64
rm $fr_cert_path/ca.key $fr_cert_path/server.csr $fr_cert_path/server.ext


## Handle (optional) SP-related details

# Figure out WAP/controller info
if [ -n "$FR_WAP_SECRET" ] && [ -n "$FR_WAP_IP" ]; then
  echo "Wireless controller/AP details provided; will add client and/or VLAN config..."

else
  # IdP-only config (no SP): use dummy values for these env vars
  echo "No wireless controller/AP details provided. Assuming you're a rare IdP-only deployment."

  FR_WAP_SECRET="NO_WAP_SECRET_PROVIDED_SO_ASSUMING_IDP_ONLY"
  FR_WAP_IP="127.0.0.2/32" # 127.0.0.1 is already a client IP for testing
fi


# Figure out VLAN info; if VLANs were specified, use them; else toggle the VLAN config off
if [ -n "$FR_VLAN_VISITORS" ] && [ -n "$FR_VLAN_OWNUSERS" ]; then
  echo "VLAN info provided for visitors and own users; will enable VLAN assignment..."
  FR_VLAN_TOGGLE="true"
else
  echo "No VLAN info provided for visitors or own users; will disable VLAN assignment..."
  FR_VLAN_TOGGLE="false"
  # Use dummy values; if we leave them empty, the conf will fail to parse when radiusd starts
  FR_VLAN_VISITORS="1864"
  FR_VLAN_OWNUSERS="1864"
fi

# Figured out WAP/controller and VLAN details, now do it
for var in $wap_vars FR_VLAN_TOGGLE FR_VLAN_VISITORS FR_VLAN_OWNUSERS; do
  replace_var_in_conf "$var"
done


## Identity source setup - ldap vs. sql (sqlite)

# If we have LDAP vars, use them; else assume sqlite
if [ -n "$FR_LDAP_SECURITY" ]; then
  echo "LDAP config provided; will disable local sqlite DB and use external ldap..."

  # Use ldap inner-tunnel config file
  cd $fr_conf_path/sites-enabled
  ln -sf ../sites-available/inner-tunnel-ldap inner-tunnel

  # Are we using LDAPS/636 or LDAP + StartTLS/389?
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
    echo "ERROR: FR_LDAP_SECURITY must be either starttls or ldaps."
    exit 1
  fi

  # Set LDAP debug level: 0x0000: none, 0x0028: default, 0xFFFF: everything
  # If FR_DEBUG is set, crank up the LDAP debug level
  if [ -n "$FR_DEBUG" ]; then
    echo "DBG: FR_DEBUG specified, will use incredibly verbose LDAP logging..."
    FR_LDAP_DEBUG_LVL=0xFFFF
  else
    FR_LDAP_DEBUG_LVL=0x0000
  fi

  # Sanity check for LDAP-specific env vars and exit early if omitted
  for var in $ldap_vars FR_LDAP_SEC_PORT FR_LDAP_SEC_STLS_TOGGLE FR_LDAP_SEC_PREFIX FR_LDAP_DEBUG_LVL; do
    eval "val=\$$var"
    if [ -z "$val" ]; then
      echo "ERROR: LDAP requires env var $var. Specify all LDAP vars or omit all of them to use the baked-in sqlite DB instead."
      exit 1
    else
      replace_var_in_conf "$var"
    fi
  done

  # Dump LDAP CA and/or intermediate certs into a file
  echo "Installing provided LDAP root CA cert(s) to $fr_cert_path..."
  echo $FR_LDAP_HOST_ROOT_CERT_BASE64 | base64 -d > "$fr_cert_path/ldap_cacert.pem"
  # Only append intermediate to CA cert chain if it was supplied
  [ -n "$FR_LDAP_HOST_INTER_CERT_BASE64" ] && echo $FR_LDAP_HOST_INTER_CERT_BASE64 | base64 -d >> "$fr_cert_path/ldap_cacert.pem"
  # Show LDAP CA / intermediate details
  openssl x509 -in "$fr_cert_path/ldap_cacert.pem" -noout -subject -serial -enddate -issuer


  # Choose the correct ldap mod config
  # We assume you're using LDAP to talk to Active Directory
  if [ -n "$FR_LDAP_GROUP_DN" ]; then
    echo "LDAP group provided; only users in '$FR_LDAP_BASEDN' who are also members of '$FR_LDAP_GROUP_DN' will be authorized..."
    replace_var_in_conf FR_LDAP_GROUP_DN
    cd $fr_conf_path/mods-enabled
    ln -sf ../mods-available/ldap-ad-group ldap
  else
    echo "No LDAP group provided; all users in $FR_LDAP_BASEDN will be authorized..."
    cd $fr_conf_path/mods-enabled
    ln -sf ../mods-available/ldap-ad-user ldap
  fi
  echo "Done setting up ldap."
else
  echo "No LDAP config provided; will disable external ldap and use local sqlite DB..."

  # Use sqlite inner-tunnel config file
  cd $fr_conf_path/sites-enabled
  ln -sf ../sites-available/inner-tunnel-sqlite inner-tunnel

  # Create sqlite DB if it doesn't exist.
  # We do it here because prepping at container (re)build time would wipe out the DB if you've been persisting it.
  fr_sql_path=/db/freeradius.sqlite
  echo "Checking for sqlite DB at $fr_sql_path..."
  if [ ! -f "$fr_sql_path" ]; then
    echo "Not found; creating..."
    sqlite3 $fr_sql_path < $fr_conf_path/mods-config/sql/main/sqlite/schema.sql # schema
    echo "Preloading any sqlite users built into the container..."
    sqlite3 $fr_sql_path < /tmp/users-preload.sql # users
  fi

  # Sanity check: how many users in the sqlite DB?
  rows=$(sqlite3 $fr_sql_path "SELECT COUNT(*) FROM radcheck;")
  if [ "$rows" -eq 0 ]; then
    echo "$fr_sql_path's radcheck table is empty. This is fine if you didn't pre-load any users."
  else
    echo "$fr_sql_path's radcheck table contains $rows rows/users."
  fi
  echo "If you persistently mounted $fr_sql_path, use the sqlite3 command from your container host to make changes."

  # Enable the sql mod
  cd $fr_conf_path/mods-enabled
  ln -sf ../mods-available/sql sql
  echo "Done setting up sqlite."
fi


## Set up logging
if [ -n "$FR_LOG_DESTINATION" ]; then
  if [ "$FR_LOG_DESTINATION" = "syslog" ]; then
    echo "Setting up logging: syslog..."

    # Use correct linelog config
    cd $fr_conf_path/mods-enabled
    ln -sf ../mods-available/linelog-syslog linelog

    # Sanity check for syslog-specific env vars and exit early if omitted
    for var in $syslog_vars; do
      eval "val=\$$var"
      if [ -z "$val" ]; then
        echo "ERROR: syslog logging requires env var $var."
        exit 1
      else
        replace_var_in_conf "$var"
      fi
    done

    # busybox's syslogd only supports UDP, so we're using syslog-ng; fortunately for us, config is easy
    echo "Starting syslog-ng using $syslog_conf_path..."
    case "$FR_LOG_SYSLOG_PROTO" in
      TCP|tcp|UDP|udp)
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
    cd $fr_conf_path/mods-enabled
    ln -sf ../mods-available/linelog-file linelog

    # If the log file is empty, this is our first run (OK) or we didn't persist in a previous run (BAD)
    mkdir -p /var/log/freeradius
    logfile_path="/var/log/freeradius/eduroam.log"
    if [ ! -s "$logfile_path" ]; then
      echo "*** Log is empty. You MUST retain 90 days of logs. Ensure $logfile_path is persistently mapped/bound, or logs will disappear when this container exits. ***"
      touch $logfile_path && chmod 0600 $logfile_path # so you can tail -f it immediately after startup
    fi
    echo "Logs will be written to $logfile_path."

  else
    echo "ERROR: FR_LOG_DESTINATION must be 'file' or 'syslog'."
    exit 1
  fi
else
  echo "ERROR: FR_LOG_DESTINATION is required."
  exit 1
fi


## entrypoint-cert-watchdog cleanup (to avoid orphaning the bg jobs)
cleanup() {
  echo "Stopping entrypoint-cert-watchdog and syslog-ng jobs..."
  kill "$cert_watchdog_pid" || true # || true in case something else already reaped it
  kill "$syslog_pid" || true
}
trap cleanup EXIT # i.e. catch SIGINT/SIGTERM/exit and call cleanup()


## Finally, start FreeRADIUS
echo "Why are we always preparing? Just go!"

# Note we don't use exec - if we did, our trap would never fire
if [ -n "$FR_DEBUG" ]; then
  echo "Starting FreeRADIUS in debug mode..."
  radiusd -X
  # Wait to be forcefully terminated if we're debugging
  while true; do
   echo "DBG: Sleeping so you can inspect the running container...";
   sleep 3600;
  done
else
  echo "Starting FreeRADIUS (to debug, set FR_DEBUG to any value and restart)..."
  radiusd -f -l stdout
  ret=$?
fi

echo "FreeRADIUS has stopped with exit code $ret."

exit $ret
