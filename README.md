# eSO-hostable rapid-deployment containerized FreeRADIUS solution for K-12s, libraries, museums, etc.
This is a containerized eduroam IdP + SP solution using FreeRADIUS, pre-configured and tailored for K-12, library, and museum deployments in the US. There are numerous examples of working eduroam configs in the wild, but many are so generalized and flexible that it can be daunting for a new eduroam IdP deployer to sort out international vs. US-specific items, considerations around different EAP types, and so forth. Our goal is to provide a free, reasonably secure by default, rapidly-deployable container, pre-configured to work with the eduroam-US infrastructure and minimize maintenance effort for whoever hosts the IdP (whether a school, small college, or an eduroam Support Organization on behalf of its constituents).

## Table of Contents

- [Setup](#setup)
  - [eduroam registration](#eduroam-registration)
  - [Container hosting](#container-hosting)
  - [Bootstrap CA script](#bootstrap-ca-script)
  - [Wireless profile builder](#wireless-profile-builder-eg-eduroam-cat-to-build--geteduroam-to-distribute-and-install)
  - [Identity options](#identity-options---randomized-tokens-or-bring-your-own)
- [Building and running the container](#building-and-running-the-container)
  - [Environmental variables](#environtmental-variables)
    - [The basics](#the-basics)
    - [Logging](#logging)
- [Finding LDAP Certificates in your Active Directory environment](#finding-ldap-certificates-in-your-active-directory-environment)
  - [Extracting the root and intermediate CA certs](#extracting-the-root-and-intermediate-ca-certs)
- [Under the hood](#under-the-hood)
  - [Building and updating](#building-and-updating)
  - [Entrypoint script magic](#entrypoint-script-magic)

## OK, but why?
As an eduroam Support Organization (eSO), we had the following goals:
- Give eSOs a quick and securely configured eduroam IdP to host on behalf of their smaller constituents who lack a central identity store, have a very small IT department, or have a relatively small set of users. By bundling a sqlite DB with randomizable credentials, credentials can be issued in person at the beginning of a school year, then easily destroyed and re-created the next school year. In many cases, a central identity environment exists but the IT team may lack the expertise, time, or willingness to set up NPS or a Linux VM to work with eduroam.
- Give constituents (i.e. schools, libraries, museums) a simple cookie-cutter eduroam IdP they can host themselves on old hardware, a prosumer-grade NAS that supports Docker, at a consultant's cloud provider, etc. in a way that can be quickly configured to talk to Active Directory, Azure/Entra, Google, or similar, over a secure LDAP connection. No NTLM or MCHAPv2 auth here; we chose EAP-TTLS + PAP, which takes a bit of work to [bind to LDAP and send the plaintext password inside an encrypted tunnel](https://www.freeradius.org/documentation/freeradius-server/3.2.8/concepts/modules/ldap/authentication.html)). When properly configured, this is quite reasonably secure - so we've focused on making it hard to misconfigure.
- Contribute our work back to the broader education community. While we're focused on spurring eduroam adoption in our neck of the woods, this is still broadly applicable (just not fine-tuned) to larger education-affiliated organizations and other countries.

# Setup
## eduroam registration
We assume you're a US-based [eduroam Support Organization (eSO)](https://incommon.org/eduroam/eduroam-k12-libraries-museums/), but maybe you're a school, school district, EDU-focused contractor, a community college... In any case, you must be able to register an IdP and/or SP in the eduroam infrastructure, as this container needs to be registered for roaming to work. US-based organizations do this via Internet2's Federation Manager tool. If you don't know what that is, reach out to Internet2 or your state's eSO. 

## Container hosting
You'll need to be able to host a container. You'll need to be able to reboot the container on a schedule (or be in the habit of redeploying so you get the latest security updates from the upstream FreeRADIUS container).

If you're an eSO, we suggest following a repeatable DNS pattern like `(constituent).roam.(your-eso-domain)`, e.g. `aa.roam.example.org`, `bb.roam.example.org`, `cc.roam.example.org`, etc. Users would then authenticate as `foo@aa.roam.example.org`. This should also make orchestration easier if you want to build a repeatable workflow.

## Bootstrap CA script
The *Certificates* section later in this document goes into greater detail about why/how it works, but you'll need to run the provided `bootstrap-ca.sh` bash script on a Linux system other than the container itself, and hang on to its output before you can start your container for the first time. This step only needs to be done once per constituent, and the resulting CA certificate is valid for 20 years.

## Wireless profile builder (e.g. eduroam CAT to build / geteduroam to distribute and install)
Presumably, you don't have a commercial wireless profile deployment tool. [eduroam CAT](https://cat.eduroam.org) is an excellent solution for building a wireless profile for your users. Your users can easily retrieve and install the profile via the `geteduroam` app, available at their local friendly official app store (or alternatively via the CAT website). Work with your NRO (e.g. Internet2 in the US) to register for CAT admin access if you do not already have access for the IdP realm you are supporting with this container. Do NOT encourage users to manually connect and blindly fill in values, accept mystery certificates, ignore warnings, etc.; eduroam is as secure as you configure it to be.

## Identity options

### Randomized tokens (local sqlite DB, manual tracking of who gets which identities)
This option is probably best suited for demo / temporary guest scenarios; or small schools, libraries, or museums lacking a central secure LDAP-based identity store for their students, volunteers, and staff.

The bundled sqlite user DB can host identities for a constituent that doesn't have a central identity store. Just use PowerShell / pwsh 7.x to run `New-HostedEduroamTokens.ps1 -Realm foo.example.org -TokenCount number` to generate as many random credentials as you need, and dump the output into `users-preload.sql` before building the container. We suggest using the DNS pattern mentioned above for the users' realm.

If you don't have PowerShell or PowerShell Core available to you, you can run the AI-generated (but human curated) bash translation: `new_hosted_eduroam_tokens.sh foo.example.org number`. In either case, you can also copy and paste the output to a spreadsheet or other document, and note the recipient, and date/time issued, of each username + password. If you choose to do this, you must not lose or widely distribute the document or you will have no idea who your users are - and that's a Bad Thing(tm) worthy of starting over from scratch with a new set of identities.

In a future release, we'd like to bundle an incredibly basic UI in the form of a sqlite editor to reduce the administrative burden for this scenario. Baby steps...

### Bring your own (secure LDAP, i.e. Active Directory; Entra / Google planned for a future release)
If you already have an identity store, you'll need credentials to let FreeRADIUS talk to that identity store over LDAP + StartTLS (port 389; not the same as LDAPS over port 636). You'll also need to know the base DN / OU where the user accounts permitted to connect to eduroam reside (i.e. the typical LDAP details). Lastly, you'll need the LDAP server's root CA and, if it uses one, its intermediate cert, so authentication between this container and your LDAP backend can be secured. You do not need the actual certificate used by the LDAP server, i.e. the end entity cert; the idea is to trust the issuer of the cert, not the specific cert.

If you're using Active Directory but not protecting LDAP communication with a certificate of some sort, this container won't have a secure way to talk to your DCs... that's a Bad Thing(tm).

# Building and running the container
Build and run it as you typically would with the supplied `Dockerfile` and/or `docker-compose.yml`. We tested with `docker-compose` for convenience, but you could use other methods.

## Environmental variables
However you choose to run it, whether manually or via an automation/orchestration tool, the container configuration is completely driven by environmental variables. The entrypoint script will put the important details in the correct places in the various freeradius config files during container startup, and link the correct sites/mods/etc. based on your needs. We recommend setting these variables via the supplied `custom.env` file. You'll need one per container. Some variables can be left blank.

### The basics
`FR_IDP_FQDN`: The fully qualified public hostname for this container, which will also be the hostname included in the TLS certificate generated at startup.

`FR_IDP_SECRET`: RADIUS shared secret you configured in Federation Manager for this IdP, e.g. a random 63-character mixed-case alphanumeric string that is NOT the same as `FR_WAP_SECRET`. One quick method to generate one: `echo $(tr -dc 'A-Za-z0-9' </dev/urandom | head -c63)`.

`FR_IDP_REALM`: The fully qualified domain name for your users, e.g. `example.org` or `constituent-name.roam.your-eso-name.example.org`

`FR_FLR_IP_1`: IP address of the first federation level RADIUS proxy, e.g. 163.253.30.2 for tlrs2.eduroam.us (west coast).

`FR_FLR_IP_2`: IP address of the second federation level RADIUS proxy, e.g. 163.253.31.2 for tlrs1.eduroam.us (east coast).

### TLS-related details, also required
Certificate management is generally a pain, even with automation, but we've tried to ease the pain a bit. See *Certificates* below for more details about the approach we've taken.

`FR_TLS_CA_CERT_BASE64`: The base64-encoded x.509 private CA cert, in PEM format, that will be used to generate a new TLS cert for FreeRADIUS to use every time the container starts. Clients will need to trust this CA cert. *Do not reuse another CA cert for this purpose.*

`FR_TLS_CA_KEY_BASE64`: The base64-encoded private key corresponding to the private CA cert.

`FR_TLS_MAXAGE`: Number of days a newly-autogenerated server TLS cert should last. This is effectively a "use by" / expiration date for your container because FreeRADIUS needs to completely restart to use a new TLS cert. We recommend 90.

### Only omit these if you are not operating an SP (i.e. wireless hotspot) as part of your eduroam deployment. This is a VERY uncommon situation.
`FR_WAP_SECRET`: RADIUS shared secret you configured on your wireless APs / controller to talk to this container, e.g. a random 63-character mixed-case alphanumeric string that is NOT the same as `FR_IDP_REALM`.

`FR_WAP_IP`: IP address or CIDR subnet of your own wireless APs / controller that will send authentication requests to this container, e.g. `192.168.0.1/24`.

You may additionally omit these if you don't use VLANs, but we strongly recommend using them to help segment your network traffic:

`FR_VLAN_VISITORS`: VLAN number to assign your eduroam visitors, i.e. external users roaming to your wireless network.

`FR_VLAN_OWNUSERS`: VLAN number to assign your own users when they connect to your wireless network (using eduroam as your organization's primary SSID is a best practice).

### Only set these if you want to use LDAP; setting these will disable the local sqlite DB, and omitting them will enable the local sqlite DB
`FR_LDAP_HOST_FQDN_1`: fully qualified hostname of your first LDAP server. Hostnames are generally better than IPs, to avoid LDAP server cert issues.

`FR_LDAP_HOST_FQDN_2`: fully qualified hostname of another LDAP server, for redundancy. If you only have one, just use the same value as `FR_LDAP_HOST_FQDN_1`.

`FR_LDAP_BASEDN`: the LDAP location under which all your eduroam users reside (e.g. `cn=Users,dc=example,dc=org` or `ou=staff,ou=school1,dc=example,dc=org`).

`FR_LDAP_BIND_USER`: the LDAP-formatted username (distinguished name, e.g. `cn=eduroam-ldap-bind,ou=special accounts,dc=example,dc=org`) of the service account that will connect to your LDAP servers and authenticate your eduroam users. The account must already exist. Do not use formatting like `EXAMPLE\eduroam-ldap-bind` or `eduroam-ldap-bind@example.org`.

`FR_LDAP_BIND_PASS`: the password for `FR_LDAP_BIND_USER`. We recommend choosing a very long (64+ characters) random password for this account, and configuring it to never expire (if possible). To avoid input formatting problems, consider limiting your use of special characters to "basic" ones like `.@!-^_*()[]`

#### LDAP security
LDAP certificates for LDAPS (636/tcp) or LDAP + StartTLS (389/tcp) ensure that the authentication attempts between FreeRADIUS and your auth backend are encrypted in transit and only sent to your own LDAP server(s), not a clever attacker watching traffic between the container and your auth backend.

Export the root and intermediate cert(s), but not the end entity cert, to PEM format (i.e. `-----BEGIN CERTIFICATE-----`) using your tool of choice, then use the command `base64 -w 0 /path/to/each/cert.pem` to base64 encode + remove line breaks so they can be pasted into the corresponding variables below.

`FR_LDAP_SECURITY`: set to `ldaps` to use LDAPS (636/tcp), or `starttls` to use LDAP + StartTLS (389/tcp). Both methods are secure, but if you're not sure which to use, try LDAPS and if it doesn't work try again with StartTLS. Unencrypted LDAP is not supported, by design.

See *Finding LDAP Certificates in your Active Directory environment* for help finding and retrieving these certificates from an AD domain controller.

`FR_LDAP_ROOT_CERT_BASE64`: the root CA certificate that issued your intermediate and/or LDAP server cert, i.e. the top of the cert chain.

`FR_LDAP_INTER_CERT_BASE64`: the intermediate CA certificate (if any) between the root CA certificate and the LDAP server cert. Omit or leave blank if you don't have an intermediate cert.

`FR_LDAP_GROUP`: (optional) set this to the distinguishedName (e.g. `cn=eduroam users,dc=example,dc=org`) of a group if you want to further restrict access by also requiring users to be in a particular group to connect via eduroam. If omitted, we assume any user inside `FR_LDAP_BASEDN` is allowed to connect.

### Logging
Anyone operating an eduroam IdP or SP is required to keep sufficient logs for troubleshooting. FreeRADIUS, particularly in debug mode, can be _very_ chatty, and this is a good thing. But you probably don't have infinite space for logs, so we provide two options that are less verbose than debug level console output, but still very useful for investigating and troubleshooting. We also include a `Correlation-ID` field in these log entries to help you grep for individual EAP conversations.

#### Remote syslog (recommended)
If you have a remote syslog host or SIEM tool, take advantage of its collection, searching, and compression capabilities.

`FR_LOG_SYSLOG_HOST`: the FQDN or IP of your syslog host.

`FR_LOG_SYSLOG_PORT`: the port number your syslog host is listening on.

`FR_LOG_SYSLOG_PROTO`: either `tcp` (recommended) or `udp`.

`FR_LOG_SYSLOG_FAC`: the syslog facility name FreeRADIUS logs should use. We recommend `local1` but this is arbitrary.

`FR_LOG_SYSLOG_SEV`: the syslog severity level FreeRADIUS logs should use. We recommend `notice` but this is arbitrary.

#### File based logging with persistent storage
If you don't specify the syslog details above, we assume you don't have a syslog receiver. In that case, the container will log to a file instead: `/var/log/freeradius/eduroam.log`. You should persistently map / bind this file to a volume using your container host's recommended method. It's up to you to rotate and trim the log with a tool of your choice from your container host; the container won't do it for you. Simply logging the container's console output is not sufficient.

# Finding LDAP Certificates in your Active Directory environment
Depending on your AD domain controller and/or AD Certificate Services configuration, retrieving the root and (if applicable) intermediate certificates used to sign your domain controllers' LDAP certificate may not be possible programatically.

The simplest way to retrieve an AD domain controller's root and intermediate certificates is to ask a Domain Admin to run `certlm.msc` on a domain controller and gather it for you via the Windows GUI. While it is technically possible to retrieve it via the openssl command, many DCs are not configured to serve their root and intermediate certificates along with the actual LDAP cert, so it's not a reliable method.

Browse to `Personal` -> `Certificates`. You should see a certificate issued to the domain controller in question. The `Certificate Template` column will likely say `Domain Controller` or similar - again, this depends on your environment. Double-click the certificate from the list to view its properties, then click the `Certification Path` tab. You should see more than one certificate in a simple tree view. The bottom-most certificate, typically having the same FQDN as the domain controller, is the end entity certificate, which is only cert that you do NOT need from this dialog.

## Extracting the root and intermediate CA certs
In the certificate properties window, work your way from the second-lowest to the highest certificate in the hierarchy: the highest certificate is the root CA certificate, and any between the root and the bottom certificate are intermediate CA certificates. It is acceptable not to have an intermediate certificate.

Double-click any intermediate certificates, causing a new certificate properties window to open. Click the `Details` tab -> `Copy to File...` button. A wizard should open, asking you how and where to save the file.  Choose `Base-64 encoded X.509` and save it somewhere as `intermediate.pem` (if you have multiple intermediates, name them accordingly). Once saved, close the wizard and the intermediate certificate's Properties window. Repeat the same process for the top-most certificate, saving it as `root.pem`. These files are safe to send over email, chat, etc., as they are public certificates. Now you can copy them to your container host and follow the steps in *LDAP Security* above.

### If you only see one certificate in the list...
If there is exactly one certificate in the list, the DC is likely using a self-signed certificate and you cannot securely communicate to it over LDAP. Ask your Domain Admin (or their consultant...) to configure AD to enable secure LDAP connections with a certificate issued by a private Certificate Authority (CA) such as AD Certificate Services.

# Under the hood
If you eat, live, and breathe containers, this is old hat for you. For the rest of us... well...

## Building and updating
We use the latest official Alpine-based FreeRADIUS container, add the sqlite and openssl packages, and copy our eduroam-US friendly config files over at container build time. We then apply actual configuration details during run time. Thus, you can destroy and rebuild the container every day and it will work the same way every time, as long as your config is the same (e.g. the set of environmental variables you feed your automation/orchestration tools). Security updates then take the form of pulling and rebuilding the container image, thereby starting from scratch with the latest patched Alpine + FreeRADIUS; destroying the currently-running container; and starting the new one.

This requires a change in thinking from operating a "traditional" VM. The author remembers when VMs were new and cool...

## Entrypoint script magic
At container startup, `entrypoint.sh` will do some helpful things for you. Perhaps most importantly, it will update the relevant FreeRADIUS conf files based on the environmental variables you made available to the container, and generate a brand new TLS certificate used by FreeRADIUS for EAP-TTLS.

### The "TLS" part of TTLS: server certificates
eduroam clients need to be able to verify that they're talking to a legitimate IdP when they authenticate. Since this container is designed to give your users an easy way to access eduroam using EAP-TTLS + PAP, we need a usable TLS certificate. Please note we are not addressing client certs for EAP-TLS, but rather the server cert for EAP-TTLS.

### TLS certificate trust is different in EAP/RADIUS vs. web servers
In a web client + server scenario, web clients generally have no idea about a given web server's identity until it needs to fetch a something from the server. Simplifying a bit: web browsers need to build a chain of trust from an HTTPS web server's cert to verify whether the server is who it claims to be, and not an imposter. That trust is founded upon pre-bundled well-known "public" CA certs trusted by the web browser. Enterprise wireless scenarios use a different approach: the client, configured in advance via a wireless profile, only needs to verify the identity of one particular server (i.e. this container). This means we don't need a fancy $100/yr. web TLS cert issued by a well-known public CA for your eduroam users to securely authenticate; we can use a "private" CA instead. The catch is that clients need to know about this private CA and the name of this container before connecting. We strongly recommend using [eduroam CAT](https://cat.eduroam.org) to generate and distribute a wireless profile for this purpose. You can then deliver the CAT-generated profile to your end-users via the excellent [geteduroam app](https://eduroam.org/geteduroam-get-connected-quickly-and-safely/) from their app store of choice, via your organization's mobile device management (MDM) platform if you have one, or even both methods.

[More information about EAP/RADIUS server certs and eduroam](https://wiki.geant.org/display/H2eduroam/EAP+Server+Certificate+considerations)

#### Our approach to automating TLS certificate management
Using TLS with containers is tricky. Containerized services generally rely on another container, the container's host, orchestration tools, ACME (in or outside the container), and/or a TLS reverse proxy to handle this. But we're not working with TLS + HTTPS, and we're trying to keep things lightweight.

We considered building a "cert watchdog" script that would run in the background to make TLS cert management completely transparent and friction-free. FreeRADIUS has to restart to load its certs, so we'd either have to terminate our own container and depend on the container host restarting it automatically; switch to a "heavier" container base image with a full `init` system; or write our own service management wrapper for FreeRADIUS... and none of these approaches seemed very "containery" or lightweight.

Of course, it'd be great if we could just pre-generate and package a self-signed root CA cert as part of this repo... but then anyone could clone this repo and get the same self-signed root and its private key, allowing them to impersonate YOUR container. Fortunately, we found a middle ground that works pretty well.

The operator of this container (e.g. an eSO) will generate a unique private CA cert using the provided `bootstrap-ca.sh` script once for each IdP/constituent. The resulting CA cert and its private key must be passed into the container's environment via an env var. At startup, the container will temporarily use the CA cert to issue a brand new server TLS cert, then "forget" its CA cert and key. The CA cert (but not the key, of course) can then be supplied to the eduroam CAT/geteduroam profile builder as the trust anchor for your wireless clients. The server TLS cert is essentially ephemeral and expires in `FR_TLS_MAXAGE` days, but no client reconfiguration is needed whenever a new server cert is generated, per the previous section. The catch is that each container must be restarted every so often (which is a normal and containery thing to do).

The CA cert generated by `bootstrap-ca.sh` and the server TLS certs are generated using 256 bit elliptic curve keys (ECDSA with prime256v1), roughly equivalent to 3072 bit RSA keys. This keeps cert and signature sizes small while sufficiently secure and fast, meaning fewer and smaller packets during TLS handshakes, EAP conversations, etc. We'd prefer to use ED25519, but certain mainstream wireless clients still don't support it.

## Handling the fully-self-contained use case
If no sqlite DB was found at `/db/freeradius.sqlite`, we'll pre-populate it using any SQL statements contained in `users-preload.sql`. Otherwise, we assume you're using persistent storage for `/db` and that the sqlite DB is already just the way you like it. We've provided scripts to generate a large number of randomized credentials that you can use for demo purposes or to create "tokens" to hand out as-needed.

We recommend persisting the sqlite DB so you can interact with it from inside or outside of the container, e.g. to revoke a user's eduroam access or add/change users via the sqlite3 command and INSERT/DELETE rows in the `radcheck` table. A future release may incorporate a light web interface to make this a more constituent-friendly option instead of leaving user adds/deletes to the eSO.
