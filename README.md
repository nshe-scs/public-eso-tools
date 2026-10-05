# eSO-hostable rapid-deployment containerized FreeRADIUS solution for K-12s, libraries, museums, etc.
Containerized eduroam IdP + SP solution using FreeRADIUS, pre-configured and tailored for K-12, library, and museum deployments in the US.

Free, rapidly-deployable and repeatable, reasonably secure by default, and pre-configured to work with the eduroam-US infrastructure with minimal maintenance effort for whoever hosts it, whether a school, small college, or an eduroam Support Organization on behalf of its constituents.

# Table of Contents
  - [Why?](#why)
  - [Setup](#setup)
    - [eduroam registration](#eduroam-registration)
    - [Container hosting and naming](#container-hosting-and-naming)
    - [Bootstrap CA script](#bootstrap-ca-script)
    - [Wireless profile](#wireless-profile)
    - [Identity source options](#identity-source-options)
  - [Building and running the container](#building-and-running-the-container)
    - [Environmental variables](#environmental-variables)
  - [Logging options](#logging-options)
  - [About LDAP certificates](#about-ldap-certificates)
    - [Google](#google)
    - [Active Directory Domain Controllers](#active-directory-domain-controllers)
  - [Updating](#updating)
  - [Further reading](#further-reading)

# Why?
There are numerous examples of valid eduroam configs in the wild. Many are so generalized and flexible that it can be daunting for a new eduroam IdP deployer to sort out international vs. US-specific items, considerations around EAP types, integrating with their identity source, log options, and so forth. As an eduroam Support Organization (eSO), we had the following goals:
- Give eSOs a quickly deployable and scalable option to host eduroam IdPs on behalf of their smaller constituents who lack a central identity source, have a very small IT department, or have a relatively small set of users. In many cases, a central identity source exists but the IT team (which may be a volunteer) lacks the expertise, time, or willingness to set up NPS or a Linux VM to work with eduroam.
- Give constituents (i.e. schools, libraries, museums) a simple cookie-cutter eduroam IdP they can host themselves on old hardware, a prosumer-grade NAS that supports Docker, at a consultant's cloud provider, etc. in a way that can be quickly configured to talk to Active Directory (on-prem, hybrid, or managed AD), Google Workspace, or similar, over a secure LDAP connection. A bundled sqlite DB with randomizable credentials is included as an "identity source of last resort", e.g. for demos, temporary events, schools without an enterprise identity system, or micro schools.
- Use secure configurations by default: we use EAP-TTLS + PAP, which takes a bit of work to do properly, but is quite reasonably secure - so we've focused on making it hard to misconfigure.
- Contribute our work back to the broader education community. While we're focused on spurring eduroam adoption in our neck of the woods, this is still broadly applicable (just not necessarily fine-tuned) to larger education-affiliated organizations and other countries.

# Setup
## eduroam registration
We assume you're a US-based [eduroam Support Organization (eSO)](https://incommon.org/eduroam/eduroam-k12-libraries-museums/), but you can also host this directly as a school, school district, multi-district IT services unit, EDU-focused contractor, a community college... In any case, you must be able to register an IdP and/or SP in the eduroam infrastructure (you can test locally, but roaming won't work unless you're registered). US-based organizations do this via Internet2's Federation Manager tool; if you don't know what that is, reach out to Internet2 or your state's eSO.

## Container hosting and naming
You'll need to be able to host a container. Podman and Docker are common, well documented, and relatively easy to install on a Linux VM or a tiny PC. You'll need to be able to reboot the container on a schedule or be in the habit of redeploying so you get the latest security updates from the upstream FreeRADIUS container (see [Updating](#updating) below).

If you're an eSO, we suggest following a repeatable pattern like `(constituent).roam.(your-eso-domain)`, e.g. `a.roam.example.org`, `b.roam.example.org`, `c.roam.example.org`, etc. when selecting a value for `FR_IDP_FQDN`. This is the name the container will use for its TLS certificate and must be specified in wireless profiles so clients can know whether they're talking to the correct server. You may want to use the same value for `FR_IDP_REALM`, which is the realm (domain name) registered in the eduroam infrastructure so roaming authentication requests can be routed to the container. For example, if `FR_IDP_REALM` is `a.roam.example.org`, users would authenticate as `foo@a.roam.example.org`. This should also make orchestration easier if you want to build a repeatable workflow for many constituents.

If you are hosting this as an individual district or school, we recommend something more familiar to your users, like your school's email suffix.

If a constituent has discrete identity sources for students vs. faculty/staff/teachers, e.g. two different Google Workspace tenants, different AD domains, etc., we recommend running two containers (e.g. `students.a.roam.example.org` and `staff.a.roam.example.org`.

## Bootstrap CA script
You'll need to run the provided `bootstrap-ca.sh` bash script on a Linux system, and hang on to its output before you can start your container for the first time. This only needs to be done once per constituent, and the resulting CA certificate is valid for 20 years. The container will use this cert to generate its own short-lived certs whenever it starts, and because clients will be told to trust the private cert only for eduroam, you won't need to worry about ever-shortening public cert lifetimes.

## Wireless profile
We strongly recommend using [eduroam CAT](https://cat.eduroam.org) to generate and distribute a wireless profile. You can then allow self-service/BYOD installation of the CAT-generated profile using the excellent [geteduroam app](https://eduroam.org/geteduroam-get-connected-quickly-and-safely/) via the major app stores, push the profile yourself via your organization's mobile device management (MDM) platform if you have one, or even use both approaches.

Work with your NRO (e.g. Internet2 in the US) to register for CAT admin access if you do not already have it for the IdP realm(s) you are supporting with this container. Do NOT encourage users to manually connect and blindly fill in values, accept mystery certificates while traveling, ignore server cert warnings, etc.

## Identity source options

### Randomized tokens (local sqlite DB, manual tracking of who gets which identities)
This option is probably best suited for demo / temporary event scenarios, small schools, libraries, or museums lacking a central identity source.

The bundled sqlite user DB can host identities for a constituent that doesn't have a central identity source. We've supplied a PowerShell / pwsh 7.x script (run `New-HostedEduroamTokens.ps1 -Realm a.roam.example.org -TokenCount number`) and an AI-generated (but human curated) bash version (`new_hosted_eduroam_tokens.sh a.roam.example.org number`) to generate as many random credentials as you need, and dump the output into `users-preload.sql` before building the container.

In either case, you could also copy and paste the output to a spreadsheet or other document as a paper roster. Note the recipient, date/time issued, and contact info for whomever you assign each username + password. If you choose to do this, you must not lose or widely distribute the document or you will have no idea who your users are - and that's a Bad Thing(tm) worthy of starting over from scratch with a new set of randomized identities. It also puts you at risk of violating the eduroam Terms of Service, etc. We're considering bundling a simple web UI to reduce the administrative burden for this scenario.

### Bring your own secure LDAP (e.g. Active Directory)
If you already have an LDAP-compatible identity source, you'll need credentials to let FreeRADIUS talk to it over LDAPS (port 636) or LDAP + StartTLS (port 389). You'll also need to know the base DN / OU where the user accounts you'll permit to connect to eduroam reside, and optionally a group of users to allow-list, i.e. the typical LDAP details. Lastly, you'll need the LDAP server's root CA and, if it uses one, its intermediate cert, so authentication between this container and the LDAP backend can be secured. You do not need the "server" or "end entity" cert used by the LDAP server; the idea is to trust the issuer of the cert and the LDAP server(s) hostname.

If you're using Active Directory but not protecting LDAP communication with a certificate of some sort, this container won't have a secure way to talk to your DCs... that's a Bad Thing(tm) and we intentionally don't provide a way to override cert checking.

### Google Secure LDAP
Google does LDAPS a little differently than AD and has a query rate limit, so we treat it differently. If your Google Workspace tenant does not already have the Secure LDAP service enabled, you will need to enable it from the tenant's admin portal. You'll need to create an "LDAP client", which is really a client cert + key for the container to authenticate to Google over LDAPS, and "access credentials", which are an auto-generated username and passphrase used in conjunction with the client cert + key. You'll also need to allow the LDAP client to read basic user information from your tenant, and note the OU and (optional) group your eduroam users reside in.

### Let's Wi-Fi (EAP-TLS client certificates from an eso-letswifi portal)
Users enroll each device at an [eso-letswifi](https://github.com/nshe-scs/public-eso-letswifi) portal, which signs them in through their institution's own SSO and installs a personal client certificate. Devices then authenticate with EAP-TLS instead of a username and password, so there's no password to phish or forget, and no identity backend for this container to talk to.

To deploy the portal and switch your IdPs to it, see the [Let's Wi-Fi production guide](https://github.com/nshe-scs/public-eso-letswifi/blob/HEAD/docs/production-guide.md).

To get the value for `FR_LETSWIFI_CA_CERT_BASE64`, run `realm-ca-cert.py <FR_IDP_REALM>` on the eso-letswifi portal host and paste the line it prints. In the portal, the institution's realm must use this container's `FR_IDP_REALM`, its `--server-name` must be this container's `FR_IDP_FQDN`, and its `--trust` must be the CA in `FR_TLS_CA_CERT_BASE64`.

Certs revoked in the portal must stop working here too. The container host (not the container) pulls the realm's revocation list from the portal into `./vols/revocations` every minute with `letswifi/fetch-revocations.py`, using `FR_IDP_REALM` and `FR_LETSWIFI_REVOCATIONS_URL` from this container's `custom.env`. New revocations take effect within a couple of minutes. If no list is mounted, the container still starts but warns that revoked certs will be accepted, and a missing or unreadable list never blocks logins. The portal side is described in eso-letswifi's `revocations/README.md`; it must allow this host's IP address in `LETSWIFI_REVOCATION_CLIENTS`.

To set it up, install the systemd units once per host, then start a timer for each container. The timer's name encodes the container's directory, so let `systemd-escape` build it:
```
# Once per host, from any copy of this repo
cp freeradius-idp-container/letswifi/letswifi-revocations-fetch@.* /etc/systemd/system/
systemctl daemon-reload

# For each container, from its directory (where its docker-compose.yml and custom.env are)
vim custom.env # set FR_LETSWIFI_REVOCATIONS_URL
mkdir -p vols/revocations
timer=$(systemd-escape --path --template letswifi-revocations-fetch@.timer "$PWD")
systemctl enable --now "$timer"
journalctl -u "${timer%.timer}.service" -n 5 # expect "installed export ..."; later runs say "not modified"
vim docker-compose.yml # uncomment volumes: and the ./vols/revocations line
docker compose down && docker compose up -d # startup log shows "Revocation list for '<realm>': ..."
```
Each timer runs the `fetch-revocations.py` in its own container's directory, so updating that container's copy of this repo updates its fetcher too. `systemctl list-timers 'letswifi-revocations-fetch@*'` lists every timer on the host.

After changing a realm's root CA in the portal, run `realm-ca-cert.py` again: it includes both CAs until certs signed by the old one have expired or been revoked.

# Building and running the container
Build and run it as you typically would with the supplied `Dockerfile`, and a `docker-compose.yml` and `custom.env` that you'll modify based on the supplied `docker-compose.yml.example` and `custom.env.example`. We tested with `docker compose` for convenience, but you could use other methods.

For example:
```
# First time setup
mkdir /opt/constituent-a
cd /opt/constituent-a
git clone https://github.com/nshe-scs/public-eso-tools
cd public-eso-tools/freeradius-idp-container
./bootstrap-ca.sh # store the output in a safe place, e.g. your organization's secrets vault / password manager

# Configure the container
cp docker-compose.yml.example docker-compose.yml
vim docker-compose.yml # set the desired container name, IP/port mapping, etc.
cp custom.env.example custom.env
vim custom.env # set your env vars to configure everything, e.g. identity source, eduroam registration settings, logging (see next section)

# Build and start the container
docker compose up --build -d
docker compose logs -f # make sure the container started correctly and is waiting for requests
```

## Environmental variables
The container configuration is completely driven by environmental variables. Do not edit the various FreeRADIUS conf files from this project; the container's entrypoint script will handle everything during container startup. We recommend setting the environment via the supplied `custom.env` file, which was written to be self-documenting - just dive in and fill in the blanks in the file.

# Logging options
Anyone operating an eduroam IdP or SP is required to keep sufficient logs for troubleshooting and incident response. Logging the container's console output to a file is not sufficient, and while FreeRADIUS in debug mode is quite verbose (this is a good thing), you shouldn't run in debug mode once you're done testing, and you probably don't have infinite space for logs.

We provide two options that are less verbose than the debug level console output, but are still useful for investigating and troubleshooting, and we include a `Correlation-Id` field in the log entries to help you grep and follow individual EAP sessions.

If you have a remote syslog host or SIEM tool, use it. Take advantage of its collection, searching, and compression capabilities. If you don't have a syslog receiver of some sort, the container can log to a file instead (`/var/log/freeradius/eduroam.log`) but you must persistently map / bind `/var/log/freeradius` to a volume on your container host or the log will disappear when the container stops. It's up to you to rotate and trim the log; the container won't do it for you.

Keep logs for at least eduroam's minimum retention period (six months for eduroam-US). For example, in `/etc/logrotate.d/eso-tools` on the container host (list each container's log, or use a wildcard):
```
/path/to/public-eso-tools/freeradius-idp-container/vols/log/eduroam.log {
    daily
    rotate 190
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
}
```
`copytruncate` keeps FreeRADIUS writing to the same file; `rotate 190` keeps just over six months. Test it with `logrotate -f /etc/logrotate.d/eso-tools`; on SELinux hosts, the volume's label may block logrotate.

# About LDAP certificates
Strict LDAP certificate checking ensures that the authentication traffic between the container and the constituent's auth backend are encrypted in transit and only sent to the constituent's own LDAP server(s), not a clever adversary.

## Google
In the case of Google, the LDAPS connection is protected by the client certificate provided by Google (see *Google Secure LDAP* above).

## Active Directory Domain Controllers
In an AD environment, it can be difficult to find the root and intermediate certificates that signed a domain controller's LDAPS certificate. Depending on the DC and/or AD Certificate Services configuration, retrieving the root and (if applicable) intermediate certificates used to sign the DCs' LDAP certificates may not be feasible programmatically, so here's a short guide to retrieving it via the GUI.

The simplest way to retrieve the root and intermediate certificates is to ask a Domain Admin to run `certlm.msc` on a domain controller and have them retrieve it for you. While it is technically possible to retrieve via the openssl command, many DCs are not configured to serve their root and intermediate certificates along with the actual LDAP cert, so it's not a reliable method.

Inside the `certlm.msc` MMC snap-in, go to `Personal` -> `Certificates`. You should see a certificate issued to the domain controller in question. The `Certificate Template` column will likely say `Domain Controller` or similar - exact phrasing depends on the environment. Double-click the certificate from the list to view its properties, then click the `Certification Path` tab. You should see more than one certificate in a simple tree view. The bottom-most certificate, typically having the same FQDN as the domain controller, is the server or "end entity" certificate, which is only cert that you do NOT need.

In the certificate properties window, work your way from the second-lowest to the highest certificate in the hierarchy: the lower certs are intermediates, and the highest is the root CA cert. It is possible that there is no intermediate cert.

Double-click any intermediate certs, causing a new certificate properties window to open. Click the `Details` tab -> `Copy to File...` button. A wizard should open, asking you how and where to save the file.  Choose `Base-64 encoded X.509` and save it somewhere as `intermediate.pem` (if you have multiple intermediates, name them accordingly). Once saved, close the wizard and the intermediate cert's Properties window. Repeat this process for the root cert, saving it as `root.pem`. These files are safe to send over email, chat, etc., as they are public certificates, not private keys. Copy them to the container host and base64-encode them per the details in the example `custom.env`.

### If you only see one certificate...
If there is exactly one certificate, the DC is likely using an individual self-signed certificate and you cannot securely communicate to it with this container. Ask a Domain Admin (or their consultant...) to configure AD to enable secure LDAP connections with a certificate issued by a private Certificate Authority (CA) such as AD Certificate Services. There is no need to pay a public CA for certs for your DCs and it will likely introduce exciting new problems down the road.

# Updating
We use the latest official Alpine-based FreeRADIUS container, add the sqlite and openssl packages, and copy our eduroam-US friendly config files over at container build time. We then apply actual configuration details during run time. Thus, you can destroy and rebuild the container every day and it will work the same way every time, as long as your config is the same (e.g. the set of environmental variables you feed your automation/orchestration tools).

To only update the base container image and FreeRADIUS, e.g. if you just want to keep your containers patched and aren't interested in bug fixes or new features from this project: simply pull and rebuild the container image, stop the container, and start a new one (see "Rebuild and restart the container" in the example below).

To update everything, including grabbing the latest release of this project (rarely necessary - please check the release notes before updating), pull the latest code and rebuild. Your `custom.env`, `docker-compose.yml` and `vols/` aren't tracked by git, so a pull leaves them alone, but it never hurts to take a backup! Upgrading from v1.x? Follow the upgrade steps in the v2.0.0 release notes instead: v2 renamed the container directory.

Example (e.g. "Constituent A"):
```
# Back up config + any persistent volumes just in case something goes awry
cd /opt/constituent-a
tar cjf constituent-a.bak.tar.bz2 -C public-eso-tools/freeradius-idp-container custom.env docker-compose.yml vols/

# Get the latest project code
git -C public-eso-tools pull

# Rebuild and restart the container
cd /opt/constituent-a/public-eso-tools/freeradius-idp-container
docker compose build --pull # pull the latest base image and incorporate this project's customizations
docker compose down # stop the running container
docker compose up -d # start the container and detach it from the console so you can keep working
docker compose logs -f # view the container's output to make sure it started correctly and is waiting for requests
```

To automate your updates, schedule them with cron, systemd, or a fancy orchestration tool of your choice.

# Further reading

## Private CA certs and our approach to automating (T)TLS
The operator of this container (e.g. an eSO) generates a unique private CA cert and key using the provided `bootstrap-ca.sh` script once per IdP/constituent and feeds it to the container via env vars. At startup, the container issues itself a brand new cert for EAP-TTLS (not to be confused with EAP-TLS) using the private CA cert and key, then removes the key from its environment. The private CA cert (not the key, of course) can then be supplied to eduroam CAT or another wireless profile builder as the trust anchor for your wireless clients. No client reconfiguration is needed unless you change the private CA cert or rename the container.

It is NOT a Bad Thing(tm) to use a private CA cert with eduroam. See the *Wireless profile* section above and [information about EAP/RADIUS server certs and eduroam](https://wiki.geant.org/display/H2eduroam/EAP+Server+Certificate+considerations) for more information, or read on...

Enterprise wireless clients are not web browsers. Wireless clients need to verify that they are talking to a legitimate server, but there is an expectation that someone in the "enterprise", not a third-party like a "public" CA, determines which servers are trustworthy. So clients are configured in advance via a wireless profile indicating the trustworthy server name(s) and expected CA cert, and will assume others are untrustworthy. The catch is that clients need the server name and the CA cert in advance. End-users delegate the question of trustworthiness to someone else in the organization/enterprise.

Contrast this with web servers. Clients generally have no idea about a given server's identity until it's time to fetch something from the server. Web browsers essentially need to build a chain of trust to verify that the server is who it claims to be, without ever having met the server before. That trust is based on "public" CA certs bundled with and trusted by the web browser. The end-user typically knows nothing about these CA certs or the organizations/people responsible for them. Trust is abstracted a little further away from the end-user, with the question of a server's trustworthiness left to someone outside their organization/enterprise, namely those responsible for the web browsers and CA certs.

## Automating TLS cert management
Using TLS with containers can be tricky, relying on another container, the container host, orchestration tools, ACME in or outside the container, and/or a reverse proxy to handle encrypting and decrypting traffic. But since we're not working with HTTPS and can also use a private CA cert, we use a lightweight self-contained solution: issue ourselves a cert every time we start.

FreeRADIUS 3.2.x needs a restart to reload TLS certs, so we terminate the container after a configurable number of days, and depend on the container host to restart the container automatically. We chose not to use a "heavier" container base image with a full `init` system, or to write a custom service management wrapper because these approaches don't seem very "containery" or lightweight. The catch is that your containers must be restarted every so often, which is a normal and containery thing to do. If you host containers for multiple constituents and don't have fancy orchestration tools, you can stagger the terminations by setting different ages in `custom.env`.

Of course, it'd be great if we could just pre-generate and package a root CA cert as part of this repo... but then anyone using this repo would have the same root and private key, allowing them to impersonate YOUR container. Fortunately, we found a middle ground that works pretty well.

## Keeping TLS certs small(ish)
The private CA cert and the server TLS certs are generated using 256 bit elliptic curve keys (ECDSA with prime256v1), roughly equivalent to 3072 bit RSA keys. This keeps cert and signature sizes small while sufficiently secure and fast, meaning fewer and smaller packets during TLS handshakes, EAP conversations, etc. We'd prefer ED25519, but certain mainstream wireless clients still don't support it. If you read this far, you may be interested in asking your favorite search engine for a performance and traffic comparison.
