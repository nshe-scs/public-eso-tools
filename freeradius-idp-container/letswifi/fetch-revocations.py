#!/usr/bin/python3
"""Pull one realm's revocation deny-list from the eso-letswifi portal and install it for FreeRADIUS.

Runs on each FreeRADIUS container host (not in the container), from a systemd timer:
one timer per eso-tools container (see letswifi-revocations-fetch@.service). The lists come
from an eso-letswifi portal's revocations/export-revocations.py, format version 2. With --container-dir, it reads the container's realm
(FR_IDP_REALM) and the portal's revocations URL (FR_LETSWIFI_REVOCATIONS_URL) from
<container-dir>/custom.env, downloads <url>/<realm>.sqlite over HTTPS (using the ETag, so an
unchanged file costs a 304 response), and installs it as
<container-dir>/vols/revocations/revoked.sqlite for the container to mount read-only
at /revocations. For other layouts, --realm, --dir and --base-url install <dir>/<realm>/revoked.sqlite.

A download is only installed if:
  * it is a complete, intact format-2 export for exactly this realm (size limit,
    integrity check, row count);
  * it is not older than the copy already installed (no replays or out-of-order files);
  * it does not drop revocations that are still in force. This host keeps its own
    baseline, so this also catches a portal restored from an old backup. After
    investigating, --allow-shrink accepts such a file once.

The new file replaces the old one by rename, so FreeRADIUS never sees a partial file.
The server's certificate is always verified, and redirects are never followed.

Exit codes: 0 installed or unchanged, 1 error, 2 refused, 3 installed copy is stale
(the portal has not produced a new export for longer than --max-age-minutes).
Compatible with the RHEL 9 system Python (3.9).
"""

import argparse
import datetime
import fcntl
import os
import re
import sqlite3
import ssl
import sys
import syslog
import tempfile
import urllib.error
import urllib.parse
import urllib.request

FORMAT_VERSION = "2"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
REQUIRED_COLUMNS = {"ident", "serial", "ca_sub", "revoked", "expires"}
REALM_PATTERN = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")
USER_AGENT = "letswifi-revocations-fetch/2"


class Refused(Exception):
    pass


class NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, "redirect to %s refused" % newurl, headers, fp)


def log(message, priority=syslog.LOG_INFO):
    print(message, file=sys.stderr, flush=True)
    syslog.syslog(priority, message)


def utc_now():
    return datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)


def open_ro(path):
    uri = "file:%s?mode=ro" % urllib.parse.quote(os.path.abspath(path))
    return sqlite3.connect(uri, uri=True, timeout=30)


def describe(path, realm):
    """Validate an export for this realm and return (meta dict, {ident: expires})."""
    db = open_ro(path)
    try:
        if db.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise RuntimeError("integrity check failed")
        meta = dict(db.execute("SELECT key, value FROM meta"))
        if meta.get("format_version") != FORMAT_VERSION:
            raise RuntimeError("not a format-%s export" % FORMAT_VERSION)
        if meta.get("realm") != realm:
            raise RuntimeError("export is for realm %r, not %r" % (meta.get("realm"), realm))
        columns = {row[1] for row in db.execute("PRAGMA table_info(revoked)")}
        if not REQUIRED_COLUMNS <= columns:
            raise RuntimeError("revoked table is missing columns")
        datetime.datetime.strptime(meta["generated_at"], DATE_FORMAT)
        int(meta["export_id"])
        entries = dict(db.execute("SELECT ident, expires FROM revoked"))
        if len(entries) != int(meta["revoked_count"]):
            raise RuntimeError("row count does not match meta.revoked_count")
        return meta, entries
    except (KeyError, ValueError) as error:
        raise RuntimeError("malformed export: %s" % error)
    except sqlite3.DatabaseError as error:
        raise RuntimeError("not a valid export: %s" % error)
    finally:
        db.close()


def download(url, etag, dest, max_bytes, timeout, ca_file):
    """GET url into dest. Returns the new ETag, or None if the server says 304 Not Modified."""
    context = ssl.create_default_context(cafile=ca_file)
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=context), NoRedirects)
    headers = {"User-Agent": USER_AGENT}
    if etag:
        headers["If-None-Match"] = etag
    try:
        response = opener.open(urllib.request.Request(url, headers=headers), timeout=timeout)
    except urllib.error.HTTPError as error:
        if error.code == 304:
            return None
        raise RuntimeError("%s: HTTP %d %s" % (url, error.code, error.reason))
    except urllib.error.URLError as error:
        raise RuntimeError("%s: %s" % (url, error.reason))
    with response, open(dest, "wb") as out:
        size = 0
        while True:
            chunk = response.read(65536)
            if not chunk:
                break
            size += len(chunk)
            if size > max_bytes:
                raise RuntimeError("download exceeds %d bytes" % max_bytes)
            out.write(chunk)
        out.flush()
        os.fsync(out.fileno())
    if size == 0:
        raise RuntimeError("empty response")
    return response.headers.get("ETag", "")


def check_acceptable(new_meta, new_entries, current_meta, current_entries, allow_shrink):
    if current_meta is None:
        return "no copy installed yet"
    if int(new_meta["export_id"]) < int(current_meta["export_id"]):
        raise Refused("export generated %s is older than the installed one (%s)"
                      % (new_meta["generated_at"], current_meta["generated_at"]))
    cutoff = (utc_now() - datetime.timedelta(days=int(new_meta.get("grace_days", "30")))).strftime(DATE_FORMAT)
    vanished = sorted(ident for ident, expires in current_entries.items()
                      if ident not in new_entries and expires >= cutoff)
    if vanished and not allow_shrink:
        raise Refused("%d installed revocation(s) are missing from the new export but not expired (e.g. %s); "
                      "if the portal database was deliberately restored, rerun once with --allow-shrink"
                      % (len(vanished), ", ".join(vanished[:5])))
    if vanished:
        return "--allow-shrink: dropped %d unexpired revocation(s)" % len(vanished)
    return "ok"


def read_custom_env(container_dir, keys):
    """The given keys from an eso-tools container's custom.env (the last assignment wins, as with env files)."""
    path = os.path.join(container_dir, "custom.env")
    values = {}
    try:
        with open(path) as handle:
            for line in handle:
                key, sep, value = line.strip().partition("=")
                if sep and key in keys:
                    value = value.strip()
                    if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
                        value = value[1:-1]
                    values[key] = value
    except OSError as error:
        raise RuntimeError("can't read %s: %s" % (path, error.strerror))
    for key in keys:
        if not values.get(key):
            raise RuntimeError("%s doesn't set %s" % (path, key))
    return values


def write_atomic_text(path, text):
    fd, tmp = tempfile.mkstemp(prefix=".etag-", dir=os.path.dirname(path))
    with os.fdopen(fd, "w") as out:
        out.write(text)
    os.replace(tmp, path)


def update(args, realm_dir):
    target = os.path.join(realm_dir, "revoked.sqlite")
    etag_path = os.path.join(realm_dir, ".etag")
    current_meta = current_entries = None
    unreadable = False
    if os.path.exists(target):
        try:
            current_meta, current_entries = describe(target, args.realm)
        except RuntimeError as error:
            log("installed copy is unreadable (%s); it will be replaced" % error, syslog.LOG_WARNING)
            unreadable = True

    etag = None
    if current_meta is not None and os.path.exists(etag_path) and not args.from_file:
        with open(etag_path) as handle:
            etag = handle.read().strip() or None

    fd, tmp_path = tempfile.mkstemp(prefix=".fetch-", suffix=".tmp", dir=realm_dir)
    os.close(fd)
    try:
        if args.from_file:
            with open(args.from_file, "rb") as src, open(tmp_path, "wb") as out:
                out.write(src.read(args.max_bytes + 1))
            if os.path.getsize(tmp_path) > args.max_bytes:
                raise RuntimeError("input exceeds %d bytes" % args.max_bytes)
            new_etag = ""
        else:
            url = "%s/%s.sqlite" % (args.base_url.rstrip("/"), args.realm)
            new_etag = download(url, etag, tmp_path, args.max_bytes, args.timeout, args.ca_file)
            if new_etag is None:
                return current_meta, "not modified"

        new_meta, new_entries = describe(tmp_path, args.realm)
        if current_meta is not None and new_meta["export_id"] == current_meta["export_id"]:
            result = "export %s already installed" % new_meta["generated_at"]
        else:
            verdict = check_acceptable(new_meta, new_entries, current_meta, current_entries, args.allow_shrink)
            if unreadable:
                verdict = "replaced an unreadable copy"
            os.chmod(tmp_path, 0o644)
            os.replace(tmp_path, target)
            dir_fd = os.open(realm_dir, os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
            current_meta = new_meta
            result = "installed export %s with %s revocation(s) (%s)" % (
                new_meta["generated_at"], new_meta["revoked_count"], verdict)
        if new_etag:
            write_atomic_text(etag_path, new_etag)
        elif args.from_file and os.path.exists(etag_path):
            os.unlink(etag_path)  # the saved ETag no longer describes the installed copy
        return current_meta, result
    finally:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--container-dir", help="an eso-tools container's directory (where its custom.env is), e.g. "
                             "/opt/constituent-a/public-eso-tools/freeradius-idp-container; "
                                                "the realm comes from its custom.env, the list goes in its vols/revocations")
    parser.add_argument("--realm", help="the realm to fetch (without --container-dir)")
    parser.add_argument("--base-url", help="e.g. https://lets.example.edu/revocations "
                                           "(default with --container-dir: its FR_LETSWIFI_REVOCATIONS_URL)")
    parser.add_argument("--from-file", help="install a local export instead of downloading")
    parser.add_argument("--dir", help="with --realm: installs <dir>/<realm>/revoked.sqlite")
    parser.add_argument("--allow-shrink", action="store_true",
                        help="accept an export that drops unexpired revocations (after investigating!)")
    parser.add_argument("--max-age-minutes", type=int, default=30,
                        help="exit 3 if the installed export is older than this (default 30)")
    parser.add_argument("--max-bytes", type=int, default=64 * 1024 * 1024)
    parser.add_argument("--timeout", type=int, default=30, help="HTTP timeout in seconds")
    parser.add_argument("--ca-file", help="CA bundle to verify the portal (default: system trust store)")
    args = parser.parse_args()
    syslog.openlog("letswifi-revocations-fetch")

    if args.base_url and args.from_file:
        parser.error("--base-url and --from-file can't be combined")
    if args.container_dir:
        if args.realm or args.dir:
            parser.error("--container-dir can't be combined with --realm or --dir")
        if not os.path.isdir(os.path.join(args.container_dir, "vols", "revocations")):
            log("error: %s has no vols/revocations directory. Create it first: mkdir -p %s"
                % (args.container_dir, os.path.join(args.container_dir, "vols", "revocations")), syslog.LOG_ERR)
            return 1
        needed = ["FR_IDP_REALM"] if (args.base_url or args.from_file) else ["FR_IDP_REALM", "FR_LETSWIFI_REVOCATIONS_URL"]
        try:
            env = read_custom_env(args.container_dir, needed)
        except RuntimeError as error:
            log("error: %s" % error, syslog.LOG_ERR)
            return 1
        args.realm = env["FR_IDP_REALM"]
        args.base_url = args.base_url or env.get("FR_LETSWIFI_REVOCATIONS_URL")
        realm_dir = os.path.join(args.container_dir, "vols", "revocations")
    elif args.realm and args.dir:
        if not os.path.isdir(args.dir):
            log("error: %s does not exist" % args.dir, syslog.LOG_ERR)
            return 1
        realm_dir = os.path.join(args.dir, args.realm)
    else:
        parser.error("give --container-dir, or both --realm and --dir")
    if not args.base_url and not args.from_file:
        parser.error("give --base-url or --from-file")
    if args.base_url and not args.base_url.startswith("https://"):
        log("error: the revocations URL must start with https:// (got %r)" % args.base_url, syslog.LOG_ERR)
        return 1
    if not REALM_PATTERN.match(args.realm):
        log("error: %r isn't a valid realm name" % args.realm, syslog.LOG_ERR)
        return 1
    os.makedirs(realm_dir, mode=0o755, exist_ok=True)

    lock = open(os.path.join(realm_dir, ".fetch.lock"), "w")
    fcntl.flock(lock, fcntl.LOCK_EX)
    status = 0
    current_meta = None
    try:
        current_meta, result = update(args, realm_dir)
        log("%s: %s" % (args.realm, result))
    except Refused as refusal:
        log("%s: REFUSED: %s; installed copy kept" % (args.realm, refusal), syslog.LOG_ERR)
        status = 2
    except (RuntimeError, sqlite3.Error, OSError) as error:
        log("%s: error: %s; installed copy kept" % (args.realm, error), syslog.LOG_ERR)
        status = 1
    finally:
        lock.close()

    # Staleness alarm: the portal rewrites every export at least every 10 minutes
    if current_meta is None:
        try:
            current_meta, _ = describe(os.path.join(realm_dir, "revoked.sqlite"), args.realm)
        except (RuntimeError, sqlite3.Error, OSError):
            return status or 1
    age = utc_now() - datetime.datetime.strptime(current_meta["generated_at"], DATE_FORMAT)
    if age > datetime.timedelta(minutes=args.max_age_minutes):
        log("%s: STALE: installed export was generated %s UTC (%d minutes ago)"
            % (args.realm, current_meta["generated_at"], age.total_seconds() // 60), syslog.LOG_ERR)
        return status or 3
    return status


if __name__ == "__main__":
    sys.exit(main())
