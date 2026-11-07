#!/usr/bin/env python3
"""certwatch - check TLS certificate expiry for hosts you operate.

Opens a normal TLS connection (with verification) and reads the certificate's
expiry date. Intended for monitoring your own servers.
Standard library only. Exit code 0 = all OK, 1 = warning/critical/error, 2 = usage.
"""
import argparse
import concurrent.futures
import datetime
import json
import socket
import ssl
import sys

__version__ = "1.1.0"


def parse_target(text, default_port=443):
    """'host', 'host:port' or '[v6]:port' -> (host, port)."""
    text = text.strip()
    if text.startswith("["):
        host, _, rest = text[1:].partition("]")
        return host, int(rest[1:]) if rest.startswith(":") else default_port
    if text.count(":") == 1:
        host, port = text.split(":")
        return host, int(port)
    return text, default_port


def days_left(not_after, now=None):
    """not_after: cert 'notAfter' string, e.g. 'Jun  1 12:00:00 2030 GMT'."""
    expires = ssl.cert_time_to_seconds(not_after)
    now = now if now is not None else datetime.datetime.now(datetime.timezone.utc).timestamp()
    return (expires - now) / 86400.0


def classify(days, warn=30, crit=7):
    if days < 0:
        return "EXPIRED"
    if days < crit:
        return "CRITICAL"
    if days < warn:
        return "WARNING"
    return "OK"


def fetch_not_after(host, port, timeout=10):
    ctx = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as tls:
            return tls.getpeercert()["notAfter"]


def fetch_cert(host, port, timeout=10):
    """Return the peer certificate dict (verified TLS connection)."""
    ctx = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as tls:
            return tls.getpeercert()


def _name(rdns):
    """Readable name from the getpeercert() subject/issuer structure."""
    flat = {k: v for rdn in rdns or () for k, v in rdn}
    return flat.get("commonName") or flat.get("organizationName") or ""


def inspect(target, warn=30, crit=7, fetch=fetch_cert, now=None, timeout=10):
    """Full result dict for one target. Never raises on network or certificate errors."""
    res = {"target": target, "status": "ERROR", "days_left": None, "not_after": None,
           "subject": None, "issuer": None, "san": [], "detail": ""}
    try:
        host, port = parse_target(target)
        try:
            cert = fetch(host, port, timeout)
        except TypeError:  # injected fetchers that take only (host, port)
            cert = fetch(host, port)
        days = days_left(cert["notAfter"], now)
    except ssl.SSLCertVerificationError as exc:
        res.update(status="INVALID", detail="certificate verification failed: %s" % exc.verify_message)
        return res
    except (OSError, ValueError, KeyError, TypeError) as exc:
        res["detail"] = str(exc)
        return res
    res.update(status=classify(days, warn, crit), days_left=round(days, 2), not_after=cert["notAfter"],
               subject=_name(cert.get("subject")), issuer=_name(cert.get("issuer")),
               san=[v for k, v in cert.get("subjectAltName", ()) if k == "DNS"],
               detail="%.1f day(s) left" % days)
    return res


def check(target, warn=30, crit=7, fetch=fetch_not_after, now=None):
    """Return (status, detail) for one target. Never raises on network errors."""
    try:
        host, port = parse_target(target)
        days = days_left(fetch(host, port), now)
    except ssl.SSLCertVerificationError as exc:
        return "INVALID", "certificate verification failed: %s" % exc.verify_message
    except (OSError, ValueError, KeyError) as exc:
        return "ERROR", str(exc)
    return classify(days, warn, crit), "%.1f day(s) left" % days


def main(argv=None, _fetch=fetch_cert):
    ap = argparse.ArgumentParser(description="Check TLS certificate expiry.")
    ap.add_argument("targets", nargs="*", help="host or host:port")
    ap.add_argument("-f", "--file", help="file with one target per line (# comments ok)")
    ap.add_argument("--warn", type=int, default=30, help="warning threshold in days")
    ap.add_argument("--crit", type=int, default=7, help="critical threshold in days")
    ap.add_argument("--timeout", type=float, default=10, help="connect/handshake timeout in seconds")
    ap.add_argument("--workers", type=int, default=8, help="hosts to check in parallel (default 8)")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--version", action="version", version=__version__)
    args = ap.parse_args(argv)

    targets = list(args.targets)
    if args.file:
        try:
            with open(args.file) as fh:
                targets += [l.split("#")[0].strip() for l in fh if l.split("#")[0].strip()]
        except OSError as exc:
            print("certwatch: %s" % exc, file=sys.stderr)
            return 2
    if not targets:
        ap.print_usage(sys.stderr)
        return 2

    if args.crit >= args.warn:
        print("certwatch: --crit (%d) must be lower than --warn (%d)" % (args.crit, args.warn), file=sys.stderr)
        return 2
    workers = max(1, min(args.workers, len(targets)))
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        results = list(pool.map(lambda t: inspect(t, args.warn, args.crit, _fetch, None, args.timeout), targets))
    bad = sum(1 for r in results if r["status"] != "OK")
    if args.json:
        print(json.dumps(results, indent=2))
    else:
        for r in results:
            print("%-9s %-40s %s" % (r["status"], r["target"], r["detail"]))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
