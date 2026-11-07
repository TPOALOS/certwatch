#!/usr/bin/env python3
"""certwatch - check TLS certificate expiry for hosts you operate.

Opens a normal TLS connection (with verification) and reads the certificate's
expiry date. Intended for monitoring your own servers.
Standard library only. Exit code 0 = all OK, 1 = warning/critical/error, 2 = usage.
"""
import argparse
import datetime
import socket
import ssl
import sys

__version__ = "1.0.0"


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


def main(argv=None):
    ap = argparse.ArgumentParser(description="Check TLS certificate expiry.")
    ap.add_argument("targets", nargs="*", help="host or host:port")
    ap.add_argument("-f", "--file", help="file with one target per line (# comments ok)")
    ap.add_argument("--warn", type=int, default=30, help="warning threshold in days")
    ap.add_argument("--crit", type=int, default=7, help="critical threshold in days")
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

    bad = 0
    for t in targets:
        status, detail = check(t, args.warn, args.crit)
        if status != "OK":
            bad += 1
        print("%-9s %-40s %s" % (status, t, detail))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
