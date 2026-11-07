# certwatch

Check TLS certificate expiry for hosts you operate. Opens a normal, verified TLS
connection and reads the certificate's `notAfter` date. Standard library only.

Use it only against servers you own or are authorized to monitor.

## Usage

```bash
python3 certwatch.py example.com
python3 certwatch.py example.com:8443 internal.example.org
python3 certwatch.py -f hosts.txt --warn 45 --crit 10
```

`hosts.txt` holds one `host` or `host:port` per line; `#` starts a comment.

Statuses: `OK`, `WARNING` (under `--warn` days, default 30), `CRITICAL` (under
`--crit`, default 7), `EXPIRED`, `INVALID` (verification failed, e.g. untrusted or
hostname mismatch), `ERROR` (network problem).

Exit codes: `0` all OK, `1` any non-OK result, `2` usage error. Suitable for cron.

## Tests

Tests run fully offline (the network fetch is injected):

```bash
python3 -m unittest -v
```

## License

MIT (c) TPOALOS
