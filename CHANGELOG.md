# Changelog

## 1.1.0

- `--json` output with subject, issuer, DNS SANs, not_after and days_left
- Hosts are checked in parallel (`--workers`) and reported in input order
- `--timeout`, and `--crit` must now be lower than `--warn`
- Installable with pip (`certwatch` command), CI on Linux and macOS

## 1.0.0

Initial release.
