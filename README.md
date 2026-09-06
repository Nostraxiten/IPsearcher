# IPsearcher

IPsearcher is a concurrent Python tool for discovering live IPv4/IPv6 hosts and
checking TCP ports on networks you own or are authorized to audit.

## Requirements

- Python 3.6+
- Standard library only

## Command-line usage

Run a single address or a finite CIDR network:

```bash
python IPSearch.py 192.168.1.10 -p 22 -NF
python IPSearch.py 192.168.1.0/24 -p 80 443 -SF
python IPSearch.py 2001:db8::/120 -p 443 --any
```

### Arguments

| Argument | Description |
| --- | --- |
| `target` | IPv4/IPv6 address or CIDR network. |
| `-p`, `--ports` | One to three TCP ports. Values can be space or comma separated. |
| `-NF`, `--no-firewall` | Return hosts without filtered ports. Requires `-p`. |
| `-SF`, `--with-firewall` | Return hosts with at least one filtered port. Requires `-p`. |
| `--all` | With multiple ports, require every port to be open. Default. |
| `--any` | With multiple ports, require at least one port to be open. |
| `--no-host-validation` | Skip canary, banner, and post-probe checks. |
| `--threads` | Set worker count from 1 to 500. |
| `--timeout` | Set TCP timeout from 0.2 to 10 seconds. |
| `-h`, `--help` | Show command help and examples. |

Firewall state validation is enabled automatically whenever `-p` is used.
Each port is classified as `open`, `closed`, or `filtered`; an `open` result
is confirmed with a second connection. Without `-NF` or `-SF`, all matching
firewall states are accepted.

When no target is supplied, `python IPSearch.py` opens the legacy interactive
menu. Results are written incrementally and finalized in the `IPs` directory.

## Package layout

```text
IPSearch.py          Scanner entry point and scan engine
ipsearcher/
  cli.py             Argument parsing and CLI validation
  ports.py           Common TCP service names
```

Only scan systems that you own or have explicit permission to test.