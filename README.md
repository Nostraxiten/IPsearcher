# IPsearcher

IPsearcher is a concurrent Python tool for discovering live IPv4 and IPv6
hosts and checking TCP ports on networks you own or are authorized to audit.

## Requirements

- Python 3.6+
- Python standard library only

## Usage

Start the original interactive scanner:

```bash
python IPSearch.py
```

The menu lets you choose:

- Class A, B, C, or all classes
- A custom IPv4/IPv6 CIDR network
- Random IPv4 or IPv6 scanning
- ICMP discovery or a TCP port filter with one to three ports
- `ALL` or `ANY` matching when multiple ports are selected
- Firewall filtering for hosts with or without filtered ports
- Host validation and worker/timeout settings

When TCP ports are selected, each port is classified as `open`, `closed`, or
`filtered`. Open results are confirmed with a second connection. Firewall
validation is part of the normal port-search workflow and can be selected from
the interactive menu.

Results are saved incrementally and finalized in the `IPs` directory.

## Package layout

```text
IPSearch.py          Scanner entry point and scan engine
ipsearcher/
  ports.py           Common TCP service names
```

Only scan systems that you own or have explicit permission to test.

## License

MIT. See [LICENSE](LICENSE).

