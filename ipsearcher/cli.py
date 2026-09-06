"""Command-line argument parsing for IPsearcher."""

import argparse


def _ports(value):
    """Parse comma/space separated TCP ports and validate their range."""
    values = []
    for item in value:
        for token in item.replace(";", ",").split(","):
            token = token.strip()
            if not token:
                continue
            try:
                port = int(token)
            except ValueError as error:
                raise argparse.ArgumentTypeError(
                    f"invalid port: {token!r}"
                ) from error
            if not 1 <= port <= 65535:
                raise argparse.ArgumentTypeError(
                    f"port must be between 1 and 65535: {port}"
                )
            if port not in values:
                values.append(port)
    if len(values) > 3:
        raise argparse.ArgumentTypeError("a maximum of 3 ports is supported")
    return values


def build_parser():
    parser = argparse.ArgumentParser(
        prog="IPSearch.py",
        description="Scan an IP address or CIDR network for live hosts and TCP ports.",
        epilog=(
            "Examples: python IPSearch.py 192.168.1.10 -p 22 80 -NF; "
            "python IPSearch.py 192.168.1.0/24 -p 80,443 -SF"
        ),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "target",
        nargs="?",
        help="IPv4/IPv6 address or CIDR network. Omit it to use the interactive menu.",
    )
    parser.add_argument(
        "-p", "--ports", nargs="+", metavar="PORT", type=str,
        help="TCP ports to test (space or comma separated, up to 3).",
    )
    firewall = parser.add_mutually_exclusive_group()
    firewall.add_argument(
        "-NF", "--no-firewall", dest="firewall_mode", action="store_const",
        const="no_firewall", help="show only hosts without filtered ports.",
    )
    firewall.add_argument(
        "-SF", "--with-firewall", dest="firewall_mode", action="store_const",
        const="with_firewall", help="show only hosts with at least one filtered port.",
    )
    parser.set_defaults(firewall_mode="any")
    parser.add_argument(
        "--any", dest="match_mode", action="store_const", const="any",
        help="with multiple ports, match at least one open port.",
    )
    parser.add_argument(
        "--all", dest="match_mode", action="store_const", const="all",
        help="with multiple ports, require every port to be open.",
    )
    parser.set_defaults(match_mode="all")
    parser.add_argument(
        "--no-host-validation", action="store_true",
        help="skip canary, banner, and post-probe host validation.",
    )
    parser.add_argument("--threads", type=int, help="number of scanner worker threads.")
    parser.add_argument("--timeout", type=float, help="TCP connection timeout in seconds.")
    return parser


def parse_args(argv=None):
    args = build_parser().parse_args(argv)
    try:
        args.ports = _ports(args.ports) if args.ports else []
    except argparse.ArgumentTypeError as error:
        build_parser().error(str(error))
    if args.threads is not None and not 1 <= args.threads <= 500:
        raise SystemExit("error: --threads must be between 1 and 500")
    if args.timeout is not None and not 0.2 <= args.timeout <= 10:
        raise SystemExit("error: --timeout must be between 0.2 and 10 seconds")
    if args.match_mode == "any" and len(args.ports) < 2:
        raise SystemExit("error: --any requires at least two ports")
    if args.firewall_mode != "any" and not args.ports:
        raise SystemExit("error: -NF/-SF requires at least one port with -p")
    if not args.target and (args.ports or args.firewall_mode != "any"):
        raise SystemExit("error: a target IP or CIDR network is required when using CLI flags")
    return args
