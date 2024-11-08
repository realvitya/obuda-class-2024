"""FortiGate configuration script"""

import sys
from argparse import ArgumentParser, Namespace
from getpass import getpass
from ipaddress import IPv4Interface
from os import getenv

from jinja2 import Environment, FileSystemLoader, StrictUndefined
from scrapli import Scrapli

if sys.version_info < (3, 10):  # Check if Python version is less than 3.10
    print("Python 3.10 or higher is required.")
    sys.exit(1)

jinja_env = Environment(
    trim_blocks=True, lstrip_blocks=True, undefined=StrictUndefined, loader=FileSystemLoader("templates")
)


def main(argv=None):
    """Main program

    Args:
        argv: optional arguments in case of testing

    Returns:
        None
    """
    parser = ArgumentParser(prog="fortigate")
    parser.add_argument("--ip", default=getenv("HOST") or "192.168.1.1/24", help="Firewall IP/nm")
    parser.add_argument("--interface", "-i", default=getenv("INTERFACE") or "port1", help="Firewall data interface")
    parser.add_argument("--user", "-u", default=getenv("USER") or "admin", help="Firewall username")
    parser.add_argument("--password", "-p", default=getenv("PASSWORD"), help="Firewall password")
    tasks = parser.add_subparsers(title="tasks", dest="task", required=True)
    day0_parser = tasks.add_parser("day0", help="Day0 config generation")
    day0_parser.add_argument("--hostname", "-host", help="Firewall hostname", default="FW")
    micro_parser = tasks.add_parser("segmentation", help="Setup micro segmentation")
    micro_parser.add_argument("--test", "-t", help="Test mode", action="store_true")
    seg_parser.add_argument("--static_arp", "-a", help="Fix ARP table", action="store_true")
    args = parser.parse_args(argv)

    match args.task:
        case "day0":
            return generate_day0(args)
        case "segmentation":
            if args.password is None and (not args.test or args.static_arp):
                args.password = getpass("FW password: ")
            return config_segmentation(args)


def generate_day0(args: Namespace) -> None:
    """Generate Day0 config file

    Args:
        args: program arguments

    Returns:
        None
    """
    data = args.__dict__
    template = jinja_env.get_template("fortigate-day0.j2")
    output = template.render(**data)
    print(output)


def config_segmentation(args: Namespace) -> None:
    """Config segmentation on firewall

    Args:
        args: program arguments

    Returns:
        None
    """
    data = args.__dict__
    ip = IPv4Interface(args.firewall).ip.compressed
    args.start_ip = IPv4Interface(args.firewall).network[1]
    args.end_ip = IPv4Interface(args.firewall).network[-2]

    template = jinja_env.get_template("fortigate-micro-segmentation.j2")
    config = template.render(**data)
    firewall_data = {
        # "transport": "ssh2",
        "host": ip,
        "auth_username": args.user,
        "auth_password": args.password,
        "auth_strict_key": False,
        "ssh_config_file": True,
        # "channel_log": "fw.log",
    }
    if args.test:
        print(config)
        return
    print(f"Connecting to {ip}...")
    with Scrapli(**firewall_data) as conn:
        if args.static_arp:
            print("Gathering ARP table")
            res = conn.send_command("get system arp")
            args.arps = [
                {
                    "ip": arp["ip"],
                    "mac": arp["mac"],
                    "interface": arp["interface"],
                }
                for arp in res.ttp_parse_output("arp-parse.ttp")[0]
            ]
        config = template.render(**data)
        if args.test:
            print(config)
            return
        print("Sending configuration...")
        res = conn.send_commands(config.splitlines(), batch_mode=True)
        if res.failed:
            print("Configuration is unsuccessful!")
            return
        print("Configuration is done!")


if __name__ == "__main__":
    main()
