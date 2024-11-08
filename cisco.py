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
    parser = ArgumentParser(prog="cisco")
    parser.add_argument("--ip", default=getenv("HOST") or "192.168.1.200/24", help="Switch IP/nm")
    parser.add_argument("--mgmt-port", "-m", default=getenv("MGMT_INTERFACE") or "gi0/8", help="Switch mgmt interface")
    parser.add_argument(
        "--data-port",
        "-d",
        default=getenv("DATA_INTERFACE") or "range gi0/2-7",
        help="Switch data interface (range ...)",
    )
    parser.add_argument(
        "--fw-port", "-f", default=getenv("FW_INTERFACE") or "gi0/1", help="Switchport firewall is connected to"
    )
    parser.add_argument("--primary-vlan", "-pv", default=getenv("PRIMARY_VLAN") or "100", help="Primary VLAN")
    parser.add_argument("--isolated-vlan", "-iv", default=getenv("ISOLATED_VLAN") or "201", help="Isolated VLAN")
    parser.add_argument("--user", "-u", default=getenv("USER") or "admin", help="Switch username")
    parser.add_argument("--password", "-p", default=getenv("PASSWORD"), help="Switch password")
    tasks = parser.add_subparsers(title="tasks", dest="task", required=True)
    day0_parser = tasks.add_parser("day0", help="Day0 config generation")
    day0_parser.add_argument("--hostname", "-host", help="Switch hostname", default="FW")
    micro_parser = tasks.add_parser("segmentation", help="Setup micro segmentation")
    micro_parser.add_argument("--test", "-t", help="Test mode", action="store_true")
    args = parser.parse_args(argv)
    if args.task == "day0":
        generate_day0(args)
    elif args.task == "segmentation":
        if args.password is None and not args.test:
            args.password = getpass("SW password: ")
        config_segmentation(args)


def generate_day0(args: Namespace) -> None:
    """Generate Day0 config file

    Args:
        args: program arguments

    Returns:
        None
    """
    args.netmask = IPv4Interface(args.ip).netmask.compressed
    args.ip = IPv4Interface(args.ip).ip.compressed
    data = args.__dict__
    template = jinja_env.get_template("cisco-day0.j2")
    output = template.render(**data)
    print(output)


def config_segmentation(args: Namespace) -> None:
    """Config segmentation on Switch

    Args:
        args: program arguments

    Returns:
        None
    """
    data = args.__dict__
    ip = IPv4Interface(args.ip).ip.compressed
    args.start_ip = IPv4Interface(args.ip).network[1]
    args.end_ip = IPv4Interface(args.ip).network[-2]

    template = jinja_env.get_template("cisco-pvlan.j2")
    config = template.render(**data)
    switch_data = {
        "platform": "cisco_iosxe",
        "host": ip,
        "auth_username": args.user,
        "auth_password": args.password,
        "auth_strict_key": False,
        "ssh_config_file": True,
        "channel_log": "sw.log",
    }
    if args.test:
        print(config)
        return
    if "win" in sys.platform:
        switch_data["transport"] = "ssh2"
    print(f"Connecting to {ip}...")
    with Scrapli(**switch_data) as conn:
        print("Sending configuration...")
        res = conn.send_configs(config.splitlines())
        if res.failed:
            print("Configuration is unsuccessful!")
            return
        print("Configuration is done!")


if __name__ == "__main__":
    main()
