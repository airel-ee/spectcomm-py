"""Command-line client for the airdaq v2 remote-control protocol."""

import argparse
import ast
import json
import sys

from . import airdaq
from .airdaq import AirdaqError


def _parse_params(words):
    """Interpret the PARAMS words as JSON, a Python literal, or a plain string.

    The shell splits an unquoted literal such as [1, 0, 1] into several
    words; rejoining them restores it.
    """
    text = " ".join(words)
    if not text:
        return None
    try:
        return json.loads(text)
    except ValueError:
        pass
    try:
        return ast.literal_eval(text)
    except (ValueError, SyntaxError):
        return text


def _connect(args):
    if args.unix:
        return airdaq.connect(socket_path=args.unix)
    if args.usb:
        return airdaq.connect_usb(device_id=args.device)
    if args.address and args.port:
        return airdaq.connect(address=args.address, port=args.port)
    try:
        return airdaq.connect(address=args.address, device_id=args.device)
    except AirdaqError as net_error:
        if args.address:
            raise
        try:
            return airdaq.connect_usb(device_id=args.device)
        except AirdaqError as usb_error:
            raise AirdaqError(
                "network: {}; USB: {}".format(net_error, usb_error)
            )


def _json_default(value):
    if isinstance(value, bytes):
        return value.hex()
    return str(value)


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="airdaq", description="Control an Airel airdaq device."
    )
    parser.add_argument("--device", metavar="ID", help="device id to select")
    parser.add_argument("--address", metavar="HOST", help="device address")
    parser.add_argument("--port", type=int, metavar="N", help="device TCP port")
    parser.add_argument("--unix", metavar="PATH", help="connect to a Unix socket")
    parser.add_argument("--usb", action="store_true", help="connect over USB")

    actions = parser.add_subparsers(dest="action", required=True)
    cmd = actions.add_parser("cmd", help="invoke a device command")
    cmd.add_argument("key", help="command key")
    cmd.add_argument(
        "params",
        nargs="*",
        help="parameters as JSON or a Python literal; a plain string otherwise",
    )

    args = parser.parse_args(argv)
    if args.usb and (args.unix or args.address or args.port):
        parser.error("--usb cannot be combined with --unix, --address or --port")
    if args.unix and (args.address or args.port):
        parser.error("--unix cannot be combined with --address or --port")

    params = _parse_params(args.params)
    try:
        with _connect(args) as remote:
            result = remote.command(args.key, params)
    except (AirdaqError, OSError) as e:
        print("airdaq: {}".format(e), file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130
    if result is not None:
        print(json.dumps(result, default=_json_default))
    return 0
