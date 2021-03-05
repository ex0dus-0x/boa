#!/usr/bin/env python3
"""
__main__.py

    Command line entry point for launching either the standalone executable, or the
    webapp service.
"""
import os
import sys
import argparse

import redis
from rq import Connection, Worker

import boa

# globally instantiated parser for simplified subcommand parsing
cli = argparse.ArgumentParser(
    description="Python Malware/App Reverse Engineering Framework"
)
subparsers = cli.add_subparsers(dest="subcommand")


# initialize Flask app with factory pattern with default config
config = boa.config.config[os.environ.get("CONFIG", "development")]
app = boa.create_app(config)


def argument(*name_or_flags, **kwargs):
    """ Helper method to format arguments for subcommand decorator """
    return (list(name_or_flags), kwargs)


def subcommand(args=[], parent=subparsers):
    """
    Implements decorator for instantiating subcommand.
    Credit to: https://mike.depalatis.net/blog/simplifying-argparse.html
    """

    def decorator(func):
        parser = parent.add_parser(func.__name__, description=func.__doc__)
        for arg in args:
            parser.add_argument(*arg[0], **arg[1])
        parser.set_defaults(func=func)

    return decorator

#############################
# Web Application Commands
#############################

@subcommand(
    [
        argument(
            "--host", default="0.0.0.0", help="Set host URL to start webapp on (default is 0.0.0.0).",
        ),
        argument(
            "--start_worker", action="store_true", help="Spawns a task worker."
        ),
    ]
)
def webapp(args):
    """ Starts a webapp instance of boa, or if configured, a web worker instance for Redis-based tasks. """
    if args.start_worker:
        url = app.config["REDIS_URL"]
        conn = redis.from_url(url)
        with Connection(conn):
            worker = Worker(app.config["QUEUES"])
            worker.work()
    else:
        app.run(host=args.url, ssl_context=app.config["SSL_CONTEXT"])


#############################
# Standalone CLI Commands
#############################

@subcommand(
    [argument("executable", help="Path to Python-compiled executable to reverse engineer.")]
)
def reverse(args):
    """ Subcommand to attempt to fully reverse engineering a target executable """
    app = args.executable
    if not os.path.exists(app):
        print("Cannot find path to executable. Exiting...")
        sys.exit(1)


def main():
    args = cli.parse_args()
    if args.subcommand is None:
        cli.print_help()
    else:
        args.func(args)


if __name__ == "__main__":
    try:
        exit(main())
    except KeyboardInterrupt:
        sys.exit(1)
