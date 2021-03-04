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

# initialize Flask app with factory pattern with default config
config = boa.config.config[os.environ.get("CONFIG", "development")]
app = boa.create_app(config)

def startweb(args):
    """ Starts a webapp instance of boa """
    app.run(host="0.0.0.0", ssl_context=app.config["SSL_CONTEXT"])


def webworker(args):
    """ Instantiates a new Redis-based web worker """
    url = app.config["REDIS_URL"]
    conn = redis.from_url(url)
    with Connection(conn):
        worker = Worker(app.config["QUEUES"])
        worker.work()


def main():
    parser = argparse.ArgumentParser(
        description="Python Malware/App Reverse Engineering Framework"
    )
    if args.subcommand is none:
        cli.print_help()


if __name__ == "__main__":
    try:
        exit(main())
    except KeyboardInterrupt:
        sys.exit(1)
