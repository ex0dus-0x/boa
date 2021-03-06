""""
uwsgi.py

    Runner for deploying boa on the web, locally, or through Gunicorn.
"""
import os
import sys

import redis
from rq import Connection, Worker

from boa import create_app, config, argparse

config = config.config[os.environ.get("CONFIG", "development")]
app = create_app(config)
app.app_context().push()


@argparse.subcommand(
    [
        argparse.argument(
            "--host", default="0.0.0.0", help="Set host URL to start webapp on (default is 0.0.0.0)."
        ),
        argparse.argument(
            "--port", default=5000, type=int, help="Set host port to start webapp on (default is 5000)."
        ),
    ]
)
def webapp(args):
    """ 
    Starts a non-Gunicorn development Flask server. This is useful for users that want to run locally without
    a full Docker build, or contributors/me for launching a dev server.
    """
    app.run(host=args.host, port=args.port, ssl_context=app.config["SSL_CONTEXT"])


@argparse.subcommand()
def taskworker(args):
    """ Instantiates a Redis task worker to handle RE as a background task. """
    url = app.config["REDIS_URL"]
    conn = redis.from_url(url)
    with Connection(conn):
        worker = Worker(app.config["QUEUES"])
        worker.work()


if __name__ == "__main__":
    try:
        argparse.parse_args()
    except KeyboardInterrupt:
        sys.exit(1)
