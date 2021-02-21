#!/usr/bin/env python3
"""
manage.py

    Entry point to web service, for now runs the boa app.
"""
import os
import redis

from rq import Connection, Worker

from boa import create_app
from boa.config import config

# initialize Flask app with factory pattern with the given configuration
config = config[os.environ.get("CONFIG", "development")]
app = create_app(config)

def run_worker():
    """ Instantiates a worker that handles reverse engineering """
    redis_url = app.config["REDIS_URL"]
    redis_connection = redis.from_url(redis_url)
    with Connection(redis_connection):
        worker = Worker(app.config["QUEUES"])
        worker.work()


if __name__ == "__main__":
    app.run(host="0.0.0.0", ssl_context=app.config["SSL_CONTEXT"])
