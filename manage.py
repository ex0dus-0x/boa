#!/usr/bin/env python3
"""
manager.py

    Entry point to web service, for now runs the boa app.
"""
import os
from boa import create_app
from boa.config import config

# initialize Flask app with factory pattern
config = config[os.environ.get("CONFIG", "development")]
app = create_app(config)

if __name__ == "__main__":
    app.run(ssl_context=app.config["SSL_CONTEXT"])
