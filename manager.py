#!/usr/bin/env python3
"""
manager.py

    Entry point to web service, for now runs the boa app.

    WIP: creates parallel workers
"""
from boa import create_app
from boa.config import BaseConfig

# initialize Flask app with factory pattern
config = BaseConfig()
app = create_app(config)

if __name__ == "__main__":
    app.run(host="0.0.0.0")
